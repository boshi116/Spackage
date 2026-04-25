#!/usr/bin/env python3
import json
import os
import shutil
import subprocess
import time

from config_manager import ConfigManager, DEFAULT_POLICY_CRON, validate_config_file
import firewall_manager
from tc_manager import TCManager


LOG_FILE = "/var/log/sqm_controller.log"
CRON_FILE = "/etc/crontabs/root"
CRON_MARK = "# sqm-controller-policy"
DEFAULT_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"


def ensure_path():
    current = os.environ.get("PATH", "")
    if not current:
        os.environ["PATH"] = DEFAULT_PATH
        return

    items = current.split(":")
    for seg in DEFAULT_PATH.split(":"):
        if seg not in items:
            items.append(seg)
    os.environ["PATH"] = ":".join(items)


def find_command(name):
    candidates = [name, f"/usr/sbin/{name}", f"/usr/bin/{name}", f"/sbin/{name}", f"/bin/{name}"]
    for cand in candidates:
        if "/" in cand:
            if os.path.isfile(cand) and os.access(cand, os.X_OK):
                return cand
            continue
        found = shutil.which(cand)
        if found:
            return found
    return None


def run(command):
    return subprocess.run(command, shell=True, capture_output=True, text=True)


def to_bool(value):
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return bool(value)


def get_policy_cron_state(cfg):
    expression = cfg.get_policy_cron_expression() if cfg else DEFAULT_POLICY_CRON
    present = False

    try:
        if os.path.exists(CRON_FILE):
            with open(CRON_FILE, "r", encoding="utf-8") as file_handle:
                for raw in file_handle:
                    line = raw.strip()
                    if not line or CRON_MARK not in line:
                        continue
                    present = True
                    line = line.split(CRON_MARK, 1)[0].strip()
                    parts = line.split()
                    if len(parts) >= 5:
                        expression = " ".join(parts[:5])
                    break
    except Exception:
        present = False

    return {"present": present, "expression": expression}


def check_dependencies(configured_backend):
    required = ["python3", "tc", "ip", "uci"]
    missing = []
    resolved = {}
    for name in required:
        path = find_command(name)
        if path is None:
            missing.append(name)
        else:
            resolved[name] = path

    backend_command = ""
    backend_path = ""
    backend_error = ""
    if configured_backend == "nft":
        backend_command = "nft"
        backend_path = find_command("nft") or ""
        if not backend_path:
            backend_error = "configured backend nft is unavailable"
    elif configured_backend == "iptables":
        backend_command = "iptables"
        backend_path = find_command("iptables") or ""
        if not backend_path:
            backend_error = "configured backend iptables is unavailable"
    else:
        nft_path = find_command("nft") or ""
        iptables_path = find_command("iptables") or ""
        backend_path = nft_path or iptables_path
        backend_command = "nft|iptables"
        if not backend_path:
            backend_error = "no supported firewall backend command found"

    ok = (len(missing) == 0) and (backend_error == "")
    detail = "all found" if ok else ", ".join(filter(None, [("missing: " + ", ".join(missing)) if missing else "", backend_error]))
    return {
        "name": "dependencies",
        "ok": ok,
        "detail": detail,
        "data": {
            "resolved": resolved,
            "configured_backend_command": backend_command,
            "configured_backend_path": backend_path,
        },
    }


def check_interface(settings):
    ip_cmd = find_command("ip") or "ip"
    iface = settings.get("interface", "eth0")
    result = run(f"{ip_cmd} link show {iface}")
    return {
        "name": "interface",
        "ok": result.returncode == 0,
        "detail": iface if result.returncode == 0 else f"{iface} not found",
    }


def check_tc_rules(settings, classification_enabled):
    enabled = to_bool(settings.get("enabled", False))
    tc = TCManager(settings)
    state = tc.inspect_runtime_state(classification_enabled=classification_enabled)

    upload_ok = state.get("upload_root_present", False) and state.get("upload_parent_present", False) and state.get("upload_default_qdisc_present", False)
    if state.get("want_download"):
        download_ok = (
            state.get("download_root_present", False)
            and state.get("download_parent_present", False)
            and state.get("download_default_qdisc_present", False)
            and state.get("ingress_filter_present", False)
        )
    else:
        download_ok = True

    if not enabled:
        ok = True
        detail = "service disabled; tc rules not required"
    else:
        ok = upload_ok and download_ok and state.get("classifier_tc_complete", False)
        detail = (
            f"upload_base={upload_ok} download_base={download_ok} "
            f"upload_classifier={state.get('upload_class_queues_present', False)} "
            f"download_classifier={state.get('download_class_queues_present', False)}"
        )

    return {
        "name": "tc_rules",
        "ok": ok,
        "detail": detail,
        "data": state,
    }


def check_log_rw():
    marker = f"SQM_SELF_CHECK {int(time.time())}"
    try:
        os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
        with open(LOG_FILE, "a", encoding="utf-8") as file_handle:
            file_handle.write(marker + "\n")
        with open(LOG_FILE, "r", encoding="utf-8") as file_handle:
            found = marker in file_handle.read()
        return {
            "name": "log_rw",
            "ok": found,
            "detail": "write/read ok" if found else "marker not found after write",
        }
    except Exception as exc:
        return {
            "name": "log_rw",
            "ok": False,
            "detail": f"failed: {exc}",
        }


def check_validation(validation):
    errors = list(validation.get("errors", []))
    warnings = list(validation.get("warnings", []))
    return {
        "name": "config_validation",
        "ok": len(errors) == 0,
        "detail": f"errors={len(errors)} warnings={len(warnings)}",
        "data": {
            "errors": errors,
            "warnings": warnings,
            "rule_conflicts": list(validation.get("rule_conflicts", [])),
        },
    }


def check_policy_cron(cron_state, policy_enabled):
    if not policy_enabled:
        return {
            "name": "policy_cron",
            "ok": True,
            "detail": "policy disabled; cron not required",
            "data": cron_state,
        }
    return {
        "name": "policy_cron",
        "ok": bool(cron_state.get("present")),
        "detail": cron_state.get("expression", DEFAULT_POLICY_CRON),
        "data": cron_state,
    }


def main():
    ensure_path()

    cfg = ConfigManager()
    cfg.load_config()
    settings = cfg.get_settings().get("all", {})
    validation = validate_config_file(cfg.config_path)
    configured_backend = cfg.get_classification_backend()
    active_backend_info = firewall_manager.detect_active_backend()
    active_backend = str(active_backend_info.get("backend", "")).strip().lower()
    cron_state = get_policy_cron_state(cfg)
    policy_enabled = to_bool(cfg.get_section("policy", "policy").get("enabled", False))
    classification_enabled = to_bool(cfg.get_section("classification", "classification").get("enabled", False))

    checks = [
        check_dependencies(configured_backend),
        check_interface(settings),
        check_tc_rules(settings, classification_enabled),
        check_log_rw(),
        check_validation(validation),
        check_policy_cron(cron_state, policy_enabled),
    ]
    tc_check = next((item for item in checks if item.get("name") == "tc_rules"), {})
    tc_data = tc_check.get("data", {}) if isinstance(tc_check.get("data"), dict) else {}
    success = all(item.get("ok") for item in checks)

    result = {
        "success": success,
        "time": int(time.time()),
        "interface": settings.get("interface", "eth0"),
        "configured_backend": configured_backend,
        "active_backend": active_backend,
        "policy_cron_present": bool(cron_state.get("present")),
        "policy_cron_expression": cron_state.get("expression", DEFAULT_POLICY_CRON),
        "rule_conflicts_count": len(validation.get("rule_conflicts", [])),
        "upload_class_queues_present": bool(tc_data.get("upload_class_queues_present")),
        "download_class_queues_present": bool(tc_data.get("download_class_queues_present")),
        "classifier_tc_complete": bool(tc_data.get("classifier_tc_complete")),
        "validation_errors": list(validation.get("errors", [])),
        "validation_warnings": list(validation.get("warnings", [])),
        "checks": checks,
    }
    print(json.dumps(result, ensure_ascii=False))
    raise SystemExit(0 if success else 1)


if __name__ == "__main__":
    main()
