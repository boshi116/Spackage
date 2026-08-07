#!/usr/bin/env python3
import json
import os
import re
import shutil
import subprocess
import time

from config_manager import ConfigManager, DEFAULT_POLICY_CRON, validate_config_file
import firewall_manager
import nss_detect
from tc_manager import TCManager

LOG_FILE = "/var/log/sqm_controller.log"
POLICY_REPORT_FILE = "/var/log/sqm_policy.jsonl"
UNKNOWN_FLOW_FILE = "/var/log/sqm_unknown_flows.jsonl"
POLICY_STATE_FILE = "/tmp/sqm_decision_state.json"
LEGACY_POLICY_STATE_FILE = "/tmp/sqm_decision_state_" + "v" + "4.json"
CRON_FILE = "/etc/crontabs/root"
CRON_MARK = "# sqm-controller-policy"
DEFAULT_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"
IFACE_NAME_RE = re.compile(r"^[A-Za-z0-9_.:-]+$")


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
    if not isinstance(command, (list, tuple)) or not command:
        raise ValueError("command must be a non-empty argument list")
    return subprocess.run(list(command), capture_output=True, text=True)


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


def check_nss(settings):
    queue_backend = str(settings.get("queue_backend", "auto") or "auto").strip().lower()
    resolved_backend, info = nss_detect.resolve_backend(queue_backend)
    ok = True  # 检测本身不算失败：非 NSS 设备无需硬件
    detail = info.get("reason", "")
    if queue_backend == "nss" and not info.get("available"):
        ok = False
        detail = "强制 NSS 模式但检测失败：%s" % info.get("reason", "")
    return {
        "name": "nss",
        "ok": ok,
        "detail": detail,
        "data": {
            "configured": queue_backend,
            "resolved_backend": resolved_backend,
            "available": info.get("available", False),
            "model": info.get("model", ""),
        },
    }


def check_nss_tc_rules(settings):
    iface = str(settings.get("interface", "eth0") or "eth0").strip()
    want_upload = int(settings.get("upload_speed", settings.get("upload_bandwidth", 0)) or 0) > 0
    want_download = int(settings.get("download_speed", settings.get("download_bandwidth", 0)) or 0) > 0
    out = run(["tc", "qdisc", "show", "dev", iface])
    text = (out.stdout or "") + (out.stderr or "")
    wan_hit = bool(re.search(r"nsstbl|nssfq_codel", text))
    # 下载方向走 ifb0
    ifb_out = run(["tc", "qdisc", "show", "dev", "ifb0"])
    ifb_text = (ifb_out.stdout or "") + (ifb_out.stderr or "")
    ifb_hit = bool(re.search(r"nsstbl|nssfq_codel", ifb_text))
    # 按方向分别要求：配置了上行才要求 wan 侧，配置了下行才要求 ifb0 侧
    wan_ok = (not want_upload) or wan_hit
    ifb_ok = (not want_download) or ifb_hit
    ok = wan_ok and ifb_ok
    return {
        "name": "nss_tc_rules",
        "ok": ok,
        "detail": "nsstbl/nssfq_codel mounted (wan=%s ifb0=%s, want_up=%s want_down=%s)" % (wan_hit, ifb_hit, want_upload, want_download),
        "data": {"dev": iface, "wan": wan_hit, "ifb0": ifb_hit, "want_upload": want_upload, "want_download": want_download, "qdisc": (text + ifb_text)[:2000]},
    }

def check_interface(settings):
    ip_cmd = find_command("ip") or "ip"
    iface = str(settings.get("interface", "eth0") or "eth0").strip()
    if not IFACE_NAME_RE.match(iface):
        return {
            "name": "interface",
            "ok": False,
            "detail": f"{iface} invalid",
        }
    result = run([ip_cmd, "link", "show", iface])
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


def check_jsonl(path, name):
    if not os.path.exists(path):
        return {"name": name, "ok": True, "detail": f"{path} does not exist yet (ok)"}
    try:
        count = 0
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    count += 1
        return {"name": name, "ok": True, "detail": f"{count} lines"}
    except Exception as exc:
        return {"name": name, "ok": False, "detail": f"read failed: {exc}"}


def check_enhanced_modules():
    enhanced_modules = [
        "traffic_classifier", "rule_manager", "unknown_flow_logger",
        "traffic_analyzer", "congestion_detector", "decision_state", "adaptive_allocator",
    ]
    loaded = []
    failed = []
    for mod_name in enhanced_modules:
        try:
            __import__(mod_name)
            loaded.append(mod_name)
        except Exception as exc:
            failed.append(f"{mod_name}: {exc}")
    ok = len(failed) == 0
    return {
        "name": "enhanced_modules",
        "ok": ok,
        "detail": f"{len(loaded)} loaded, {len(failed)} failed" if ok else ", ".join(failed),
        "data": {"loaded": loaded, "failed": failed},
    }


def check_policy_chain_quick():
    try:
        import congestion_detector
        result = congestion_detector.detect_live()
        level = result.get("level", "unknown")
        ok = level in ("normal", "mild", "severe")
        return {
            "name": "policy_congestion_detect",
            "ok": ok,
            "detail": f"level={level}, reason={result.get('reason', '?')}",
            "data": {"level": level},
        }
    except Exception as exc:
        return {"name": "policy_congestion_detect", "ok": False, "detail": f"failed: {exc}"}


def check_policy_state_file():
    path = POLICY_STATE_FILE if os.path.exists(POLICY_STATE_FILE) else LEGACY_POLICY_STATE_FILE
    if not os.path.exists(path):
        return {"name": "policy_decision_state", "ok": True, "detail": "no state yet (ok)"}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        mode = data.get("current_mode", "?")
        last = data.get("last_run_time", 0)
        return {
            "name": "policy_decision_state",
            "ok": True,
            "detail": f"mode={mode}, last_run={last}",
            "data": {"current_mode": mode, "last_run_time": last},
        }
    except Exception as exc:
        return {"name": "policy_decision_state", "ok": False, "detail": f"read failed: {exc}"}


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
        check_nss(settings),
        check_interface(settings),
    ]
    # NSS 模式用 nsstbl/nssfq_codel 检测替代 HTB 多类检测
    resolved_backend = checks[1].get("data", {}).get("resolved_backend", "software")
    if resolved_backend == "nss":
        checks.append(check_nss_tc_rules(settings))
    else:
        checks.append(check_tc_rules(settings, classification_enabled))
    checks += [
        check_log_rw(),
        check_validation(validation),
        check_policy_cron(cron_state, policy_enabled),
        check_jsonl(POLICY_REPORT_FILE, "policy_jsonl"),
        check_jsonl(UNKNOWN_FLOW_FILE, "unknown_flow_jsonl"),
        check_enhanced_modules(),
        check_policy_chain_quick(),
        check_policy_state_file(),
    ]
    tc_check = next((item for item in checks if item.get("name") in ("tc_rules", "nss_tc_rules")), {})
    tc_data = tc_check.get("data", {}) if isinstance(tc_check.get("data"), dict) else {}
    success = all(item.get("ok") for item in checks)

    result = {
        "success": success,
        "time": int(time.time()),
        "interface": settings.get("interface", "eth0"),
        "configured_backend": configured_backend,
        "active_backend": active_backend,
        "queue_backend": checks[1].get("data", {}).get("resolved_backend", "software"),
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
