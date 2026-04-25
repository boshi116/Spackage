#!/usr/bin/env python3
import argparse
import json
import logging
from logging.handlers import RotatingFileHandler
import os
import re
import shutil
import subprocess
import time

from config_manager import ConfigManager, DEFAULT_POLICY_CRON, validate_config_file as validate_config_snapshot
from tc_manager import TCManager
from template_manager import get_template
import firewall_manager
import policy_engine
import traffic_classifier
import traffic_stats


LOG_FILE = "/var/log/sqm_controller.log"
SELF_CHECK_PY = "/usr/lib/sqm-controller/self_check.py"
CONFIG_FILE = "/etc/config/sqm_controller"
ALLOWED_ALGORITHMS = {"fq_codel", "cake"}
ALLOWED_LOG_LEVELS = {"debug", "info", "warn", "warning", "error"}
LOG_MAX_BYTES = 256 * 1024
LOG_BACKUP_COUNT = 5
POLICY_REPORT_FILE = "/var/log/sqm_policy.jsonl"
CLASSIFIER_RULE_STATE_FILE = "/tmp/sqm_classifier_rule_state.json"
FALLBACK_CONFIG_FILE = "/etc/config/sqm-controller"
POLICY_CRON_FILE = "/etc/crontabs/root"
POLICY_CRON_TAG = "sqm-controller-policy"
POLICY_CRON_MARK = f"# {POLICY_CRON_TAG}"
CLASSIFIER_FLOWIDS = {
    "gaming": {"upload": "1:11", "download": "2:21"},
    "streaming": {"upload": "1:12", "download": "2:22"},
    "bulk": {"upload": "1:13", "download": "2:23"},
}
CLASSIFIER_MARK_DEFAULTS = {
    "other": "0x10",
    "gaming": "0x11",
    "streaming": "0x12",
    "bulk": "0x13",
}


def setup_logging():
    try:
        os.makedirs("/var/log", exist_ok=True)
    except Exception:
        pass

    root = logging.getLogger()
    root.setLevel(logging.INFO)
    root.handlers = []
    handler = RotatingFileHandler(
        LOG_FILE,
        maxBytes=LOG_MAX_BYTES,
        backupCount=LOG_BACKUP_COUNT,
        encoding="utf-8",
    )
    handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
    root.addHandler(handler)


def rotate_logs(log_path=LOG_FILE, backup_count=LOG_BACKUP_COUNT):
    if backup_count < 1:
        backup_count = 1

    rotated = False
    oldest = f"{log_path}.{backup_count}"
    if os.path.exists(oldest):
        try:
            os.remove(oldest)
        except Exception:
            pass

    for index in range(backup_count - 1, 0, -1):
        src = f"{log_path}.{index}"
        dst = f"{log_path}.{index + 1}"
        if os.path.exists(src):
            try:
                os.replace(src, dst)
            except Exception:
                pass

    if os.path.exists(log_path) and os.path.getsize(log_path) > 0:
        try:
            os.replace(log_path, f"{log_path}.1")
            rotated = True
        except Exception:
            rotated = False

    try:
        os.makedirs(os.path.dirname(log_path), exist_ok=True)
        with open(log_path, "a", encoding="utf-8"):
            pass
    except Exception:
        pass

    return {
        "success": True,
        "rotated": rotated,
        "max_bytes": LOG_MAX_BYTES,
        "backup_count": backup_count,
    }


def _to_bool(value):
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return bool(value)


def _ecn_from_tc_output(text):
    if not text:
        return None
    lower = text.lower()
    if " fq_codel" in lower:
        if " noecn" in lower:
            return False
        if " ecn" in lower:
            return True
        return None
    if " cake" in lower:
        # On OpenWrt 23.05, cake does not expose explicit ecn/noecn options.
        # Treat cake as ECN-capable unless noecn is explicitly present.
        if " noecn" in lower:
            return False
        return True
    return None


def _merge_ecn_state(wan_state, ifb_state, running):
    if not running:
        return "not_applied"

    if wan_state is None and ifb_state is None:
        return "unknown"
    if wan_state is not None and ifb_state is None:
        return "upload_only"
    if wan_state is None and ifb_state is not None:
        return "download_only"
    if wan_state == ifb_state:
        return "enabled" if wan_state else "disabled"
    if wan_state or ifb_state:
        return "partial_enabled"
    return "partial_disabled"


def _csv_escape(value):
    text = "" if value is None else str(value)
    if any(ch in text for ch in [",", '"', "\n", "\r"]):
        return '"' + text.replace('"', '""') + '"'
    return text


def _dict_get(data, path, default=""):
    current = data
    for key in path:
        if not isinstance(current, dict):
            return default
        current = current.get(key)
    return current if current is not None else default


def _load_policy_report_entries(path=POLICY_REPORT_FILE):
    if not os.path.exists(path):
        return None, {"success": False, "error": "report log not found", "details": {"path": path}}

    try:
        with open(path, "r", encoding="utf-8") as file_handle:
            lines = [line.strip() for line in file_handle if line.strip()]
    except Exception as exc:
        return None, {"success": False, "error": f"failed to read report log: {exc}", "details": {"path": path}}

    if not lines:
        return None, {"success": False, "error": "report log is empty", "details": {"path": path}}

    entries = []
    for index, line in enumerate(lines, start=1):
        try:
            entries.append(json.loads(line))
        except Exception as exc:
            return None, {
                "success": False,
                "error": f"invalid jsonl line at {index}: {exc}",
                "details": {"path": path, "line": index},
            }
    return entries, None


def _load_validation_result(config_path):
    validation = validate_config_snapshot(config_path)
    if not isinstance(validation, dict):
        return {"valid": False, "errors": ["validation returned invalid payload"], "warnings": [], "rule_conflicts": []}
    validation.setdefault("errors", [])
    validation.setdefault("warnings", [])
    validation.setdefault("rule_conflicts", [])
    return validation


def _load_policy_cron_state(config_manager):
    configured_expr = ""
    if config_manager is not None:
        try:
            configured_expr = config_manager.get_policy_cron_expression()
        except Exception:
            configured_expr = DEFAULT_POLICY_CRON

    present = False
    expression = ""
    try:
        if os.path.exists(POLICY_CRON_FILE):
            with open(POLICY_CRON_FILE, "r", encoding="utf-8") as file_handle:
                for raw in file_handle:
                    line = raw.strip()
                    if not line or POLICY_CRON_MARK not in line:
                        continue
                    present = True
                    line = line.split(POLICY_CRON_MARK, 1)[0].strip()
                    parts = line.split()
                    if len(parts) >= 5:
                        expression = " ".join(parts[:5])
                    break
    except Exception:
        present = False
        expression = ""

    if not expression:
        expression = configured_expr or DEFAULT_POLICY_CRON

    return {
        "present": present,
        "expression": expression,
    }


def _load_runtime_metadata(config_manager):
    configured_backend = ""
    if config_manager is not None:
        try:
            configured_backend = config_manager.get_classification_backend()
        except Exception:
            configured_backend = ""

    active_backend_result = firewall_manager.detect_active_backend()
    active_backend = ""
    if isinstance(active_backend_result, dict):
        active_backend = str(active_backend_result.get("backend", "")).strip().lower()

    validation = _load_validation_result(config_manager.config_path if config_manager is not None else CONFIG_FILE)
    cron_state = _load_policy_cron_state(config_manager)
    return {
        "configured_backend": configured_backend,
        "active_backend": active_backend,
        "policy_cron_present": bool(cron_state["present"]),
        "policy_cron_expression": cron_state["expression"],
        "rule_conflicts_count": len(validation.get("rule_conflicts", [])),
        "validation_errors": list(validation.get("errors", [])),
        "validation_warnings": list(validation.get("warnings", [])),
    }


def _resolve_classifier_config_path(config_path=None):
    candidates = []
    for path in (config_path, CONFIG_FILE, FALLBACK_CONFIG_FILE):
        text = str(path or "").strip()
        if text and text not in candidates:
            candidates.append(text)

    for path in candidates:
        try:
            if os.path.isfile(path):
                return path
        except Exception:
            continue

    return candidates[0] if candidates else CONFIG_FILE


def _strip_inline_comment(line):
    in_single = False
    in_double = False
    out = []
    for ch in line:
        if ch == "'" and not in_double:
            in_single = not in_single
            out.append(ch)
            continue
        if ch == '"' and not in_single:
            in_double = not in_double
            out.append(ch)
            continue
        if ch == "#" and not in_single and not in_double:
            break
        out.append(ch)
    return "".join(out).strip()


def _unquote(text):
    text = str(text or "").strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in ("'", '"'):
        return text[1:-1]
    return text


def _parse_uci_sections(path):
    sections = []
    current = None

    with open(path, "r", encoding="utf-8") as file_handle:
        for lineno, raw in enumerate(file_handle, start=1):
            line = _strip_inline_comment(raw.rstrip("\n").rstrip("\r"))
            if not line:
                continue

            config_match = re.match(r"^\s*config\s+([A-Za-z0-9_]+)(?:\s+(.+))?$", line)
            if config_match:
                current = {
                    "type": config_match.group(1),
                    "name": _unquote(config_match.group(2) or ""),
                    "options": {},
                    "order": len(sections),
                    "line": lineno,
                }
                sections.append(current)
                continue

            option_match = re.match(r"^\s*option\s+([A-Za-z0-9_]+)\s+(.+)$", line)
            if option_match and current is not None:
                current["options"][option_match.group(1)] = _unquote(option_match.group(2))

    return sections


def _get_first_section(sections, section_type):
    for section in sections:
        if section.get("type") == section_type:
            return section
    return None


def _get_all_sections(sections, section_type):
    return [section for section in sections if section.get("type") == section_type]


def _normalize_proto(value):
    proto = str(value or "any").strip().lower()
    if proto in ("", "any", "*"):
        return "all"
    if proto in ("tcp", "udp", "all"):
        return proto
    return proto


def _build_category_marks(classification_opts):
    marks = {}
    for category, default_mark in CLASSIFIER_MARK_DEFAULTS.items():
        raw = classification_opts.get(f"mark_{category}", default_mark)
        marks[category] = _normalize_mark_hex(raw)
    return marks


def _build_mark_to_classid(category_marks):
    mapping = {}
    for category, flowids in CLASSIFIER_FLOWIDS.items():
        mark = category_marks.get(category)
        if mark:
            mapping[mark] = {
                "upload": flowids["upload"],
                "download": flowids["download"],
            }
    return mapping


def _safe_parse_ports(value):
    text = str(value or "").strip()
    if not text:
        return []
    try:
        return firewall_manager.parse_ports(text)
    except Exception:
        ports = []
        for part in text.split(","):
            item = part.strip()
            if item:
                ports.append(item.replace(":", "-"))
        return ports


def _load_classification_backend(config_path=CONFIG_FILE):
    try:
        cfg = ConfigManager(config_path=_resolve_classifier_config_path(config_path))
        cfg.load_config()
        return cfg.get_classification_backend()
    except Exception:
        return ""


def _read_json_file(path, default):
    try:
        with open(path, "r", encoding="utf-8") as file_handle:
            data = json.load(file_handle)
        return data if data is not None else default
    except Exception:
        return default


def _write_json_atomic(path, data):
    tmp_path = path + ".tmp"
    with open(tmp_path, "w", encoding="utf-8") as file_handle:
        json.dump(data, file_handle, ensure_ascii=False)
    os.replace(tmp_path, path)


def _zero_classifier_categories():
    return {
        "other": {"classid": "2:20", "tc_bytes": 0, "tc_packets": 0, "tc_kbps": 0.0, "pct": 0.0, "rule_hits": 0, "rule_bytes": 0},
        "gaming": {"classid": "2:21", "tc_bytes": 0, "tc_packets": 0, "tc_kbps": 0.0, "pct": 0.0, "rule_hits": 0, "rule_bytes": 0},
        "streaming": {"classid": "2:22", "tc_bytes": 0, "tc_packets": 0, "tc_kbps": 0.0, "pct": 0.0, "rule_hits": 0, "rule_bytes": 0},
        "bulk": {"classid": "2:23", "tc_bytes": 0, "tc_packets": 0, "tc_kbps": 0.0, "pct": 0.0, "rule_hits": 0, "rule_bytes": 0},
    }


def _normalize_mark_hex(value):
    try:
        return f"0x{firewall_manager.parse_mark(value):x}"
    except Exception:
        return str(value or "").strip().lower()


def _parse_nft_counter_line(line):
    counter_match = re.search(r"\bcounter\s+packets\s+(\d+)\s+bytes\s+(\d+)\b", line)
    if not counter_match:
        return None

    mark_match = re.search(r"\bmeta\s+mark\s+set\s+(0x[0-9a-fA-F]+|\d+)\b", line)
    if not mark_match:
        return None

    proto_match = re.search(r"\bmeta\s+l4proto\s+(\w+)\b", line)
    if not proto_match:
        proto_match = re.search(r"\b(tcp|udp)\b", line)
    dport_match = re.search(r"\b(?:th\s+)?dport\s+([0-9:-]+)\b", line)
    sport_match = re.search(r"\b(?:th\s+)?sport\s+([0-9:-]+)\b", line)
    src_ip_match = re.search(r"\bip\s+saddr\s+(\S+)\b", line)
    if not src_ip_match:
        src_ip_match = re.search(r"\bip6\s+saddr\s+(\S+)\b", line)

    return {
        "proto": (proto_match.group(1).strip().lower() if proto_match else ""),
        "dport": (dport_match.group(1).strip().replace(":", "-") if dport_match else ""),
        "sport": (sport_match.group(1).strip().replace(":", "-") if sport_match else ""),
        "src_ip": src_ip_match.group(1).strip() if src_ip_match else "",
        "mark": _normalize_mark_hex(mark_match.group(1)),
        "counter_packets": int(counter_match.group(1)),
        "counter_bytes": int(counter_match.group(2)),
    }


def _load_nft_counter_entries():
    nft_path = firewall_manager.find_command("nft")
    if not nft_path:
        return []

    cmd = [
        nft_path,
        "list",
        "chain",
        firewall_manager.NFT_TABLE_FAMILY,
        firewall_manager.NFT_TABLE_NAME,
        firewall_manager.NFT_CHAIN_NAME,
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True)
    except Exception:
        return []
    if proc.returncode != 0:
        return []

    entries = []
    for raw_line in (proc.stdout or "").splitlines():
        item = _parse_nft_counter_line(raw_line.strip())
        if item:
            entries.append(item)
    return entries


def _run_capture(cmd):
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True)
    except Exception as exc:
        return {"rc": -1, "stdout": "", "stderr": str(exc)}
    return {
        "rc": proc.returncode,
        "stdout": (proc.stdout or "").strip(),
        "stderr": (proc.stderr or "").strip(),
    }


def _pipeline_defaults(backend):
    return {
        "firewall": {
            "status": "fail",
            "backend": backend or "",
            "table": firewall_manager.NFT_TABLE_NAME,
            "chain": firewall_manager.NFT_CHAIN_NAME,
            "restore_mark_rule": False,
        },
        "mark_restore": {
            "status": "fail",
            "method": "unknown",
            "ingress_redirect": False,
            "ifb_up": False,
        },
        "tc": {
            "status": "fail",
            "upload_root_ready": False,
            "download_root_ready": False,
            "upload_filters_ready": False,
            "download_filters_ready": False,
        },
    }


def _has_all_filter_targets(filter_text, classids):
    text = str(filter_text or "")
    for classid in classids:
        if f"flowid {classid}" in text:
            continue
        if f"classid {classid}" in text:
            continue
        return False
    return True


def _build_classifier_pipeline(interface_name, backend):
    pipeline = _pipeline_defaults(backend)

    nft_path = firewall_manager.find_command("nft")
    if backend == "nft" and nft_path:
        table_result = _run_capture(
            [nft_path, "list", "table", firewall_manager.NFT_TABLE_FAMILY, firewall_manager.NFT_TABLE_NAME]
        )
        chain_result = _run_capture(
            [
                nft_path,
                "list",
                "chain",
                firewall_manager.NFT_TABLE_FAMILY,
                firewall_manager.NFT_TABLE_NAME,
                firewall_manager.NFT_CHAIN_NAME,
            ]
        )
        chain_text = chain_result["stdout"]
        restore_mark_rule = bool(
            re.search(r"\bct\s+mark\b.*\bmeta\s+mark\s+set\s+ct\s+mark\b", chain_text, re.IGNORECASE)
        )
        pipeline["firewall"]["restore_mark_rule"] = restore_mark_rule
        if table_result["rc"] == 0 and chain_result["rc"] == 0:
            pipeline["firewall"]["status"] = "ok"
    elif backend == "iptables":
        iptables_path = firewall_manager.find_command("iptables")
        if iptables_path:
            chain_result = _run_capture([iptables_path, "-t", firewall_manager.IPT_TABLE, "-S", firewall_manager.IPT_CHAIN])
            jump_result = _run_capture([iptables_path, "-t", firewall_manager.IPT_TABLE, "-C", "PREROUTING", "-j", firewall_manager.IPT_CHAIN])
            chain_text = chain_result["stdout"]
            restore_mark_rule = "--restore-mark" in chain_text and "CONNMARK" in chain_text
            pipeline["firewall"]["restore_mark_rule"] = restore_mark_rule
            if chain_result["rc"] == 0 and jump_result["rc"] == 0:
                pipeline["firewall"]["status"] = "ok"

    ip_path = firewall_manager.find_command("ip")
    if ip_path:
        ifb_result = _run_capture([ip_path, "link", "show", "ifb0"])
    else:
        ifb_result = {"rc": -1, "stdout": "", "stderr": ""}
    ifb_text = ifb_result["stdout"]
    ifb_up = bool(re.search(r"\bifb0\b", ifb_text) and (re.search(r"\bUP\b", ifb_text) or re.search(r"state\s+UP\b", ifb_text)))
    pipeline["mark_restore"]["ifb_up"] = ifb_up

    tc_path = firewall_manager.find_command("tc")
    ingress_text = ""
    upload_qdisc_text = ""
    download_qdisc_text = ""
    upload_class_text = ""
    download_class_text = ""
    upload_filter_text = ""
    download_filter_text = ""
    if tc_path:
        ingress_result = _run_capture([tc_path, "filter", "show", "dev", interface_name, "parent", "ffff:"])
        ingress_text = ingress_result["stdout"]
        upload_qdisc_text = _run_capture([tc_path, "qdisc", "show", "dev", interface_name])["stdout"]
        download_qdisc_text = _run_capture([tc_path, "qdisc", "show", "dev", "ifb0"])["stdout"]
        upload_class_text = _run_capture([tc_path, "class", "show", "dev", interface_name])["stdout"]
        download_class_text = _run_capture([tc_path, "class", "show", "dev", "ifb0"])["stdout"]
        upload_filter_text = _run_capture([tc_path, "filter", "show", "dev", interface_name, "parent", "1:"])["stdout"]
        download_filter_text = _run_capture([tc_path, "filter", "show", "dev", "ifb0", "parent", "2:"])["stdout"]

    ingress_redirect = bool(
        re.search(r"redirect\s+dev\s+ifb0\b", ingress_text, re.IGNORECASE)
        or re.search(r"Redirect\s+to\s+device\s+ifb0\b", ingress_text, re.IGNORECASE)
    )
    method = "unknown"
    if re.search(r"\bconnmark\b", ingress_text, re.IGNORECASE):
        method = "connmark"
    elif re.search(r"\bctinfo\b", ingress_text, re.IGNORECASE):
        method = "ctinfo"
    elif ingress_redirect:
        method = "mirred"
    pipeline["mark_restore"]["ingress_redirect"] = ingress_redirect
    pipeline["mark_restore"]["method"] = method
    if ingress_redirect and ifb_up and method in ("connmark", "ctinfo"):
        pipeline["mark_restore"]["status"] = "ok"
    elif ingress_redirect and ifb_up:
        pipeline["mark_restore"]["status"] = "warn"

    upload_root_ready = bool(
        re.search(r"\bqdisc htb 1:\s+root\b", upload_qdisc_text) and re.search(r"\bclass htb 1:1\b", upload_class_text)
    )
    download_root_ready = bool(
        re.search(r"\bqdisc htb 2:\s+root\b", download_qdisc_text) and re.search(r"\bclass htb 2:1\b", download_class_text)
    )
    upload_filters_ready = _has_all_filter_targets(upload_filter_text, ("1:11", "1:12", "1:13"))
    download_filters_ready = _has_all_filter_targets(download_filter_text, ("2:21", "2:22", "2:23"))
    pipeline["tc"]["upload_root_ready"] = upload_root_ready
    pipeline["tc"]["download_root_ready"] = download_root_ready
    pipeline["tc"]["upload_filters_ready"] = upload_filters_ready
    pipeline["tc"]["download_filters_ready"] = download_filters_ready
    if upload_root_ready and download_root_ready and upload_filters_ready and download_filters_ready:
        pipeline["tc"]["status"] = "ok"
    elif upload_root_ready or download_root_ready:
        pipeline["tc"]["status"] = "warn"

    return pipeline


def _build_classifier_diagnostics(summary, categories, pipeline, focus_dev, window_sec):
    diagnostics = []

    try:
        window_seconds = float(window_sec or 0)
    except Exception:
        window_seconds = 0.0

    for category in ("gaming", "streaming", "bulk"):
        item = categories.get(category, {})
        rule_bytes = int(item.get("rule_bytes", 0) or 0)
        tc_kbps = float(item.get("tc_kbps", 0) or 0)
        estimated_tc_window_bytes = int(max(0.0, tc_kbps) * 1000.0 * max(window_seconds, 0.0) / 8.0)
        if rule_bytes > 0 and rule_bytes > max(4096, estimated_tc_window_bytes * 2):
            diagnostics.append(
                {
                    "level": "warn",
                    "code": "RULE_HIT_BUT_TC_LOW",
                    "message": f"{category} 规则窗口字节高于 tc 分类窗口估算值，链路可能存在标记恢复或分类偏差",
                }
            )

    if focus_dev == "ifb0":
        try:
            total_kbps = float(summary.get("total_kbps", 0) or 0)
        except Exception:
            total_kbps = 0.0
        if total_kbps > 0 and not pipeline.get("tc", {}).get("download_filters_ready", False):
            diagnostics.append(
                {
                    "level": "error",
                    "code": "IFB_HAS_TRAFFIC_BUT_NO_TC_FILTER",
                    "message": "ifb0 存在下载流量，但下载侧 tc filter 不完整",
                }
            )

        try:
            classified_kbps = float(summary.get("classified_kbps", 0) or 0)
        except Exception:
            classified_kbps = 0.0
        try:
            other_kbps = float(summary.get("other_kbps", 0) or 0)
        except Exception:
            other_kbps = 0.0
        if total_kbps > 0 and classified_kbps <= (total_kbps * 0.2) and other_kbps >= (total_kbps * 0.6):
            diagnostics.append(
                {
                    "level": "warn",
                    "code": "DOWNLOAD_CLASSIFICATION_FALLBACK_TO_OTHER",
                    "message": "下载流量主要落入 other，下载分类可能回退到默认类",
                }
            )

    return diagnostics


def _rule_matches_nft_entry(rule, entry):
    if not rule.get("enabled"):
        return False
    if rule.get("_mark") and entry.get("mark") != rule.get("_mark"):
        return False

    proto = rule.get("_proto", "")
    if proto and proto != "all" and entry.get("proto") != proto:
        return False

    src_ip = rule.get("_src_ip", "")
    if src_ip and entry.get("src_ip") != src_ip:
        return False
    if not src_ip and entry.get("src_ip"):
        return False

    dports = rule.get("_dports", [])
    if dports:
        if not entry.get("dport") or entry.get("dport") not in dports:
            return False
    elif entry.get("dport"):
        return False

    sports = rule.get("_sports", [])
    if sports:
        if not entry.get("sport") or entry.get("sport") not in sports:
            return False
    elif entry.get("sport"):
        return False

    return True


def _apply_rule_window_state(rules):
    now_ts = int(time.time())
    prev_state = _read_json_file(CLASSIFIER_RULE_STATE_FILE, {})
    if not isinstance(prev_state, dict):
        prev_state = {}

    next_state = {}
    for rule in rules:
        rule_id = str(rule.get("id", "")).strip()
        prev = prev_state.get(rule_id, {}) if isinstance(prev_state.get(rule_id), dict) else {}

        current_packets = int(rule.get("counter_packets", 0) or 0)
        current_bytes = int(rule.get("counter_bytes", 0) or 0)
        prev_packets = prev.get("counter_packets")
        prev_bytes = prev.get("counter_bytes")

        if isinstance(prev_packets, int) and current_packets >= prev_packets:
            rule["last_window_packets"] = current_packets - prev_packets
        else:
            rule["last_window_packets"] = 0

        if isinstance(prev_bytes, int) and current_bytes >= prev_bytes:
            rule["last_window_bytes"] = current_bytes - prev_bytes
        else:
            rule["last_window_bytes"] = 0

        next_state[rule_id] = {
            "counter_packets": current_packets,
            "counter_bytes": current_bytes,
            "time": now_ts,
        }

    try:
        _write_json_atomic(CLASSIFIER_RULE_STATE_FILE, next_state)
    except Exception:
        pass


def _build_classifier_rules(config_path, focus_dev):
    resolved_config_path = _resolve_classifier_config_path(config_path)
    cfg = ConfigManager(config_path=resolved_config_path)
    try:
        cfg.load_config()
    except Exception:
        return _load_classification_backend(resolved_config_path), []

    classification_opts = cfg.get_section("classification", "classification")
    backend = str(classification_opts.get("backend", "")).strip()
    category_marks = _build_category_marks(classification_opts)
    mark_to_classid = _build_mark_to_classid(category_marks)

    flow_side = "download" if focus_dev == "ifb0" else "upload"
    class_rule_sections = cfg.get_sections("class_rule")
    rules = []

    for idx, rule_item in enumerate(class_rule_sections):
        try:
            opts = dict(rule_item.get("options", {}))
            rule_id = str(rule_item.get("name") or f"class_rule_{idx + 1}").strip() or f"class_rule_{idx + 1}"
            enabled = _to_bool(opts.get("enabled", "1"))
            category = str(opts.get("category", "other")).strip().lower() or "other"
            src_ip = str(opts.get("src_ip", "")).strip()
            dport = str(opts.get("dport", "")).strip()
            sport = str(opts.get("sport", "")).strip()
            proto = _normalize_proto(opts.get("proto", "any"))
            priority = int(str(opts.get("priority", "0")).strip())
            dports = _safe_parse_ports(dport)
            sports = _safe_parse_ports(sport)
            mark = category_marks.get(category, "")
            classid = mark_to_classid.get(mark, {}).get(flow_side, "")
            rules.append(
                {
                    "id": rule_id,
                    "enabled": bool(enabled),
                    "priority": priority,
                    "category": category,
                    "proto": proto,
                    "dport": dport,
                    "sport": sport,
                    "src_ip": src_ip,
                    "mark": mark,
                    "classid": classid,
                    "counter_packets": 0,
                    "counter_bytes": 0,
                    "last_window_packets": 0,
                    "last_window_bytes": 0,
                    "status": "disabled" if not enabled else "idle",
                    "_order": idx,
                    "_proto": proto,
                    "_dports": dports,
                    "_sports": sports,
                    "_src_ip": src_ip,
                    "_mark": mark,
                }
            )
        except Exception:
            continue

    if backend == "nft":
        match_order = sorted(
            [rule for rule in rules if rule.get("enabled")],
            key=lambda item: (-int(item.get("priority", 0)), int(item.get("_order", 0))),
        )
        for entry in _load_nft_counter_entries():
            for rule in match_order:
                if _rule_matches_nft_entry(rule, entry):
                    rule["counter_packets"] += int(entry.get("counter_packets", 0) or 0)
                    rule["counter_bytes"] += int(entry.get("counter_bytes", 0) or 0)
                    break

    _apply_rule_window_state(rules)

    for rule in rules:
        if not rule.get("enabled"):
            rule["status"] = "disabled"
        elif int(rule.get("counter_packets", 0) or 0) > 0:
            rule["status"] = "hit"
        else:
            rule["status"] = "idle"
        for key in ("_order", "_proto", "_dports", "_sports", "_src_ip", "_mark"):
            rule.pop(key, None)

    return backend, rules


def _build_classifier_state(stats_result, backend, focus_dev, rules=None, pipeline=None):
    now_ts = int(time.time())
    categories = _zero_classifier_categories()
    rules = rules if isinstance(rules, list) else []
    pipeline = pipeline if isinstance(pipeline, dict) else _pipeline_defaults(backend)
    summary = {
        "total_kbps": 0.0,
        "classified_kbps": 0.0,
        "other_kbps": 0.0,
        "classification_ratio": 0.0,
        "rules_total": len(rules),
        "rules_active": sum(1 for rule in rules if rule.get("enabled")),
        "health": "degraded",
    }
    result = {
        "success": False,
        "time": now_ts,
        "window_sec": 0,
        "backend": backend or "",
        "focus_dev": focus_dev,
        "summary": summary,
        "categories": categories,
        "rules": rules,
        "pipeline": pipeline,
        "diagnostics": [],
    }

    if not isinstance(stats_result, dict):
        return result

    result["success"] = bool(stats_result.get("success"))
    result["time"] = int(stats_result.get("time", now_ts) or now_ts)
    try:
        result["window_sec"] = float(stats_result.get("dt", 0) or 0)
    except Exception:
        result["window_sec"] = 0

    class_data = stats_result.get("classes", {}) if isinstance(stats_result.get("classes"), dict) else {}
    for category in categories:
        item = class_data.get(category, {}) if isinstance(class_data.get(category), dict) else {}
        base = categories[category]
        base["classid"] = str(item.get("classid", base["classid"])) or base["classid"]
        try:
            base["tc_bytes"] = int(item.get("bytes", 0) or 0)
        except Exception:
            base["tc_bytes"] = 0
        try:
            base["tc_packets"] = int(item.get("packets", 0) or 0)
        except Exception:
            base["tc_packets"] = 0
        try:
            base["tc_kbps"] = round(float(item.get("kbps", 0) or 0), 2)
        except Exception:
            base["tc_kbps"] = 0.0
        try:
            base["pct"] = round(float(item.get("pct", 0) or 0), 2)
        except Exception:
            base["pct"] = 0.0

    for rule in rules:
        if not isinstance(rule, dict):
            continue
        category = str(rule.get("category", "")).strip().lower()
        if category not in categories:
            continue
        try:
            categories[category]["rule_hits"] += int(rule.get("last_window_packets", 0) or 0)
        except Exception:
            pass
        try:
            categories[category]["rule_bytes"] += int(rule.get("last_window_bytes", 0) or 0)
        except Exception:
            pass

    summary["total_kbps"] = round(float(stats_result.get("total_kbps", 0) or 0), 2)
    summary["classified_kbps"] = round(
        categories["gaming"]["tc_kbps"] + categories["streaming"]["tc_kbps"] + categories["bulk"]["tc_kbps"],
        2,
    )
    summary["other_kbps"] = round(categories["other"]["tc_kbps"], 2)
    if summary["total_kbps"] > 0:
        summary["classification_ratio"] = round(summary["classified_kbps"] / summary["total_kbps"] * 100.0, 2)
    else:
        summary["classification_ratio"] = 0.0
    summary["health"] = "ok" if summary["classified_kbps"] > 0 else "degraded"
    if summary["total_kbps"] == 0:
        summary["health"] = "degraded"
    result["diagnostics"] = _build_classifier_diagnostics(
        summary,
        categories,
        pipeline,
        focus_dev,
        result.get("window_sec", 0),
    )

    return result


class SQMController:
    def __init__(self, config_path=None):
        self.config_manager = ConfigManager(config_path)
        self.config = {}
        self._reload_config(force=True)

    def _reload_config(self, force=False):
        if force or not self.config:
            self.config_manager.load_config()
            settings = self.config_manager.get_settings()
            self.config = settings["all"]
        return self.config

    def _current_all_settings(self):
        self._reload_config(force=True)
        return self.config_manager.get_settings()["all"].copy()

    def _diff_config(self, before, after):
        changes = {}
        for key in sorted(set(before.keys()) | set(after.keys())):
            old = before.get(key)
            new = after.get(key)
            if old != new:
                changes[key] = {"from": old, "to": new}
        return changes

    def _apply_runtime_config(self, enabled_override=None):
        self._reload_config(force=True)
        enabled = _to_bool(self.config.get("enabled", False))
        if enabled_override is not None:
            enabled = bool(enabled_override)
            self.config["enabled"] = enabled

        if not enabled:
            cleanup = self._clear_classifier_runtime()
            return {
                "requested": True,
                "enabled": False,
                "applied": bool(cleanup.get("success")),
                "restart_success": bool(cleanup.get("success")),
                "message": "service disabled, runtime cleared" if cleanup.get("success") else "service disabled, runtime clear failed",
                "cleanup": cleanup,
            }

        tc = TCManager(self.config)
        ok = tc.setup_htb()
        if not ok:
            return {
                "requested": True,
                "enabled": True,
                "applied": False,
                "restart_success": False,
                "message": "failed to apply tc rules",
            }

        classifier_runtime = self._apply_classifier_runtime()
        if not classifier_runtime.get("requested"):
            return {
                "requested": True,
                "enabled": True,
                "applied": True,
                "restart_success": True,
                "message": "tc rules applied",
                "classifier": classifier_runtime,
            }

        classifier_ok = bool(classifier_runtime.get("applied"))
        return {
            "requested": True,
            "enabled": True,
            "applied": classifier_ok,
            "restart_success": classifier_ok,
            "message": "tc and classifier applied" if classifier_ok else "classifier apply failed after tc setup",
            "classifier": classifier_runtime,
        }

    def _apply_classifier_runtime(self):
        classification = self.config_manager.get_section("classification", "classification")
        if not _to_bool(classification.get("enabled", False)):
            return {
                "requested": False,
                "enabled": False,
                "applied": True,
                "message": "classification disabled",
            }

        try:
            result = traffic_classifier.run_classifier(config_path=self.config_manager.config_path)
        except Exception as exc:
            logging.exception("_apply_classifier_runtime() failed: %s", exc)
            result = {"success": False, "error": str(exc)}

        return {
            "requested": True,
            "enabled": True,
            "applied": bool(result.get("success")),
            "message": "classifier applied" if result.get("success") else "classifier apply failed",
            "result": result,
        }

    def _clear_classifier_runtime(self):
        self._reload_config(force=True)
        configured_backend = self.config_manager.get_classification_backend()
        result = {
            "success": True,
            "firewall": {},
            "tc": {},
            "errors": [],
        }

        try:
            result["firewall"] = firewall_manager.clear_rules(preferred_backend=configured_backend)
        except Exception as exc:
            result["firewall"] = {"success": False, "error": str(exc)}
        if not result["firewall"].get("success"):
            result["errors"].append(f"firewall: {result['firewall'].get('error', 'clear failed')}")

        try:
            tc_result = TCManager(self.config).clear_classifier_tc()
            result["tc"] = tc_result if isinstance(tc_result, dict) else {"success": bool(tc_result)}
        except Exception as exc:
            result["tc"] = {"success": False, "error": str(exc)}
        if not result["tc"].get("success"):
            result["errors"].append(f"tc: {result['tc'].get('error', 'clear failed')}")

        result["success"] = len(result["errors"]) == 0
        return result

    def _managed_tc_runtime_state(self):
        self._reload_config(force=True)
        iface = self.config_manager.get_interface()
        tc_wan = subprocess.getoutput(f"tc qdisc show dev {iface} 2>/dev/null")
        tc_ifb = subprocess.getoutput("tc qdisc show dev ifb0 2>/dev/null")
        wan_managed = "qdisc htb 1:" in (tc_wan or "").lower()
        ifb_managed = "qdisc htb 2:" in (tc_ifb or "").lower()
        return {
            "iface": iface,
            "tc_wan": tc_wan,
            "tc_ifb": tc_ifb,
            "wan_managed": wan_managed,
            "ifb_managed": ifb_managed,
            "running": wan_managed or ifb_managed,
        }

    def enable(self):
        logging.info("enable() called")
        runtime = self._apply_runtime_config(enabled_override=True)
        ok = bool(runtime.get("applied"))
        result = {
            "success": ok,
            "runtime": runtime,
        }
        logging.info("enable() runtime => %s", runtime)
        if ok:
            self.config_manager.set_value("enabled", True, "basic_config")
            saved = self.config_manager.save_config()
            result["config_saved"] = bool(saved)
            result["message"] = "enabled"
            if not saved:
                result["success"] = False
                result["error"] = "enabled but failed to save config"
            return result

        cleanup = self._clear_classifier_runtime()
        self.config_manager.set_value("enabled", False, "basic_config")
        saved = self.config_manager.save_config()
        result["cleanup"] = cleanup
        result["config_saved"] = bool(saved)
        result["message"] = "enable failed"
        classifier = runtime.get("classifier", {}) if isinstance(runtime.get("classifier"), dict) else {}
        classifier_result = classifier.get("result", {}) if isinstance(classifier.get("result"), dict) else {}
        result["error"] = (
            classifier_result.get("error")
            or classifier.get("message")
            or runtime.get("message")
            or "enable failed"
        )
        return result

    def disable(self):
        logging.info("disable() called")
        cleanup = self._clear_classifier_runtime()
        runtime_state = self._managed_tc_runtime_state()
        runtime_cleared = not runtime_state.get("running")
        if not runtime_cleared:
            logging.error(
                "disable() runtime verify failed: iface=%s wan_managed=%s ifb_managed=%s",
                runtime_state.get("iface"),
                runtime_state.get("wan_managed"),
                runtime_state.get("ifb_managed"),
            )

        saved = False
        if bool(cleanup.get("success")) and runtime_cleared:
            self.config_manager.set_value("enabled", False, "basic_config")
            saved = self.config_manager.save_config()

        ok = bool(cleanup.get("success")) and runtime_cleared and bool(saved)
        logging.info("disable() cleanup => %s", cleanup)
        logging.info("disable() runtime verify => %s", runtime_state)
        logging.info("disable() done saved=%s", saved)
        return ok

    def apply_template(self, name):
        logging.info("apply_template(%s) called", name)
        template = get_template(name)
        if not template:
            logging.warning("template not found: %s", name)
            return {"success": False, "error": "template not found", "template": name}

        before = self._current_all_settings()

        self.config_manager.set_value("upload_speed", template["upload"], "basic_config")
        self.config_manager.set_value("download_speed", template["download"], "basic_config")
        self.config_manager.set_value("queue_algorithm", template["algorithm"], "basic_config")
        self.config_manager.set_value("ecn", str(template.get("ecn", False)).lower(), "advanced_config")

        saved = self.config_manager.save_config()
        if not saved:
            return {
                "success": False,
                "error": "failed to save config",
                "template": name,
                "changes": {},
            }

        after = self._current_all_settings()
        runtime = self._apply_runtime_config()
        success = bool(runtime.get("applied"))

        return {
            "success": success,
            "template": name,
            "changes": self._diff_config(before, after),
            "runtime": runtime,
        }

    def validate_config_file(self, path):
        return _load_validation_result(path)

    def restore_config(self, path, apply_now=True):
        validation = self.validate_config_file(path)
        if not validation["valid"]:
            return {
                "success": False,
                "error": "config validation failed",
                "validation": validation,
            }

        before = self._current_all_settings()
        backup_path = None

        try:
            if os.path.exists(CONFIG_FILE):
                backup_path = f"/tmp/sqm_controller.backup.{time.strftime('%Y%m%d-%H%M%S')}"
                shutil.copy2(CONFIG_FILE, backup_path)

            shutil.copy2(path, CONFIG_FILE)
            self._reload_config(force=True)
            after = self._current_all_settings()

            runtime = {"requested": bool(apply_now), "applied": False}
            if apply_now:
                runtime = self._apply_runtime_config()

            success = True if not apply_now else bool(runtime.get("applied"))
            return {
                "success": success,
                "backup_path": backup_path,
                "changes": self._diff_config(before, after),
                "validation": validation,
                "runtime": runtime,
            }
        except Exception as exc:
            logging.exception("restore_config() failed: %s", exc)
            return {
                "success": False,
                "error": f"restore failed: {exc}",
                "backup_path": backup_path,
                "validation": validation,
            }

    def status_json(self):
        runtime_state = self._managed_tc_runtime_state()
        iface = runtime_state.get("iface")
        tc_wan = runtime_state.get("tc_wan", "")
        tc_ifb = runtime_state.get("tc_ifb", "")
        tc_wan_detail = subprocess.getoutput(f"tc -d qdisc show dev {iface} 2>/dev/null")
        tc_ifb_detail = subprocess.getoutput("tc -d qdisc show dev ifb0 2>/dev/null")

        # "qdisc fq_codel 0: root" can be kernel default after clearing rules.
        # Only regard SQM as applied when our managed HTB roots exist.
        running = bool(runtime_state.get("running"))

        ecn_state = _merge_ecn_state(
            _ecn_from_tc_output(tc_wan_detail),
            _ecn_from_tc_output(tc_ifb_detail),
            running,
        )

        data = {
            "service_status": "running" if running else "stopped",
            "pid": "N/A(no resident process)",
            "tc_state": "applied" if running else "not_applied",
            "ecn_state": ecn_state,
            "tc_wan": tc_wan,
            "tc_ifb": tc_ifb,
        }
        data.update(_load_runtime_metadata(self.config_manager))
        tc_state = TCManager(self.config).inspect_runtime_state(
            classification_enabled=_to_bool(self.config_manager.get_section("classification", "classification").get("enabled", False))
        )
        data.update({
            "upload_class_queues_present": tc_state.get("upload_class_queues_present", False),
            "download_class_queues_present": tc_state.get("download_class_queues_present", False),
            "classifier_tc_complete": tc_state.get("classifier_tc_complete", False),
        })
        print(json.dumps(data, ensure_ascii=False))

    def rotate_logs_json(self):
        result = rotate_logs()
        logging.info("rotate_logs_json() rotated=%s", result.get("rotated"))
        print(json.dumps(result, ensure_ascii=False))

    def self_check_json(self):
        if not os.path.exists(SELF_CHECK_PY):
            print(json.dumps({"success": False, "error": "self_check.py not found"}, ensure_ascii=False))
            return
        out = subprocess.getoutput(f"python3 {SELF_CHECK_PY}")
        print(out)

    def monitor_json(self):
        self._reload_config(force=True)
        iface = self.config_manager.get_interface()
        logging.info("monitor_json() iface=%s", iface)
        out = subprocess.getoutput(f"/usr/lib/sqm-controller/monitor.py --iface {iface} --record")
        print(out)

    def monitor_history_json(self, window):
        self._reload_config(force=True)
        iface = self.config_manager.get_interface()
        if window not in {"1m", "5m", "1h"}:
            window = "5m"
        logging.info("monitor_history_json() iface=%s window=%s", iface, window)
        out = subprocess.getoutput(
            f"/usr/lib/sqm-controller/monitor.py --iface {iface} --history --window {window}"
        )
        print(out)

    def speedtest(self):
        """
        改为调用 /usr/lib/sqm-controller/speedtest.py 做“下载测速（只下行）”，
        只更新 download_speed，不修改 upload_speed，保存并应用 tc 规则。
        """
        logging.info("speedtest() called")

        SPEEDTEST_PY = "/usr/lib/sqm-controller/speedtest.py"
        try:
            if not os.path.exists(SPEEDTEST_PY):
                raise Exception("speedtest.py not found")

            # 运行测速脚本，读取 JSON 输出
            out = subprocess.getoutput(f"python3 {SPEEDTEST_PY}")
            try:
                result = json.loads(out)
            except Exception:
                raise Exception(f"speedtest.py returned non-json: {out}")

            if isinstance(result, dict) and result.get("error"):
                # 透传错误信息（前端会看到 raw）
                raise Exception(result.get("raw") or result.get("error"))

            down_kbps = result.get("download")
            if down_kbps is None:
                raise Exception(f"speedtest result missing download: {result}")

            try:
                down_kbps = int(down_kbps)
            except Exception:
                raise Exception(f"invalid download value: {down_kbps}")

            if down_kbps <= 0:
                raise Exception("download speed is <= 0")

            # 预留 15% headroom（沿用你原逻辑的 0.85）
            down_apply = int(down_kbps * 0.85)

            # 记录变更前（用于回显）
            before = self._current_all_settings()
            old_up = before.get("upload_speed")

            # 只更新 download_speed，不动 upload_speed
            self.config_manager.set_value("download_speed", down_apply, "basic_config")
            saved = self.config_manager.save_config()
            if not saved:
                raise Exception("failed to save config")

            runtime = self._apply_runtime_config()
            if not runtime.get("applied"):
                raise Exception("speedtest result saved but failed to apply tc rules")

            after = self._current_all_settings()
            print(json.dumps({
                "download": down_apply,
                "upload": old_up,                 # 保留原 upload（不改）
                "backend": result.get("backend"),
                "source_url": result.get("url") or result.get("url_effective"),
                "time_total": result.get("time_total"),
                "http_code": result.get("http_code"),
                "changes": self._diff_config(before, after),
                "runtime": runtime
            }, ensure_ascii=False))

        except Exception as exc:
            logging.exception("speedtest() failed: %s", exc)
            print(json.dumps({"error": "speedtest failed", "raw": str(exc)}, ensure_ascii=False))

def main():
    setup_logging()

    parser = argparse.ArgumentParser()
    parser.add_argument("--enable", action="store_true")
    parser.add_argument("--disable", action="store_true")
    parser.add_argument("--status-json", action="store_true")
    parser.add_argument("--monitor", action="store_true")
    parser.add_argument("--monitor-history", action="store_true")
    parser.add_argument("--window", choices=["1m", "5m", "1h"], default="5m")
    parser.add_argument("--speedtest", action="store_true")
    parser.add_argument("--rotate-logs", action="store_true")
    parser.add_argument("--self-check", action="store_true")
    parser.add_argument("--template")
    parser.add_argument("--validate-config")
    parser.add_argument("--restore-config")
    parser.add_argument("--no-apply", action="store_true")
    parser.add_argument("--apply-classifier", action="store_true")
    parser.add_argument("--clear-classifier", action="store_true")
    parser.add_argument("--get-class-stats", action="store_true")
    parser.add_argument("--get-classifier-state", action="store_true")
    parser.add_argument("--policy-once", action="store_true")
    parser.add_argument("--export-report", action="store_true")
    parser.add_argument("--format", choices=["json", "csv"], default="json")
    parser.add_argument("--dev", default="ifb0")
    args = parser.parse_args()

    ctl = SQMController()

    if args.status_json:
        ctl.status_json()
    elif args.monitor:
        ctl.monitor_json()
    elif args.monitor_history:
        ctl.monitor_history_json(args.window)
    elif args.speedtest:
        ctl.speedtest()
    elif args.rotate_logs:
        ctl.rotate_logs_json()
    elif args.self_check:
        ctl.self_check_json()
    elif args.validate_config:
        result = ctl.validate_config_file(args.validate_config)
        print(json.dumps(result, ensure_ascii=False))
        raise SystemExit(0 if result.get("valid") else 1)
    elif args.restore_config:
        result = ctl.restore_config(args.restore_config, apply_now=(not args.no_apply))
        print(json.dumps(result, ensure_ascii=False))
        raise SystemExit(0 if result.get("success") else 1)
    elif args.template:
        result = ctl.apply_template(args.template)
        print(json.dumps(result, ensure_ascii=False))
        raise SystemExit(0 if result.get("success") else 1)
    elif args.apply_classifier:
        ctl._reload_config(force=True)
        try:
            result = traffic_classifier.run_classifier(config_path=ctl.config_manager.config_path)
        except Exception as exc:
            result = {"success": False, "error": str(exc)}

        if result.get("success"):
            tc_state = TCManager(ctl.config).inspect_runtime_state(
                classification_enabled=_to_bool(
                    ctl.config_manager.get_section("classification", "classification").get("enabled", False)
                )
            )
            verify_cmd = "tc runtime classifier completeness"
            if not tc_state.get("classifier_tc_complete", False):
                result["success"] = False
                result["error"] = "classifier verify failed: tc classifier queues are incomplete"
                details = result.get("details")
                if not isinstance(details, dict):
                    details = {}
                details["verify_cmd"] = verify_cmd
                details["tc_runtime_state"] = tc_state
                result["details"] = details
        print(json.dumps(result, ensure_ascii=False))
        raise SystemExit(0 if result.get("success") else 1)
    elif args.clear_classifier:
        ctl._reload_config(force=True)
        result = ctl._clear_classifier_runtime()
        print(json.dumps(result, ensure_ascii=False))
        raise SystemExit(0 if result.get("success") else 1)
    elif args.get_class_stats:
        ctl._reload_config(force=True)
        try:
            dev = (args.dev or "ifb0").strip() or "ifb0"
            if dev in {"iface", "wan", "interface"}:
                dev = ctl.config_manager.get_interface()
            result = traffic_stats.collect(dev)
        except Exception as exc:
            result = {"success": False, "error": str(exc), "details": {}}
        print(json.dumps(result, ensure_ascii=False))
        raise SystemExit(0 if result.get("success") else 1)
    elif args.get_classifier_state:
        ctl._reload_config(force=True)
        focus_dev = (args.dev or "ifb0").strip() or "ifb0"
        if focus_dev in {"iface", "wan", "interface"}:
            focus_dev = ctl.config_manager.get_interface()
        try:
            stats_result = traffic_stats.collect(focus_dev)
        except Exception:
            stats_result = {"success": False, "time": int(time.time()), "dt": 0, "classes": {}, "total_kbps": 0}
        backend, rules = _build_classifier_rules(ctl.config_manager.config_path, focus_dev)
        pipeline = _build_classifier_pipeline(ctl.config_manager.get_interface(), backend)
        result = _build_classifier_state(stats_result, backend, focus_dev, rules=rules, pipeline=pipeline)
        print(json.dumps(result, ensure_ascii=False))
        raise SystemExit(0 if result.get("success") else 1)
    elif args.policy_once:
        try:
            result = policy_engine.run_once(config_path=ctl.config_manager.config_path)
        except Exception as exc:
            result = {"success": False, "error": str(exc), "details": {}, "actions": [], "changed": False}
        if not isinstance(result, dict):
            result = {"success": False, "error": "invalid policy_once result", "details": {}, "actions": [], "changed": False}
        if not isinstance(result.get("actions"), list):
            result["actions"] = []
        print(json.dumps(result, ensure_ascii=False))
        raise SystemExit(0 if result.get("success") else 1)
    elif args.export_report:
        entries, err = _load_policy_report_entries()
        if err:
            print(json.dumps(err, ensure_ascii=False))
            raise SystemExit(1)

        fmt = (args.format or "json").strip().lower()
        if fmt not in {"json", "csv"}:
            result = {"success": False, "error": "invalid format", "details": {"format": args.format}}
            print(json.dumps(result, ensure_ascii=False))
            raise SystemExit(1)

        if fmt == "json":
            result = {
                "success": True,
                "format": "json",
                "count": len(entries),
                "entries": entries,
            }
            print(json.dumps(result, ensure_ascii=False))
            raise SystemExit(0)

        headers = [
            "time",
            "decision.mode",
            "decision.reason",
            "inputs.monitor.latency",
            "inputs.monitor.loss",
            "inputs.traffic_stats.total_kbps",
            "changed",
        ]
        rows = [",".join(headers)]
        for item in entries:
            row = [
                _dict_get(item, ["time"], ""),
                _dict_get(item, ["decision", "mode"], ""),
                _dict_get(item, ["decision", "reason"], ""),
                _dict_get(item, ["inputs", "monitor", "latency"], ""),
                _dict_get(item, ["inputs", "monitor", "loss"], ""),
                _dict_get(item, ["inputs", "traffic_stats", "total_kbps"], ""),
                _dict_get(item, ["changed"], ""),
            ]
            rows.append(",".join(_csv_escape(value) for value in row))
        print("\n".join(rows))
        raise SystemExit(0)
    elif args.enable:
        result = ctl.enable()
        if result.get("success"):
            print("enabled")
            raise SystemExit(0)
        print(json.dumps(result, ensure_ascii=False))
        raise SystemExit(1)
    elif args.disable:
        ok = ctl.disable()
        print("disabled" if ok else "disable failed")
        raise SystemExit(0 if ok else 1)
    else:
        ctl.status_json()


if __name__ == "__main__":
    main()
