#!/usr/bin/env python3
import argparse
import json
import logging
import os
import re

from config_manager import ConfigManager, detect_rule_conflicts
import firewall_manager
from tc_manager import TCManager


CATEGORY_FLOWIDS = {
    "gaming": {"upload": "1:11", "download": "2:21"},
    "streaming": {"upload": "1:12", "download": "2:22"},
    "bulk": {"upload": "1:13", "download": "2:23"},
}

DEFAULT_CATEGORY_MARKS = {
    "other": "0x10",
    "gaming": "0x11",
    "streaming": "0x12",
    "bulk": "0x13",
}

IPV6_SCOPE_WARNING = (
    "IPv4 download classification is guaranteed in v3.0 first release; "
    "IPv6 download classification requires setup_htb() redirect enhancement."
)
PREFERRED_CONFIG_PATH = "/etc/config/sqm_controller"
FALLBACK_CONFIG_PATH = "/etc/config/sqm-controller"


def _to_bool(value, default=False):
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    text = str(value).strip().lower()
    if text in ("1", "true", "yes", "on"):
        return True
    if text in ("0", "false", "no", "off"):
        return False
    return default


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
    text = text.strip()
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
                section_type = config_match.group(1)
                section_name = _unquote(config_match.group(2) or "")
                current = {
                    "type": section_type,
                    "name": section_name,
                    "options": {},
                    "order": len(sections),
                    "line": lineno,
                }
                sections.append(current)
                continue

            option_match = re.match(r"^\s*option\s+([A-Za-z0-9_]+)\s+(.+)$", line)
            if option_match and current is not None:
                key = option_match.group(1)
                value = _unquote(option_match.group(2))
                current["options"][key] = value
                continue

    return sections


def _get_first_section(sections, section_type):
    for section in sections:
        if section["type"] == section_type:
            return section
    return None


def _get_all_sections(sections, section_type):
    return [section for section in sections if section["type"] == section_type]


def _to_int(value, default=0):
    try:
        return int(str(value).strip())
    except Exception:
        return default


def _mark_to_hex(value, field_name):
    if isinstance(value, int):
        mark_int = value
    else:
        text = str(value).strip().lower()
        if not text:
            raise ValueError(f"{field_name} is empty")
        mark_int = int(text, 16) if text.startswith("0x") else int(text, 10)

    if mark_int <= 0 or mark_int > 0xFFFFFFFF:
        raise ValueError(f"{field_name} out of range")
    return f"0x{mark_int:x}"


def _normalize_proto(proto_value, rule_name):
    proto = str(proto_value or "any").strip().lower()
    if proto in ("any", "*", ""):
        return "all"
    if proto in ("tcp", "udp"):
        return proto
    raise ValueError(f"{rule_name}: unsupported proto '{proto}'")


def _specificity_score(proto, ports, sport, ip_value):
    score = 0
    if ip_value:
        score += 100
    if ports or sport:
        score += 10
    if proto in ("tcp", "udp"):
        score += 1
    return score


def _build_category_marks(classification_options):
    marks = {}
    for category in ("other", "gaming", "streaming", "bulk"):
        key = f"mark_{category}"
        raw_value = classification_options.get(key, DEFAULT_CATEGORY_MARKS[category])
        marks[category] = _mark_to_hex(raw_value, key)
    return marks


def _build_mark_to_classid(category_marks):
    mapping = {}
    for category, flow in CATEGORY_FLOWIDS.items():
        mark_hex = category_marks[category]
        mapping[mark_hex] = {"upload": flow["upload"], "download": flow["download"]}
    return mapping


def _build_tc_plan(settings):
    upload_kbps = _to_int(settings.get("upload_speed", settings.get("upload_bandwidth", 0)), 0)
    download_kbps = _to_int(settings.get("download_speed", settings.get("download_bandwidth", 0)), 0)
    if upload_kbps <= 0 or download_kbps <= 0:
        raise ValueError("upload_speed/download_speed must be > 0 for classifier apply")

    qdisc = str(settings.get("queue_algorithm", "fq_codel")).strip().lower()
    if qdisc not in ("fq_codel", "cake"):
        qdisc = "fq_codel"

    return {
        "upload_classes": [
            {"classid": "1:11", "rate_kbps": upload_kbps, "ceil_kbps": upload_kbps, "prio": 10, "qdisc": qdisc},
            {"classid": "1:12", "rate_kbps": upload_kbps, "ceil_kbps": upload_kbps, "prio": 20, "qdisc": qdisc},
            {"classid": "1:13", "rate_kbps": upload_kbps, "ceil_kbps": upload_kbps, "prio": 30, "qdisc": qdisc},
        ],
        "download_classes": [
            {
                "classid": "2:21",
                "rate_kbps": download_kbps,
                "ceil_kbps": download_kbps,
                "prio": 10,
                "qdisc": qdisc,
            },
            {
                "classid": "2:22",
                "rate_kbps": download_kbps,
                "ceil_kbps": download_kbps,
                "prio": 20,
                "qdisc": qdisc,
            },
            {
                "classid": "2:23",
                "rate_kbps": download_kbps,
                "ceil_kbps": download_kbps,
                "prio": 30,
                "qdisc": qdisc,
            },
        ],
    }


def _build_fw_map(category_marks):
    fw_map = []
    for category, flow in CATEGORY_FLOWIDS.items():
        fw_map.append(
            {
                "mark": category_marks[category],
                "upload_flowid": flow["upload"],
                "download_flowid": flow["download"],
            }
        )
    return fw_map


def _prepare_raw_rules(class_rule_sections, category_marks):
    errors = []
    prepared = []

    for idx, section in enumerate(class_rule_sections):
        opts = section.get("options", {})
        if not _to_bool(opts.get("enabled", "1"), default=True):
            continue

        rule_name = str(section.get("name") or opts.get("name") or f"class_rule_{idx + 1}").strip()
        category = str(opts.get("category", "other")).strip().lower() or "other"
        if category not in category_marks:
            errors.append(f"{rule_name}: unsupported category '{category}'")
            continue

        dst_ip = str(opts.get("dst_ip", "")).strip()
        if dst_ip:
            errors.append(f"{rule_name}: dst_ip is not supported in this release")
            continue

        try:
            proto = _normalize_proto(opts.get("proto", "any"), rule_name)
        except Exception as exc:
            errors.append(str(exc))
            continue

        try:
            priority = int(str(opts.get("priority", "0")).strip())
        except Exception:
            errors.append(f"{rule_name}: invalid priority '{opts.get('priority')}'")
            continue

        ports = str(opts.get("dport", "")).strip()
        sport = str(opts.get("sport", "")).strip()
        ip_value = str(opts.get("src_ip", "")).strip()
        specificity = _specificity_score(proto, ports, sport, ip_value)

        prepared.append(
            {
                "_order": idx,
                "_specificity": specificity,
                "proto": proto,
                "ports": ports,
                "sport": sport,
                "ip": ip_value,
                "priority": priority,
                "category": category,
                "mark": category_marks[category],
            }
        )

    prepared.sort(key=lambda item: (-item["priority"], -item["_specificity"], item["_order"]))
    raw_rules = []
    for item in prepared:
        raw_rules.append(
            {
                "proto": item["proto"],
                "ports": item["ports"],
                "sport": item["sport"],
                "ip": item["ip"],
                "priority": item["priority"],
                "category": item["category"],
                "mark": item["mark"],
            }
        )
    return raw_rules, errors


def _resolve_config_path(config_path):
    candidates = []

    def add_candidate(path):
        text = str(path or "").strip()
        if text and text not in candidates:
            candidates.append(text)

    add_candidate(PREFERRED_CONFIG_PATH)
    add_candidate(FALLBACK_CONFIG_PATH)
    add_candidate(config_path)

    for path in candidates:
        try:
            if os.path.isfile(path):
                return path, candidates
        except Exception:
            continue

    return (str(config_path).strip() if str(config_path or "").strip() else PREFERRED_CONFIG_PATH), candidates


def run_classifier(config_path=None):
    result = {
        "success": False,
        "rules_count": 0,
        "backend": "",
        "marks": {"category_marks": {}, "mark_to_classid": {}},
        "errors": [],
        "warnings": [IPV6_SCOPE_WARNING],
        "details": {},
    }

    resolved_config_path, config_candidates = _resolve_config_path(config_path)
    result["details"]["config_path"] = resolved_config_path
    result["details"]["config_candidates"] = config_candidates
    result["details"]["firewall_applied"] = False

    cfg = ConfigManager(config_path=resolved_config_path)
    cfg.load_config()
    settings = cfg.get_settings().get("all", {})
    config_file = resolved_config_path
    result["details"]["config_path_used_by_manager"] = config_file

    sections = []
    for section_type in ("basic_config", "advanced_config", "classification", "policy", "class_rule"):
        if section_type == "class_rule":
            for item in cfg.get_sections("class_rule"):
                sections.append({"type": "class_rule", "name": item.get("name", ""), "options": item.get("options", {})})
            continue
        item = cfg.get_section(section_type, section_type)
        if item:
            sections.append({"type": section_type, "name": section_type, "options": item})
    result["details"]["sections_count"] = len(sections)
    result["details"]["sections_found"] = {
        "classification": len([s for s in sections if s["type"] == "classification"]),
        "class_rule": len([s for s in sections if s["type"] == "class_rule"]),
        "policy": len([s for s in sections if s["type"] == "policy"]),
    }

    classification = next((s for s in sections if s["type"] == "classification"), None)
    policy = next((s for s in sections if s["type"] == "policy"), None)
    class_rules = [s for s in sections if s["type"] == "class_rule"]
    result["details"]["policy"] = policy.get("options", {}) if policy else {}

    if classification is None:
        result["errors"].append("missing classification section")
        result["details"]["aborted_before_firewall"] = True
        return result

    classification_opts = classification.get("options", {})
    result["details"]["first_classification_options"] = classification_opts
    configured_backend = str(classification_opts.get("backend", "")).strip().lower()
    result["details"]["configured_backend"] = configured_backend
    try:
        category_marks = _build_category_marks(classification_opts)
    except Exception as exc:
        result["errors"].append(str(exc))
        return result

    result["marks"]["category_marks"] = category_marks
    result["marks"]["mark_to_classid"] = _build_mark_to_classid(category_marks)

    if not _to_bool(classification_opts.get("enabled", "0"), default=False):
        result["success"] = True
        result["skipped"] = "classification disabled"
        return result

    conflicts = detect_rule_conflicts(
        [{"name": item.get("name", ""), "options": item.get("options", {})} for item in class_rules]
    )
    result["details"]["rule_conflicts"] = conflicts
    for conflict in conflicts:
        if conflict.get("severity") == "error":
            result["errors"].append(conflict.get("message", "class_rule conflict"))
        else:
            result["warnings"].append(conflict.get("message", "class_rule overlap"))
    if result["errors"]:
        return result

    raw_rules, rule_errors = _prepare_raw_rules(class_rules, category_marks)
    if rule_errors:
        result["errors"].extend(rule_errors)
        return result

    try:
        normalized_rules = firewall_manager.normalize_rules(raw_rules, category_marks)
    except Exception as exc:
        result["errors"].append(f"failed to normalize firewall rules: {exc}")
        return result

    result["rules_count"] = len(normalized_rules)

    fw_result = firewall_manager.apply_rules(normalized_rules, preferred_backend=configured_backend)
    result["details"]["firewall_applied"] = True
    result["backend"] = fw_result.get("backend", "")
    result["details"]["firewall"] = fw_result.get("details", {})
    if fw_result.get("warning"):
        result["warnings"].append(fw_result.get("warning"))
    if not fw_result.get("success"):
        result["errors"].append(f"firewall apply failed: {fw_result.get('error', 'unknown error')}")
        return result

    try:
        tc_plan = _build_tc_plan(settings)
    except Exception as exc:
        result["errors"].append(str(exc))
        return result

    fw_map = _build_fw_map(category_marks)
    tc = TCManager(settings)

    if not tc.apply_classes(tc_plan):
        result["errors"].append("tc apply_classes failed")
        result["details"]["tc"] = dict(tc.last_error_details or {})
        return result

    if not tc.apply_fwmark_filters(fw_map):
        result["errors"].append("tc apply_fwmark_filters failed")
        result["details"]["tc"] = dict(tc.last_error_details or {})
        return result

    result["details"]["plan"] = tc_plan
    result["details"]["fw_map"] = fw_map
    result["success"] = True
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default=None)
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    if args.debug:
        logging.basicConfig(level=logging.DEBUG, format="%(asctime)s %(name)s %(levelname)s %(message)s")

    result = run_classifier(config_path=args.config)
    print(json.dumps(result, ensure_ascii=False))
    raise SystemExit(0 if result.get("success") else 1)


if __name__ == "__main__":
    main()
