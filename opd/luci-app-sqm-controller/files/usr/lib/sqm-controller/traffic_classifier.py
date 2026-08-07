#!/usr/bin/env python3
"""流量分类主模块。

负责三件事：
1. 汇总系统规则、用户规则和 DNS 映射结果；
2. 为连接生成分类结论和 fwmark；
3. 维护分类器所依赖的 tc class 与过滤规则。

策略模式判断由独立调度模块完成，这里只关注“这条流量应该落到哪一类”。
"""
import argparse
import json
import logging
import os
import re
import time

from config_manager import ConfigManager, detect_rule_conflicts
import firewall_manager
import dns_mapper
import adaptive_allocator
from tc_manager import TCManager
from unknown_flow_logger import append_unknown_flow, tail_unknown_flows, DEFAULT_LOG_FILE


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
    "IPv4 download classification is enabled; "
    "IPv6 download classification requires setup_htb() redirect enhancement."
)
PREFERRED_CONFIG_PATH = "/etc/config/sqm_controller"
FALLBACK_CONFIG_PATH = "/etc/config/sqm-controller"

MODULE = "traffic_classifier"
VERSION = "4.0"
ACTIVE = True
OFFICIAL_CLASSES = ("gaming", "streaming", "bulk", "other")


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


def _build_tc_plan(settings, policy_settings=None):
    # 分类器需要先把 upload/download 的基础 class 树准备好，
    # 这里生成的是服务启动和重建时使用的稳态初始配比。
    upload_kbps = _to_int(settings.get("upload_speed", settings.get("upload_bandwidth", 0)), 0)
    download_kbps = _to_int(settings.get("download_speed", settings.get("download_bandwidth", 0)), 0)
    if upload_kbps <= 0 or download_kbps <= 0:
        raise ValueError("upload_speed/download_speed must be > 0 for classifier apply")

    qdisc = str(settings.get("queue_algorithm", "fq_codel")).strip().lower()
    if qdisc not in ("fq_codel", "cake"):
        qdisc = "fq_codel"

    def rate(total, pct):
        return max(1, int(round(total * pct / 100.0)))

    policy = policy_settings if isinstance(policy_settings, dict) else {}
    mode = str(policy.get("mode") or policy.get("product_mode") or "balanced").strip().lower()
    allocation = adaptive_allocator.allocate(
        mode=mode,
        congestion="normal",
        class_pct=None,
        unknown_pct=0,
        policy_config=policy,
    )

    def item(category, direction):
        values = allocation.get(category, {}) if isinstance(allocation, dict) else {}
        rate_pct = _to_int(values.get("rate_pct", 0), 0)
        ceil_pct = _to_int(values.get("ceil_pct", rate_pct), rate_pct)
        total = upload_kbps if direction == "upload" else download_kbps
        return rate(total, rate_pct), max(rate(total, rate_pct), rate(total, ceil_pct))

    g_up_rate, g_up_ceil = item("gaming", "upload")
    s_up_rate, s_up_ceil = item("streaming", "upload")
    b_up_rate, b_up_ceil = item("bulk", "upload")
    g_down_rate, g_down_ceil = item("gaming", "download")
    s_down_rate, s_down_ceil = item("streaming", "download")
    b_down_rate, b_down_ceil = item("bulk", "download")

    return {
        "upload_classes": [
            {"classid": "1:11", "rate_kbps": g_up_rate, "ceil_kbps": g_up_ceil, "prio": 10, "qdisc": qdisc},
            {"classid": "1:12", "rate_kbps": s_up_rate, "ceil_kbps": s_up_ceil, "prio": 20, "qdisc": qdisc},
            {"classid": "1:13", "rate_kbps": b_up_rate, "ceil_kbps": b_up_ceil, "prio": 30, "qdisc": qdisc},
        ],
        "download_classes": [
            {
                "classid": "2:21",
                "rate_kbps": g_down_rate,
                "ceil_kbps": g_down_ceil,
                "prio": 10,
                "qdisc": qdisc,
            },
            {
                "classid": "2:22",
                "rate_kbps": s_down_rate,
                "ceil_kbps": s_down_ceil,
                "prio": 20,
                "qdisc": qdisc,
            },
            {
                "classid": "2:23",
                "rate_kbps": b_down_rate,
                "ceil_kbps": b_down_ceil,
                "prio": 30,
                "qdisc": qdisc,
            },
        ],
        "metadata": {
            "source": "adaptive_allocator",
            "mode": mode,
            "allocation": allocation,
            "managed_classes": ("gaming", "streaming", "bulk"),
            "default_class": "other",
        },
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
                "dst_ip": dst_ip,
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
                "dst_ip": item.get("dst_ip", ""),
                "priority": item["priority"],
                "category": item["category"],
                "mark": item["mark"],
            }
        )
    return raw_rules, errors


def _build_dns_ip_rules(category_marks, min_confidence=0.60, limit=1000):
    rules = []
    for item in dns_mapper.get_active_mappings(min_confidence=min_confidence, limit=limit):
        category = item.get("class", "")
        if category not in category_marks:
            continue
        remote_ip = str(item.get("ip", "")).strip()
        if not remote_ip:
            continue
        base = {
            "proto": "all",
            "ports": "",
            "sport": "",
            "priority": 500,
            "category": category,
            "mark": category_marks[category],
            "source": "dns",
            "domain": item.get("domain", ""),
            "pattern": item.get("pattern", ""),
            "confidence": item.get("confidence", 0.0),
        }
        # 在 prerouting 阶段，上传流量看到的是远端 daddr，
        # 下载流量看到的是远端 saddr，因此这里补齐双向规则，
        # 让 DNS 线索也能覆盖主要的下行流量。
        outbound = dict(base)
        outbound.update({"ip": "", "dst_ip": remote_ip, "direction": "outbound"})
        inbound = dict(base)
        inbound.update({"ip": remote_ip, "dst_ip": "", "direction": "inbound"})
        rules.extend([outbound, inbound])
    return rules


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
    # 服务启用、手动重建和规则变更后，都会从这里刷新整套分类器状态。
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
    adaptive_settings = cfg.get_adaptive_settings()
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
    result["details"]["adaptive_policy"] = adaptive_settings

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
        dns_refresh = dns_mapper.refresh()
    except Exception as exc:
        dns_refresh = {"success": False, "error": str(exc), "entries": 0}
    result["details"]["dns_refresh"] = dns_refresh
    if not dns_refresh.get("success"):
        result["warnings"].append(
            "DNS dynamic classification unavailable: {}".format(
                dns_refresh.get("error", "dns refresh failed")
            )
        )
    dns_rules = _build_dns_ip_rules(category_marks)
    result["details"]["dns_dynamic_rules"] = len(dns_rules)
    raw_rules = dns_rules + raw_rules

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

    fw_map = _build_fw_map(category_marks)
    try:
        tc_plan = _build_tc_plan(settings, adaptive_settings)
    except Exception as exc:
        result["errors"].append(f"failed to build tc classifier plan: {exc}")
        result["details"]["tc_plan_error"] = str(exc)
        return result
    result["details"]["tc_plan_metadata"] = tc_plan.get("metadata", {})

    tc = TCManager(settings)
    tc_state = tc.inspect_runtime_state(classification_enabled=True)
    result["details"]["tc_before"] = {
        "upload_class_queues_present": tc_state.get("upload_class_queues_present", False),
        "download_class_queues_present": tc_state.get("download_class_queues_present", False),
        "classifier_tc_complete": tc_state.get("classifier_tc_complete", False),
    }

    if not tc_state.get("classifier_tc_complete", False):
        if not tc.apply_classes(tc_plan):
            result["errors"].append("tc apply_classes failed")
            result["details"]["tc"] = dict(tc.last_error_details or {})
            return result
        result["warnings"].append("tc classifier classes were missing; created classifier class queues")

    if not tc.apply_fwmark_filters(fw_map):
        if tc.setup_htb():
            result["warnings"].append("tc base tree was missing; setup_htb initialized default classes")
            if not tc.apply_classes(tc_plan):
                result["errors"].append("tc apply_classes failed after setup_htb")
                result["details"]["tc"] = dict(tc.last_error_details or {})
                return result
            if not tc.apply_fwmark_filters(fw_map):
                result["errors"].append("tc apply_fwmark_filters failed")
                result["details"]["tc"] = dict(tc.last_error_details or {})
                return result
        else:
            result["errors"].append("tc base tree missing and setup_htb failed")
            result["details"]["tc"] = dict(tc.last_error_details or {})
            return result

    result["details"]["fw_map"] = fw_map
    result["details"]["tc_rate_owner"] = "adaptive_policy"
    result["success"] = True
    return result



DIAGNOSTIC_STATES = ("unknown",)
CONNTRACK_FILE = "/proc/net/nf_conntrack"
STATE_FILE = "/tmp/sqm_unknown_conntrack_state.json"
STATE_TTL_SEC = 300

# 0x00 = 未标记，进入 unknown 诊断日志。
# 0x10 = 已分类为 other，不再计入 unknown 指标，避免策略误判分类质量。
DIAGNOSTIC_MARKS = {0x00}
OTHER_MARKS = {0x10}
CONTROL_PLANE_PORTS = {
    22,    # SSH
    53,    # DNS
    67, 68,  # DHCP
    123,   # NTP
}

# 端口启发式规则 (类别 -> {proto: {port_range: confidence}})
# 规则仅用于诊断统计，不修改 nftables/tc 规则。DNS 域名匹配优先级最高。
PORT_HEURISTICS = {
    "gaming": {
        "udp": {
            frozenset([(27000, 27250)]): 0.90,  # Steam P2P (官方范围)
            frozenset([(3074, 3074)]): 0.85,      # Xbox Live
            frozenset([(3478, 3481)]): 0.75,       # Steam/PSN/Zoom/Teams/STUN 共享
            frozenset([(3659, 3659)]): 0.80,       # EA 游戏
            frozenset([(4379, 4380)]): 0.85,       # Steam 备用
            frozenset([(88, 88)]): 0.80,            # Xbox 认证
            frozenset([(500, 500)]): 0.70,           # Xbox IPsec NAT-T
            frozenset([(3544, 3544)]): 0.75,         # Xbox Teredo
            frozenset([(4500, 4500)]): 0.70,         # Xbox IPsec NAT-T
            frozenset([(7777, 7788)]): 0.85,         # Unreal Engine 通用
            frozenset([(9987, 9987)]): 0.88,         # TeamSpeak 3
            frozenset([(19132, 19133)]): 0.88,       # Minecraft Bedrock
            frozenset([(14000, 14050)]): 0.75,       # 多种游戏
            frozenset([(8801, 8810)]): 0.85,         # Zoom 媒体流 (低时延)
            frozenset([(5000, 5500)]): 0.40,         # 降级，太宽泛
        },
        "tcp": {
            frozenset([(3074, 3074)]): 0.80,         # Xbox Live TCP
            frozenset([(3478, 3481)]): 0.65,         # PSN/Teams 辅助
            frozenset([(25565, 25565)]): 0.88,       # Minecraft Java
            frozenset([(3724, 3724)]): 0.80,         # WoW 登录
            frozenset([(5223, 5223)]): 0.65,         # PSN
            frozenset([(6112, 6114)]): 0.82,         # Blizzard 游戏
        },
    },
    "streaming": {
        "tcp": {
            frozenset([(1935, 1935)]): 0.85,         # RTMP
            frozenset([(554, 554)]): 0.85,           # RTSP
            frozenset([(8554, 8554)]): 0.85,         # RTSP alternate
            frozenset([(1755, 1755)]): 0.50,         # MMS (老式)
            frozenset([(8000, 8001)]): 0.80,         # Shoutcast/Icecast
        },
        "udp": {
            frozenset([(443, 443)]): 0.55,            # QUIC 弱规则，需行为配合
            frozenset([(1935, 1935)]): 0.80,          # RTMP
            frozenset([(554, 554)]): 0.80,            # RTSP
            frozenset([(8554, 8554)]): 0.80,          # RTSP alternate
            frozenset([(1755, 1755)]): 0.45,          # MMS (老式)
            frozenset([(5004, 5005)]): 0.75,          # RTP/RTCP
        },
    },
    "bulk": {
        "tcp": {
            frozenset([(6881, 6999)]): 0.90,          # BitTorrent
            frozenset([(51413, 51413)]): 0.85,        # Transmission DHT
            frozenset([(20, 21)]): 0.82,              # FTP
        },
        "udp": {
            frozenset([(6881, 6999)]): 0.85,          # BitTorrent DHT
            frozenset([(51413, 51413)]): 0.70,        # Transmission DHT
        },
    },
}


def _parse_conntrack_line(line):
    """解析 /proc/net/nf_conntrack 中的一行。"""
    parts = line.strip().split()
    if len(parts) < 10:
        return None

    entry = {"raw": line.strip()}
    # parts[0]=协议族, parts[1]=协议号, parts[2]=L4协议, parts[3]=超时, parts[4]=状态
    entry["proto"] = parts[2].lower()
    entry["state"] = parts[4] if len(parts) > 4 else ""

    for part in parts:
        for prefix, key in [
            ("src=", "src"), ("dst=", "dst"), ("sport=", "sport"),
            ("dport=", "dport"), ("packets=", "packets"), ("bytes=", "bytes"),
        ]:
            if part.startswith(prefix):
                entry[key] = part[len(prefix):]

        if part.startswith("mark="):
            try:
                entry["mark"] = int(part[len("mark="):])
            except ValueError:
                entry["mark"] = 0

        if part == "[ASSURED]":
            entry["assured"] = True

    try:
        entry["packets"] = int(entry.get("packets", 0))
    except (ValueError, TypeError):
        entry["packets"] = 0
    try:
        entry["bytes"] = int(entry.get("bytes", 0))
    except (ValueError, TypeError):
        entry["bytes"] = 0
    try:
        entry["dport"] = int(entry.get("dport", 0))
    except (ValueError, TypeError):
        entry["dport"] = 0
    try:
        entry["sport"] = int(entry.get("sport", 0))
    except (ValueError, TypeError):
        entry["sport"] = 0

    entry.setdefault("mark", 0)
    entry.setdefault("src", "")
    entry.setdefault("dst", "")
    entry.setdefault("assured", False)
    return entry


def _port_in_ranges(port, ranges):
    for lo, hi in ranges:
        if lo <= port <= hi:
            return True
    return False


def _guess_by_port(proto, dport):
    """基于端口和协议猜测业务类型。"""
    best_class = "unknown"
    best_confidence = 0.0
    best_rule = ""

    for category, proto_rules in PORT_HEURISTICS.items():
        rules = proto_rules.get(proto, {})
        for port_set, confidence in rules.items():
            if _port_in_ranges(dport, set(port_set)):
                if confidence > best_confidence:
                    best_confidence = confidence
                    best_class = category
                    best_rule = f"{proto}:{dport} in {list(port_set)[0][0]}-{list(port_set)[0][1]}"

    return best_class, best_confidence, best_rule


def _guess_by_behavior(entry):
    """基于连接行为补充猜测（置信度较低的弱规则，配合端口启发式使用）。
    约束条件说明（避免误判）：
      - UDP gaming:  pkt>50 + avg<150B + bytes<100KB，仅 0.40 弱猜测
      - UDP bulk:    avg_size>800 排除 VoIP/小包游戏
      - TCP bulk:    >5MB (443) / >2MB (80) 排除普通网页/视频
    所有线索的置信度 ≤0.55，低于 DNS 匹配 (≥0.80) 和端口强规则 (≥0.80)。
    """
    proto = entry.get("proto", "")
    dport = entry.get("dport", 0)
    pkt_count = entry.get("packets", 0)
    byte_count = entry.get("bytes", 0)
    clues = []

    if pkt_count <= 0:
        return clues

    avg_size = byte_count / pkt_count

    # -- UDP 行为 --
    if proto == "udp":
        # 小包高频且总量不大时，更像低时延交互。
        # pkt>50 用来过滤 DNS、STUN 和心跳，bytes<100KB 用来排除大块传输。
        # 这里只给弱线索，真正的游戏判定仍主要依赖端口强规则。
        if pkt_count > 50 and avg_size < 150 and dport >= 1024 and byte_count < 100000:
            clues.append(("gaming", 0.40, "udp small packets high frequency"))
        # QUIC 持续大包时，更像流媒体。
        elif dport == 443 and avg_size > 800:
            clues.append(("streaming", 0.45, "udp large packets sustained"))
        # 吞吐高且包大时，更像批量传输。
        if byte_count > 500000 and avg_size > 800 and dport >= 1024:
            clues.append(("bulk", 0.40, "udp high throughput"))

    # TCP 行为
    if proto == "tcp":
        if dport in (443, 8443):
            # 大流量下载更偏向批量传输。
            if byte_count > 5000000:
                clues.append(("bulk", 0.55, "tcp443 large payload download"))
            # 中等规模但持续的传输，更像流媒体。
            elif avg_size > 800:
                clues.append(("streaming", 0.45, "tcp443 medium payload"))
        elif dport == 80:
            # tcp/80 只做很保守的大下载判断。
            if byte_count > 2000000:
                clues.append(("bulk", 0.50, "tcp80 large download"))

    return clues


def _is_control_plane_flow(entry):
    """跳过路由器本机控制面流量，避免 DNS/SSH 等污染 unknown 诊断。
    这类流量常见于 LuCI/SSH 调试和 dnsmasq 回复，通常不会进入用户业务
    分类队列，也不应该作为策略调度的 unknown 信号。
    """
    proto = entry.get("proto", "")
    sport = entry.get("sport", 0)
    dport = entry.get("dport", 0)
    if proto in ("tcp", "udp") and (sport in CONTROL_PLANE_PORTS or dport in CONTROL_PLANE_PORTS):
        return True
    return False


# 各分类来源的基准权重（用于多源证据加权组合）
SOURCE_WEIGHTS = {
    "dns": 1.00,       # DNS 域名匹配，语义最强
    "port": 0.85,      # 端口启发式，中等可靠
    "behavior": 0.70,  # 行为弱判断，低置信度补充
}
MULTI_SOURCE_BONUS = 0.10   # 每个额外一致来源的加分
MAX_MULTI_SOURCE_BONUS = 0.20  # 多源加分上限


def classify_flow(entry):
    """对单条 conntrack 流做诊断分类。
    多源证据加权组合：
      - DNS 不再使用 0.80 硬截断，而是与端口、行为做置信度加权比较
      - 多个来源指向同一类别时，叠加组合置信度
      - DNS 权重最高 (1.00)，端口中等 (0.85)，行为最低 (0.70)
    """
    # 判定顺序是“已有 mark 优先”，随后再看 DNS、端口和行为证据。
    if not isinstance(entry, dict):
        return build_result(category="unknown", confidence=0.0, reason=["invalid input"], mark="")

    proto = entry.get("proto", "")
    dport = entry.get("dport", 0)
    mark = entry.get("mark", 0)
    mark_hex = f"0x{mark:02x}"
    dst = entry.get("dst", "")

    if _is_control_plane_flow(entry):
        return build_result(category="unknown", confidence=0.0,
                            reason=["control plane flow ignored"], mark=mark_hex)

    # 已正确标记的流不需要诊断
    mark_to_class = {0x10: "other", 0x11: "gaming", 0x12: "streaming", 0x13: "bulk"}
    current_class = mark_to_class.get(mark, "other" if mark == 0 else "unknown")
    if current_class in OFFICIAL_CLASSES and current_class != "other":
        return build_result(category=current_class, confidence=0.95,
                            reason=[f"nftables mark {mark_hex}"], mark=mark_hex)

    # 先看 DNS 关联结果
    dns_class, dns_conf, dns_reason = dns_mapper.lookup_class(dst)

    # 再看端口启发式
    port_class, port_conf, port_rule = _guess_by_port(proto, dport)

    # 最后补一层行为弱判断
    behavior_clues = _guess_by_behavior(entry)

    # --- 多源证据加权组合 ---
    # candidates 里汇总每个类别来自 DNS、端口和行为的证据。
    candidates = {}

    def _add_evidence(cls, source, conf, reason):
        if not cls or conf <= 0:
            return
        if cls not in candidates:
            candidates[cls] = {"dns": 0.0, "port": 0.0, "behavior": 0.0, "reasons": []}
        weight = SOURCE_WEIGHTS.get(source, 0.70)
        weighted = conf * weight
        # 同一来源只保留最高置信度
        if weighted > candidates[cls][source]:
            candidates[cls][source] = weighted
        if reason and reason not in candidates[cls]["reasons"]:
            candidates[cls]["reasons"].append(reason)

    # 先收集 DNS 证据，不再加硬截断阈值。
    if dns_class and dns_conf > 0:
        _add_evidence(dns_class, "dns", dns_conf, dns_reason)

    # 收集端口证据
    if port_class and port_conf > 0:
        _add_evidence(port_class, "port", port_conf, port_rule if port_rule else None)

    # 收集行为证据
    for b_class, b_conf, b_reason in behavior_clues:
        _add_evidence(b_class, "behavior", b_conf, b_reason)

    # 计算每个候选类别的组合置信度
    best_class = "unknown"
    best_conf = 0.0
    best_reasons = []

    for cls, scores in candidates.items():
        # 取最强来源为基础
        base = max(scores["dns"], scores["port"], scores["behavior"])
        # 统计有几个独立来源指向同一类别
        sources_count = sum(1 for s in [scores["dns"], scores["port"], scores["behavior"]] if s > 0)
        # 多源加分：第二个来源起每个加 MULTI_SOURCE_BONUS
        bonus = min(MAX_MULTI_SOURCE_BONUS, max(0, sources_count - 1) * MULTI_SOURCE_BONUS)
        combined = min(1.0, base + bonus)

        if combined > best_conf or (combined == best_conf and cls == dns_class):
            best_conf = combined
            best_class = cls
            best_reasons = list(scores["reasons"])

    if not best_reasons:
        best_reasons.append("no heuristic matched")

    return build_result(
        category=best_class,
        confidence=best_conf,
        reason=best_reasons,
        mark=mark_hex,
    )


def build_result(category="unknown", confidence=0.0, reason=None, mark=""):
    normalized_class = str(category or "unknown").strip().lower()
    if normalized_class not in OFFICIAL_CLASSES and normalized_class not in DIAGNOSTIC_STATES:
        normalized_class = "unknown"

    try:
        confidence = max(0.0, min(float(confidence), 1.0))
    except (ValueError, TypeError):
        confidence = 0.0

    if reason is None:
        reason = []
    elif isinstance(reason, str):
        reason = [reason]
    elif isinstance(reason, tuple):
        reason = list(reason)

    return {
        "class": normalized_class,
        "confidence": round(confidence, 2),
        "reason": [str(r) for r in reason],
        "mark": str(mark or ""),
        "official_class": normalized_class in OFFICIAL_CLASSES,
    }


def _flow_key(entry):
    return "|".join([
        str(entry.get("proto", "")),
        str(entry.get("src", "")),
        str(entry.get("sport", 0)),
        str(entry.get("dst", "")),
        str(entry.get("dport", 0)),
        str(entry.get("mark", 0)),
    ])


def _load_scan_state(path=STATE_FILE):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _save_scan_state(state, path=STATE_FILE):
    try:
        directory = os.path.dirname(path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        tmp_path = path + ".tmp"
        with open(tmp_path, "w", encoding="utf-8") as fh:
            json.dump(state, fh, ensure_ascii=False)
        os.replace(tmp_path, path)
        return True
    except Exception:
        return False


def _delta_bytes_for_entry(entry, state, now_ts, min_bytes):
    key = _flow_key(entry)
    current_bytes = max(0, int(entry.get("bytes", 0)))
    previous = state.get(key, {}) if isinstance(state.get(key), dict) else {}
    previous_bytes = max(0, int(previous.get("bytes", 0) or 0))

    if current_bytes < previous_bytes:
        delta = current_bytes
    elif previous_bytes <= 0:
        delta = current_bytes
    else:
        delta = current_bytes - previous_bytes

    state[key] = {"bytes": current_bytes, "time": now_ts}
    if delta < min_bytes:
        return 0
    return delta


def _prune_scan_state(state, now_ts, ttl_sec=STATE_TTL_SEC):
    cutoff = now_ts - max(60, int(ttl_sec or STATE_TTL_SEC))
    pruned = {}
    for key, item in state.items():
        if not isinstance(item, dict):
            continue
        try:
            item_time = int(item.get("time", 0))
        except (ValueError, TypeError):
            item_time = 0
        if item_time >= cutoff:
            pruned[key] = item
    return pruned


def scan_conntrack(path=CONNTRACK_FILE, log_path=None, min_bytes=4096,
                   state_path=STATE_FILE, record=True, include_other=False):
    """扫描 conntrack，对 mark=0 的未分类流做诊断并记录。
    include_other=True 时可临时诊断 mark=0x10 的 other 流，但默认不记录，
    避免已分类 other 被 unknown_pct 重复统计。
    """
    # 这里侧重“补规则”和“解释为什么没命中”，不是在线实时分类。
    if log_path is None:
        log_path = DEFAULT_LOG_FILE

    if not os.path.exists(path):
        return {"success": False, "error": f"conntrack file not found: {path}"}

    now_ts = int(time.time())
    scan_state = _prune_scan_state(_load_scan_state(state_path), now_ts)
    min_bytes = max(0, int(min_bytes or 0))
    diagnostic_marks = set(DIAGNOSTIC_MARKS)
    if include_other:
        diagnostic_marks.update(OTHER_MARKS)
    stats = {
        "total_flows": 0,
        "classified_correctly": 0,
        "diagnosed": 0,
        "logged": 0,
        "skipped_delta": 0,
        "skipped_control": 0,
        "other_mark_flows": 0,
        "errors": 0,
        "by_guess": {},
        "time": now_ts,
    }

    try:
        fh = open(path, "r", encoding="utf-8")
    except Exception as exc:
        return {"success": False, "error": str(exc)}

    try:
        for line in fh:
            line = line.strip()
            if not line or "src=" not in line:
                continue

            entry = _parse_conntrack_line(line)
            if entry is None:
                continue

            stats["total_flows"] += 1
            mark = entry.get("mark", 0)

            if mark in OTHER_MARKS and not include_other:
                stats["other_mark_flows"] += 1
                stats["classified_correctly"] += 1
                continue

            if mark not in diagnostic_marks:
                stats["classified_correctly"] += 1
                continue

            if entry.get("bytes", 0) < min_bytes:
                continue

            if _is_control_plane_flow(entry):
                stats["skipped_control"] += 1
                continue

            delta_bytes = _delta_bytes_for_entry(entry, scan_state, now_ts, min_bytes)
            if delta_bytes <= 0:
                stats["skipped_delta"] += 1
                continue

            result = classify_flow(entry)
            guess = result.get("class", "other")
            stats["by_guess"][guess] = stats["by_guess"].get(guess, 0) + 1
            stats["diagnosed"] += 1

            flow_record = {
                "time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now_ts)),
                "src": entry.get("src", ""),
                "dst": entry.get("dst", ""),
                "proto": entry.get("proto", ""),
                "sport": entry.get("sport", 0),
                "dport": entry.get("dport", 0),
                "bytes": delta_bytes,
                "packets": entry.get("packets", 0),
                "ct_mark": f"0x{mark:02x}",
                "guess": guess,
                "confidence": result.get("confidence", 0.0),
                "reason": ", ".join(result.get("reason", [])),
            }

            if record:
                append_result = append_unknown_flow(flow_record, path=log_path)
                if append_result.get("success"):
                    stats["logged"] += 1
                else:
                    stats["errors"] += 1

    finally:
        fh.close()

    if not _save_scan_state(scan_state, state_path):
        stats["errors"] += 1
        stats["state_error"] = "failed to save scan state"

    try:
        # 持久化本次 scan_conntrack 触发的 DNS lookup hits/misses，
        # 避免短生命周期 CLI 进程退出后统计回到旧值。
        dns_mapper.save()
    except Exception as exc:
        stats["errors"] += 1
        stats["dns_stats_error"] = str(exc)

    stats["success"] = True
    return stats


def self_test():
    sample_entry = {"proto": "udp", "dport": 27015, "sport": 52000, "mark": 0,
                    "src": "192.168.1.100", "dst": "203.0.113.50",
                    "packets": 150, "bytes": 32000}
    result = classify_flow(sample_entry)
    return {
        "ok": True,
        "module": MODULE,
        "version": VERSION,
        "active": ACTIVE,
        "time": int(time.time()),
        "official_classes": list(OFFICIAL_CLASSES),
        "diagnostic_states": list(DIAGNOSTIC_STATES),
        "conntrack_file": CONNTRACK_FILE,
        "sample": result,
    }

def main():
    parser = argparse.ArgumentParser(description="SQM Controller traffic classifier")
    parser.add_argument("--config", default=None)
    parser.add_argument("--debug", action="store_true")
    parser.add_argument("--diag", action="store_true", help="扫描 conntrack 诊断未识别流量")
    parser.add_argument("--tail", type=int, default=0, help="查看最近 N 条 unknown 流量记录")
    parser.add_argument("--self-test", action="store_true", help="运行分类诊断自检")
    parser.add_argument("--min-bytes", type=int, default=4096, help="诊断的最小字节阈值")
    args = parser.parse_args()

    if args.debug:
        logging.basicConfig(level=logging.DEBUG, format="%(asctime)s %(name)s %(levelname)s %(message)s")

    if args.diag:
        result = scan_conntrack(min_bytes=args.min_bytes)
        print(json.dumps(result, ensure_ascii=False))
        raise SystemExit(0 if result.get("success") else 1)

    if args.tail > 0:
        result = tail_unknown_flows(limit=args.tail)
        print(json.dumps(result, ensure_ascii=False))
        raise SystemExit(0 if result.get("success", True) else 1)

    if args.self_test:
        print(json.dumps(self_test(), ensure_ascii=False))
        raise SystemExit(0)

    result = run_classifier(config_path=args.config)
    print(json.dumps(result, ensure_ascii=False))
    raise SystemExit(0 if result.get("success") else 1)


if __name__ == "__main__":
    main()
