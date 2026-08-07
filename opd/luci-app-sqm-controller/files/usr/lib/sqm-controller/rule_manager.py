#!/usr/bin/env python3
"""SQM Controller 分类规则管理器。

读取 UCI 和用户自定义规则的优先级合并规则集，校验规则合法性。
第一阶段不生成 nftables/tc 规则，只做规则管理和 dry-run。
"""
import json
import os
import re
import time

MODULE = "rule_manager"
VERSION = "4.0"
ACTIVE = True
VALID_CLASSES = {"gaming", "streaming", "bulk", "other"}
VALID_PROTO = {"tcp", "udp", "all", "any", ""}
REQUIRED_FIELDS = ("name", "class", "proto", "priority", "enabled")

DEFAULT_CONFIG_PATH = "/etc/config/sqm_controller"
USER_RULES_FILE = "/etc/sqm_controller/user_rules.json"
LEGACY_USER_RULES_FILE = "/etc/sqm_controller/" + "v" + "4_user_rules.json"

# 系统默认规则（优先级最低的兜底规则）
SYSTEM_DEFAULT_RULES = [
    {"name": "default_other", "class": "other", "proto": "all", "priority": 0,
     "enabled": True, "source": "system", "dport": "", "sport": "",
     "src_ip": "", "dst_ip": ""},
]


def _to_bool(value, default=True):
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    text = str(value).strip().lower()
    if text in ("1", "true", "yes", "on", "enabled"):
        return True
    if text in ("0", "false", "no", "off", "disabled"):
        return False
    return default


def _normalize_proto(value):
    proto = str(value or "any").strip().lower()
    if proto in ("", "any", "*"):
        return "all"
    if proto in ("tcp", "udp", "all"):
        return proto
    return proto


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
    """解析 UCI 配置文件，返回 section 列表。"""
    sections = []
    current = None
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for raw in fh:
                line = _strip_inline_comment(raw.rstrip("\n").rstrip("\r"))
                if not line:
                    continue
                m = re.match(r"^\s*config\s+([A-Za-z0-9_]+)(?:\s+(.+))?$", line)
                if m:
                    current = {
                        "type": m.group(1),
                        "name": _unquote(m.group(2) or ""),
                        "options": {},
                    }
                    sections.append(current)
                    continue
                m = re.match(r"^\s*option\s+([A-Za-z0-9_]+)\s+(.+)$", line)
                if m and current is not None:
                    current["options"][m.group(1)] = _unquote(m.group(2))
    except FileNotFoundError:
        pass
    except Exception:
        pass
    return sections


def validate_rule(rule):
    """校验单条规则，返回 {valid, errors, rule}。"""
    errors = []
    normalized = {}
    if not isinstance(rule, dict):
        return {"valid": False, "errors": ["rule must be dict"], "rule": {}}

    for field in REQUIRED_FIELDS:
        if field not in rule:
            errors.append("missing field: %s" % field)

    name = str(rule.get("name", "")).strip()
    if not name:
        errors.append("name is empty")
    normalized["name"] = name

    category = str(rule.get("class", rule.get("category", ""))).strip().lower()
    if category not in VALID_CLASSES:
        errors.append("unsupported class: %s" % category)
    normalized["class"] = category

    proto = _normalize_proto(rule.get("proto", "any"))
    if proto not in VALID_PROTO:
        errors.append("unsupported proto: %s" % proto)
    normalized["proto"] = proto

    normalized["src_ip"] = str(rule.get("src_ip", "")).strip()
    normalized["dst_ip"] = str(rule.get("dst_ip", "")).strip()
    normalized["sport"] = str(rule.get("sport", rule.get("sport", ""))).strip()
    normalized["dport"] = str(rule.get("dport", rule.get("dport", ""))).strip()

    try:
        normalized["priority"] = int(rule.get("priority", 0))
    except (ValueError, TypeError):
        errors.append("invalid priority: %s" % rule.get("priority"))
        normalized["priority"] = 0

    normalized["enabled"] = _to_bool(rule.get("enabled", True))
    normalized["source"] = str(rule.get("source", "user")).strip() or "user"

    return {"valid": len(errors) == 0, "errors": errors, "rule": normalized}


def load_uci_rules(config_path=None):
    """从 UCI 配置中加载 class_rule 条目，转换为规则格式。"""
    path = config_path or DEFAULT_CONFIG_PATH
    sections = _parse_uci_sections(path)
    rules = []
    for section in sections:
        if section.get("type") != "class_rule":
            continue
        opts = section.get("options", {})
        rules.append({
            "name": str(section.get("name") or opts.get("name") or "").strip(),
            "class": str(opts.get("category", "other")).strip().lower(),
            "proto": _normalize_proto(opts.get("proto", "any")),
            "dport": str(opts.get("dport", "")).strip(),
            "sport": str(opts.get("sport", "")).strip(),
            "src_ip": str(opts.get("src_ip", "")).strip(),
            "dst_ip": str(opts.get("dst_ip", "")).strip(),
            "priority": int(str(opts.get("priority", "0")).strip()) if opts.get("priority", "0").strip().lstrip("-").isdigit() else 0,
            "enabled": _to_bool(opts.get("enabled", "1")),
            "source": "uci",
        })
    return rules


def load_user_rules(path=None):
    """从 JSON 文件加载用户自定义规则。"""
    filepath = path or USER_RULES_FILE
    if path is None and not os.path.exists(filepath) and os.path.exists(LEGACY_USER_RULES_FILE):
        filepath = LEGACY_USER_RULES_FILE
    if not os.path.exists(filepath):
        return []
    try:
        with open(filepath, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if isinstance(data, list):
            return data
        return data.get("rules", []) if isinstance(data, dict) else []
    except Exception:
        return []


def save_user_rules(rules, path=None):
    """保存用户自定义规则到 JSON 文件。"""
    filepath = path or USER_RULES_FILE
    try:
        directory = os.path.dirname(filepath)
        if directory:
            os.makedirs(directory, exist_ok=True)
        tmp = filepath + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump({"rules": rules, "updated": int(time.time())}, fh, ensure_ascii=False, indent=2)
        os.replace(tmp, filepath)
        return True
    except Exception:
        return False


def merge_rules(uci_rules=None, user_rules=None, system_rules=None):
    """合并所有来源的规则：用户规则 > UCI 规则 > 系统默认规则。

    返回排序后的有效规则列表和校验错误列表。
    """
    all_rules = []
    errors = []

    if user_rules is None:
        user_rules = load_user_rules()
    if uci_rules is None:
        uci_rules = load_uci_rules()
    if system_rules is None:
        system_rules = SYSTEM_DEFAULT_RULES

    validated_names = set()
    for source_label, rules in [("user", user_rules), ("uci", uci_rules), ("system", system_rules)]:
        for raw_rule in rules or []:
            result = validate_rule(raw_rule)
            if not result["valid"]:
                errors.append({
                    "name": raw_rule.get("name", "?"),
                    "source": source_label,
                    "errors": result["errors"],
                })
                continue
            rule = result["rule"]
            if rule["name"] in validated_names:
                continue
            if not rule["enabled"]:
                continue
            rule["_source"] = source_label
            validated_names.add(rule["name"])
            all_rules.append(rule)

    # 按优先级降序排列，优先级相同时用户规则优先于 UCI
    source_order = {"user": 0, "uci": 1, "system": 2}
    all_rules.sort(key=lambda r: (-r["priority"], source_order.get(r.get("_source", "system"), 9)))

    # 清理内部字段
    for rule in all_rules:
        rule.pop("_source", None)

    return {"rules": all_rules, "errors": errors, "count": len(all_rules)}


def list_rules(config_path=None):
    """获取当前生效的规则集。"""
    uci_rules = load_uci_rules(config_path)
    user_rules = load_user_rules()
    return merge_rules(uci_rules=uci_rules, user_rules=user_rules)


def get_rule_summary(config_path=None):
    """返回规则集的摘要信息。"""
    result = list_rules(config_path)
    summary = {
        "total_rules": result["count"],
        "by_class": {},
        "by_source": {"uci": 0, "user": 0, "system": 0},
        "validation_errors": len(result["errors"]),
    }
    for rule in result["rules"]:
        cls = rule.get("class", "other")
        summary["by_class"][cls] = summary["by_class"].get(cls, 0) + 1
        src = rule.get("source", "system")
        if src in summary["by_source"]:
            summary["by_source"][src] += 1
    return {"summary": summary, "result": result}


def self_test():
    sample = merge_rules(
        uci_rules=[{
            "name": "sample_uci_rule",
            "class": "gaming",
            "proto": "udp",
            "dport": "27000-27200",
            "priority": 90,
            "enabled": True,
            "source": "uci",
        }],
        user_rules=[{
            "name": "sample_user_rule",
            "class": "gaming",
            "proto": "udp",
            "dport": "3074",
            "priority": 100,
            "enabled": True,
            "source": "user",
        }],
        system_rules=SYSTEM_DEFAULT_RULES,
    )
    return {
        "ok": True,
        "module": MODULE,
        "version": VERSION,
        "active": ACTIVE,
        "time": int(time.time()),
        "merged_count": sample["count"],
        "first_rule": sample["rules"][0] if sample["rules"] else None,
        "errors_count": len(sample["errors"]),
    }


def main():
    import argparse
    parser = argparse.ArgumentParser(description="SQM 规则管理器")
    parser.add_argument("--list", action="store_true", help="列出所有有效规则")
    parser.add_argument("--summary", action="store_true", help="规则摘要统计")
    parser.add_argument("--validate", action="store_true", help="校验所有规则并输出错误")
    parser.add_argument("--config", default=None, help="UCI 配置文件路径")
    parser.add_argument("--self-test", action="store_true", help="运行自检")
    args = parser.parse_args()

    if args.list:
        result = list_rules(args.config)
        print(json.dumps(result, ensure_ascii=False, indent=2))
    elif args.summary:
        result = get_rule_summary(args.config)
        print(json.dumps(result, ensure_ascii=False, indent=2))
    elif args.validate:
        result = list_rules(args.config)
        if result["errors"]:
            print(json.dumps({"valid": False, "errors": result["errors"]}, ensure_ascii=False, indent=2))
        else:
            print(json.dumps({"valid": True, "count": result["count"], "message": "all rules valid"}, ensure_ascii=False))
    elif args.self_test:
        print(json.dumps(self_test(), ensure_ascii=False))
    else:
        print(json.dumps(self_test(), ensure_ascii=False))


if __name__ == "__main__":
    main()
