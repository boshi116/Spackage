#!/usr/bin/env python3
import ipaddress
import logging
import os
import re


VALID_BACKENDS = {"nft", "iptables"}
VALID_CATEGORIES = {"other", "gaming", "streaming", "bulk"}
VALID_POLICY_MODES = {"auto", "balanced", "gaming", "streaming", "bulk"}
DEFAULT_POLICY_CRON = "*/1 * * * *"


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


def _to_python_value(value):
    value_str = str(value or "").strip()
    value_lower = value_str.lower()
    if value_lower in ("1", "true", "yes", "on"):
        return True
    if value_lower in ("0", "false", "no", "off"):
        return False
    if re.fullmatch(r"-?\d+", value_str):
        try:
            return int(value_str)
        except Exception:
            return value_str
    return value_str


def _value_to_string(value):
    if isinstance(value, bool):
        return "1" if value else "0"
    if isinstance(value, (int, float)):
        return str(value)
    return str(value)


def _parse_ports(value):
    text = str(value or "").strip()
    if not text:
        return []

    ranges = []
    for token in [item.strip() for item in text.split(",") if item.strip()]:
        if "-" in token:
            start_s, end_s = token.split("-", 1)
            try:
                start = int(start_s.strip(), 10)
                end = int(end_s.strip(), 10)
            except Exception:
                raise ValueError(f"invalid port range: {token}")
            if start < 1 or end < 1 or start > 65535 or end > 65535 or start > end:
                raise ValueError(f"invalid port range: {token}")
            ranges.append((start, end))
            continue

        try:
            port = int(token, 10)
        except Exception:
            raise ValueError(f"invalid port: {token}")
        if port < 1 or port > 65535:
            raise ValueError(f"invalid port: {token}")
        ranges.append((port, port))
    return ranges


def _ports_overlap(left, right):
    if not left or not right:
        return True
    for left_start, left_end in left:
        for right_start, right_end in right:
            if left_start <= right_end and right_start <= left_end:
                return True
    return False


def _proto_overlap(left, right):
    left_set = {"tcp", "udp"} if left == "all" else {left}
    right_set = {"tcp", "udp"} if right == "all" else {right}
    return bool(left_set & right_set)


def _parse_ip_value(value):
    text = str(value or "").strip()
    if not text:
        return None
    try:
        return ipaddress.ip_network(text, strict=False)
    except Exception:
        return None


def _src_ip_overlap(left, right):
    left_text = str(left or "").strip()
    right_text = str(right or "").strip()
    if not left_text or not right_text:
        return True
    if left_text == right_text:
        return True

    left_net = _parse_ip_value(left_text)
    right_net = _parse_ip_value(right_text)
    if left_net is None or right_net is None:
        return False
    if left_net.version != right_net.version:
        return False
    return left_net.overlaps(right_net)


def _validate_mark(value, field_name):
    text = str(value or "").strip().lower()
    if not text:
        raise ValueError(f"{field_name} is empty")
    try:
        mark_int = int(text, 16) if text.startswith("0x") else int(text, 10)
    except Exception:
        raise ValueError(f"{field_name} is invalid")
    if mark_int <= 0 or mark_int > 0xFFFFFFFF:
        raise ValueError(f"{field_name} out of range")
    return f"0x{mark_int:x}"


def _validate_cron_expression(expression):
    text = str(expression or "").strip()
    if not text:
        return None
    if "\n" in text or "\r" in text:
        return "policy cron must be a single line"
    parts = text.split()
    if len(parts) != 5:
        return "policy cron must contain 5 fields"
    allowed = re.compile(r"^[0-9*/,\-]+$")
    for idx, part in enumerate(parts, start=1):
        if not allowed.match(part):
            return f"policy cron field #{idx} contains unsupported characters"
    return None


class UCISectionManager:
    def __init__(self, config_path):
        self.config_path = config_path
        self.prefix = ""
        self.sections = []
        self.logger = logging.getLogger(__name__)

    def load(self):
        self.prefix = ""
        self.sections = []
        if not os.path.exists(self.config_path):
            return []

        with open(self.config_path, "r", encoding="utf-8") as file_handle:
            content = file_handle.read()

        return self.load_from_string(content)

    def load_from_string(self, content):
        self.prefix = ""
        self.sections = []
        current = None
        section_seen = False

        for lineno, raw in enumerate((content or "").splitlines(), start=1):
            line = _strip_inline_comment(raw.rstrip("\r"))
            if not line:
                if not section_seen:
                    if self.prefix:
                        self.prefix += "\n"
                    self.prefix += raw.rstrip("\r")
                continue

            config_match = re.match(r"^\s*config\s+([A-Za-z0-9_]+)(?:\s+(.+))?$", line)
            if config_match:
                section_seen = True
                current = {
                    "type": config_match.group(1),
                    "name": _unquote(config_match.group(2) or ""),
                    "options": {},
                    "order": len(self.sections),
                    "line": lineno,
                }
                self.sections.append(current)
                continue

            option_match = re.match(r"^\s*option\s+([A-Za-z0-9_]+)\s+(.+)$", line)
            if option_match and current is not None:
                current["options"][option_match.group(1)] = _unquote(option_match.group(2))

        self.prefix = self.prefix.rstrip()
        return self.sections

    def get_first(self, section_type, section_name=None):
        for section in self.sections:
            if section.get("type") != section_type:
                continue
            if section_name is not None and section.get("name") != section_name:
                continue
            return section
        return None

    def get_all(self, section_type):
        return [section for section in self.sections if section.get("type") == section_type]

    def set_first_options(self, section_type, section_name, options):
        section = self.get_first(section_type, section_name)
        if section is None:
            section = {
                "type": section_type,
                "name": section_name,
                "options": {},
                "order": len(self.sections),
                "line": 0,
            }
            self.sections.append(section)
        section["options"] = dict(options or {})
        return section

    def replace_sections(self, section_type, rendered_sections):
        kept = [section for section in self.sections if section.get("type") != section_type]
        next_sections = []
        for idx, item in enumerate(rendered_sections or []):
            next_sections.append(
                {
                    "type": section_type,
                    "name": str(item.get("name") or "").strip(),
                    "options": dict(item.get("options") or {}),
                    "order": 0,
                    "line": 0,
                }
            )
        self.sections = kept + next_sections
        for idx, section in enumerate(self.sections):
            section["order"] = idx

    def render(self):
        parts = []
        if self.prefix:
            parts.append(self.prefix)
        for section in self.sections:
            lines = [f"config {section['type']} '{section['name']}'"]
            for key, value in section.get("options", {}).items():
                lines.append(f"\toption {key} '{_value_to_string(value)}'")
            parts.append("\n".join(lines))
        return ("\n\n".join(part for part in parts if part)).rstrip() + "\n"

    def save(self):
        os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
        with open(self.config_path, "w", encoding="utf-8") as file_handle:
            file_handle.write(self.render())
        return True


class ConfigManager:
    DEFAULT_CONFIG_PATH = "/etc/config/sqm_controller"

    def __init__(self, config_path=None):
        self.config_path = config_path or self.DEFAULT_CONFIG_PATH
        self.section_manager = UCISectionManager(self.config_path)
        self.config = {}
        self.basic_config = {}
        self.advanced_config = {}
        self.classification = {}
        self.policy = {}
        self.class_rules = []
        self.logger = logging.getLogger(__name__)
        self.logger.debug("Config path: %s", self.config_path)

    def _refresh_views(self):
        self.basic_config = dict((self.section_manager.get_first("basic_config", "basic_config") or {}).get("options", {}))
        self.advanced_config = dict((self.section_manager.get_first("advanced_config", "advanced_config") or {}).get("options", {}))
        self.classification = dict((self.section_manager.get_first("classification", "classification") or {}).get("options", {}))
        self.policy = dict((self.section_manager.get_first("policy", "policy") or {}).get("options", {}))
        self.class_rules = [
            {"name": section.get("name", ""), "options": dict(section.get("options", {}))}
            for section in self.section_manager.get_all("class_rule")
        ]
        self.config = {**self.advanced_config, **self.basic_config}

    def load_config(self):
        try:
            self.section_manager.config_path = self.config_path
            self.section_manager.load()
            self._refresh_views()
            self.logger.info(
                "Config loaded: basic=%d advanced=%d classification=%d policy=%d class_rules=%d",
                len(self.basic_config),
                len(self.advanced_config),
                len(self.classification),
                len(self.policy),
                len(self.class_rules),
            )
            return self.config
        except Exception as exc:
            self.logger.error("Failed to load config: %s", exc)
            self.section_manager.sections = []
            self._refresh_views()
            return {}

    def get_settings(self):
        if not self.section_manager.sections and os.path.exists(self.config_path):
            self.load_config()
        return {
            "basic_config": self.basic_config.copy(),
            "advanced_config": self.advanced_config.copy(),
            "classification": self.classification.copy(),
            "policy": self.policy.copy(),
            "class_rules": [dict(item) for item in self.class_rules],
            "all": self.config.copy(),
        }

    def get_basic_settings(self):
        return self.get_settings()["basic_config"]

    def get_advanced_settings(self):
        return self.get_settings()["advanced_config"]

    def get_section(self, section_type, section_name=None):
        if not self.section_manager.sections and os.path.exists(self.config_path):
            self.load_config()
        section = self.section_manager.get_first(section_type, section_name if section_name is not None else section_type)
        if section is None and section_name is None:
            section = self.section_manager.get_first(section_type)
        return dict(section.get("options", {})) if section else {}

    def get_sections(self, section_type):
        if not self.section_manager.sections and os.path.exists(self.config_path):
            self.load_config()
        return [
            {"name": section.get("name", ""), "options": dict(section.get("options", {}))}
            for section in self.section_manager.get_all(section_type)
        ]

    def get_value(self, key, default=None, section=None):
        if section:
            return self.get_section(section, section).get(key, default)
        if key in self.basic_config:
            return self.basic_config.get(key, default)
        if key in self.advanced_config:
            return self.advanced_config.get(key, default)
        return self.config.get(key, default)

    def set_value(self, key, value, section=None):
        if not self.section_manager.sections and os.path.exists(self.config_path):
            self.load_config()
        target_section = section
        if target_section is None:
            if key in self.basic_config:
                target_section = "basic_config"
            elif key in self.advanced_config:
                target_section = "advanced_config"
            else:
                target_section = "basic_config"

        section_obj = self.section_manager.set_first_options(
            target_section,
            target_section,
            self.get_section(target_section, target_section),
        )
        section_obj["options"][key] = value
        self._refresh_views()

    def set_section_options(self, section_type, options, section_name=None):
        if not self.section_manager.sections and os.path.exists(self.config_path):
            self.load_config()
        actual_name = section_name or section_type
        self.section_manager.set_first_options(section_type, actual_name, options)
        self._refresh_views()

    def replace_sections(self, section_type, sections):
        if not self.section_manager.sections and os.path.exists(self.config_path):
            self.load_config()
        self.section_manager.replace_sections(section_type, sections)
        self._refresh_views()

    def save_config(self):
        try:
            self.section_manager.config_path = self.config_path
            self.section_manager.save()
            self._refresh_views()
            self.logger.info("Config saved: %s", self.config_path)
            return True
        except Exception as exc:
            self.logger.error("Failed to save config: %s", exc)
            return False

    def is_enabled(self):
        return str(self.basic_config.get("enabled", "0")).strip().lower() in {"1", "true", "yes", "on"}

    def get_interface(self):
        return str(self.basic_config.get("interface", "eth0")).strip() or "eth0"

    def get_bandwidth(self, direction="download"):
        if direction == "download":
            return self.basic_config.get("download_speed", 100000)
        if direction == "upload":
            return self.basic_config.get("upload_speed", 50000)
        return 0

    def get_algorithm(self):
        return str(self.basic_config.get("queue_algorithm", "fq_codel")).strip().lower() or "fq_codel"

    def get_log_level(self):
        return str(self.advanced_config.get("log_level", "info")).strip().lower() or "info"

    def get_log_file(self):
        return str(self.advanced_config.get("log_file", "/var/log/sqm_controller.log")).strip() or "/var/log/sqm_controller.log"

    def get_classification_backend(self):
        return str(self.classification.get("backend", "")).strip().lower()

    def get_policy_cron_expression(self):
        expr = str(self.policy.get("cron", "")).strip()
        if not expr:
            expr = str(self.policy.get("schedule", "")).strip()
        return expr or DEFAULT_POLICY_CRON


def detect_rule_conflicts(class_rules):
    conflicts = []
    prepared = []

    for item in class_rules or []:
        if not isinstance(item, dict):
            continue
        options = dict(item.get("options", {}))
        if str(options.get("enabled", "1")).strip().lower() in {"0", "false", "no", "off"}:
            continue
        name = str(item.get("name") or "class_rule").strip() or "class_rule"
        proto = str(options.get("proto", "any")).strip().lower()
        if proto in ("", "*", "any"):
            proto = "all"
        dport = str(options.get("dport", "")).strip()
        sport = str(options.get("sport", "")).strip()
        src_ip = str(options.get("src_ip", "")).strip()
        category = str(options.get("category", "other")).strip().lower() or "other"

        try:
            dport_ranges = _parse_ports(dport)
        except Exception:
            dport_ranges = None
        try:
            sport_ranges = _parse_ports(sport)
        except Exception:
            sport_ranges = None

        prepared.append(
            {
                "name": name,
                "proto": proto,
                "dport_ranges": dport_ranges,
                "sport_ranges": sport_ranges,
                "src_ip": src_ip,
                "category": category,
            }
        )

    for idx, left in enumerate(prepared):
        for right in prepared[idx + 1:]:
            if not _proto_overlap(left["proto"], right["proto"]):
                continue
            if left["dport_ranges"] is None or right["dport_ranges"] is None:
                continue
            if left["sport_ranges"] is None or right["sport_ranges"] is None:
                continue
            if not _ports_overlap(left["dport_ranges"], right["dport_ranges"]):
                continue
            if not _ports_overlap(left["sport_ranges"], right["sport_ranges"]):
                continue
            if not _src_ip_overlap(left["src_ip"], right["src_ip"]):
                continue

            same_category = left["category"] == right["category"]
            severity = "warning" if same_category else "error"
            conflicts.append(
                {
                    "severity": severity,
                    "left_rule": left["name"],
                    "right_rule": right["name"],
                    "left_category": left["category"],
                    "right_category": right["category"],
                    "message": (
                        f"class_rule overlap: {left['name']}({left['category']}) <-> "
                        f"{right['name']}({right['category']})"
                    ),
                }
            )
    return conflicts


def validate_config_file(path):
    result = {"valid": False, "errors": [], "warnings": [], "rule_conflicts": []}

    if not path or not os.path.exists(path):
        result["errors"].append("file not found")
        return result
    if os.path.getsize(path) <= 0:
        result["errors"].append("file is empty")
        return result

    manager = ConfigManager(path)
    manager.load_config()
    settings = manager.get_settings()
    basic = settings.get("basic_config", {})
    advanced = settings.get("advanced_config", {})
    classification = settings.get("classification", {})
    policy = settings.get("policy", {})
    class_rules = settings.get("class_rules", [])

    if not basic:
        result["errors"].append("missing section: basic_config")
    if not advanced:
        result["warnings"].append("missing section: advanced_config")
    if not classification:
        result["errors"].append("missing section: classification")
    if not policy:
        result["warnings"].append("missing section: policy")

    interface = str(basic.get("interface", "")).strip()
    if not interface:
        result["errors"].append("basic_config.interface is required")

    for key in ("download_speed", "upload_speed"):
        value = basic.get(key)
        if value in (None, ""):
            result["errors"].append(f"basic_config.{key} is required")
            continue
        try:
            if int(str(value).strip()) <= 0:
                result["errors"].append(f"basic_config.{key} must be > 0")
        except Exception:
            result["errors"].append(f"basic_config.{key} must be an integer")

    algorithm = str(basic.get("queue_algorithm", "")).strip().lower()
    if algorithm not in {"fq_codel", "cake"}:
        result["errors"].append("basic_config.queue_algorithm must be fq_codel or cake")

    log_level = str(advanced.get("log_level", "")).strip().lower()
    if log_level and log_level not in {"debug", "info", "warn", "warning", "error"}:
        result["warnings"].append("advanced_config.log_level is not in recommended values")

    backend = str(classification.get("backend", "")).strip().lower()
    if backend and backend not in VALID_BACKENDS:
        result["errors"].append("classification.backend must be nft or iptables")
    if not backend:
        result["warnings"].append("classification.backend is empty; runtime will auto-detect backend")

    default_class = str(classification.get("default_class", "other")).strip().lower()
    if default_class not in VALID_CATEGORIES:
        result["errors"].append("classification.default_class must be one of other/gaming/streaming/bulk")

    category_marks = {}
    for category in ("other", "gaming", "streaming", "bulk"):
        key = f"mark_{category}"
        raw_value = classification.get(key)
        if raw_value in (None, ""):
            result["errors"].append(f"classification.{key} is required")
            continue
        try:
            category_marks[category] = _validate_mark(raw_value, f"classification.{key}")
        except Exception as exc:
            result["errors"].append(str(exc))
    if len(set(category_marks.values())) != len(category_marks):
        result["errors"].append("classification marks must be unique across categories")

    for item in class_rules:
        name = str(item.get("name") or "class_rule").strip() or "class_rule"
        options = dict(item.get("options", {}))
        category = str(options.get("category", "other")).strip().lower() or "other"
        if category not in VALID_CATEGORIES:
            result["errors"].append(f"{name}: unsupported category '{category}'")

        proto = str(options.get("proto", "any")).strip().lower()
        if proto in ("", "*", "any"):
            proto = "all"
        if proto not in {"all", "tcp", "udp"}:
            result["errors"].append(f"{name}: unsupported proto '{proto}'")

        try:
            priority = int(str(options.get("priority", "0")).strip())
            if priority < 0 or priority > 1000:
                result["errors"].append(f"{name}: priority must be between 0 and 1000")
        except Exception:
            result["errors"].append(f"{name}: invalid priority '{options.get('priority')}'")

        dport = str(options.get("dport", "")).strip()
        sport = str(options.get("sport", "")).strip()
        if proto == "all" and (dport or sport):
            result["errors"].append(f"{name}: ports require proto tcp/udp")
        for field_name, field_value in (("dport", dport), ("sport", sport)):
            if not field_value:
                continue
            try:
                _parse_ports(field_value)
            except Exception as exc:
                result["errors"].append(f"{name}: {field_name} {exc}")

        src_ip = str(options.get("src_ip", "")).strip()
        if src_ip and _parse_ip_value(src_ip) is None:
            result["warnings"].append(f"{name}: src_ip '{src_ip}' is not a plain IP/CIDR; overlap detection will be conservative")

        dst_ip = str(options.get("dst_ip", "")).strip()
        if dst_ip:
            result["errors"].append(f"{name}: dst_ip is not supported in this release")

    if policy:
        mode = str(policy.get("mode", "auto")).strip().lower() or "auto"
        if mode not in VALID_POLICY_MODES:
            result["errors"].append("policy.mode must be one of auto/balanced/gaming/streaming/bulk")

        ranges = (
            ("latency_high_ms", 1, 100000),
            ("loss_high_pct", 0, 100),
            ("bulk_cap_pct", 0, 100),
            ("gaming_floor_pct", 0, 100),
            ("streaming_floor_pct", 0, 100),
            ("cooldown_min", 0, 10080),
        )
        for field_name, min_value, max_value in ranges:
            raw_value = policy.get(field_name)
            if raw_value in (None, ""):
                continue
            try:
                number = int(str(raw_value).strip())
            except Exception:
                result["errors"].append(f"policy.{field_name} must be an integer")
                continue
            if number < min_value or number > max_value:
                result["errors"].append(f"policy.{field_name} must be in range {min_value}..{max_value}")

        if (
            int(str(policy.get("gaming_floor_pct", 0) or 0)) +
            int(str(policy.get("streaming_floor_pct", 0) or 0))
        ) > 100:
            result["errors"].append("policy gaming_floor_pct + streaming_floor_pct must be <= 100")

        cron_expr = str(policy.get("cron", "")).strip() or str(policy.get("schedule", "")).strip()
        cron_error = _validate_cron_expression(cron_expr)
        if cron_error:
            result["errors"].append(cron_error)

    conflicts = detect_rule_conflicts(class_rules)
    result["rule_conflicts"] = conflicts
    for item in conflicts:
        if item["severity"] == "error":
            result["errors"].append(item["message"])
        else:
            result["warnings"].append(item["message"])

    result["valid"] = len(result["errors"]) == 0
    return result


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG, format="%(asctime)s %(name)s %(levelname)s %(message)s")
    manager = ConfigManager()
    print("all:", manager.load_config())
    print("algorithm:", manager.get_algorithm())
    print("enabled:", manager.is_enabled())
