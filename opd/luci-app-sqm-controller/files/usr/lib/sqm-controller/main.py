#!/usr/bin/env python3
"""SQM Controller 主入口。

负责三类工作：
1. 读取和保存配置，并对外提供 LuCI/CLI 入口；
2. 串起分类、诊断、策略判断和日志输出；
3. 在手动 apply 时执行快照、下发和失败回滚。

具体的分类和调度算法分散在独立模块中，这里主要负责把整条业务链路组织起来。
"""
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
import firewall_manager
import rule_manager
import traffic_analyzer
import traffic_classifier
import adaptive_allocator
import congestion_detector
import decision_state
import dns_mapper
import nss_detect
import traffic_stats
import tls_sni
import unknown_flow_logger


def _run_with_timeout(cmd_list, timeout=30, error_msg="command timeout"):
    """运行子进程并带超时保护。失败时返回 {success:False, error:...}。"""
    try:
        proc = subprocess.run(
            cmd_list, capture_output=True, text=True, timeout=timeout,
        )
        return {
            "success": proc.returncode == 0,
            "stdout": (proc.stdout or "").strip(),
            "stderr": (proc.stderr or "").strip(),
            "rc": proc.returncode,
        }
    except subprocess.TimeoutExpired:
        return {"success": False, "error": f"{error_msg} after {timeout}s", "stdout": ""}
    except Exception as exc:
        return {"success": False, "error": str(exc), "stdout": ""}


_MAIN_IFACE_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,15}$")


def _validate_iface_main(value, field="interface"):
    v = str(value or "").strip()
    if not v or not _MAIN_IFACE_RE.match(v):
        raise ValueError(f"{field} '{value}' invalid: [A-Za-z0-9_.:-] max 15 chars")
    return v


LOG_FILE = "/var/log/sqm_controller.log"
SELF_CHECK_PY = "/usr/lib/sqm-controller/self_check.py"
CONFIG_FILE = "/etc/config/sqm_controller"
ALLOWED_ALGORITHMS = {"fq_codel", "cake"}
ALLOWED_LOG_LEVELS = {"debug", "info", "warn", "warning", "error"}
LOG_MAX_BYTES = 256 * 1024
LOG_BACKUP_COUNT = 5
POLICY_REPORT_FILE = "/var/log/sqm_policy.jsonl"
POLICY_REPORT_MAX_BYTES = 2 * 1024 * 1024
POLICY_REPORT_BACKUP_COUNT = 4
POLICY_ONCE_LOCK_FILE = "/tmp/sqm_policy_once.lock"
CLASSIFIER_RULE_STATE_FILE = "/tmp/sqm_classifier_rule_state.json"
DNS_RULE_WINDOW_STATE_FILE = "/tmp/sqm_dns_rule_window_state.json"
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


def _rotate_file_if_needed(path, max_bytes, backup_count):
    """普通文件超过阈值后做轮转。"""
    if not path or max_bytes <= 0:
        return {"success": False, "rotated": False, "reason": "rotation disabled"}
    try:
        if not os.path.exists(path):
            return {"success": True, "rotated": False, "size": 0}
        size = os.path.getsize(path)
        if size < max_bytes:
            return {"success": True, "rotated": False, "size": size}
        return rotate_logs(log_path=path, backup_count=backup_count)
    except Exception as exc:
        return {"success": False, "rotated": False, "error": str(exc)}


class _BestEffortFileLock:
    """简单的非阻塞文件锁，用来避免策略任务重叠运行。"""

    def __init__(self, path):
        self.path = path
        self.handle = None
        self.locked = False

    def acquire(self):
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        self.handle = open(self.path, "a+", encoding="utf-8")
        try:
            import fcntl
            fcntl.flock(self.handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.handle.seek(0)
            self.handle.truncate()
            self.handle.write(str(os.getpid()))
            self.handle.flush()
            self.locked = True
            return True
        except Exception:
            self.locked = False
            return False

    def release(self):
        if not self.handle:
            return
        try:
            if self.locked:
                import fcntl
                fcntl.flock(self.handle.fileno(), fcntl.LOCK_UN)
        except Exception:
            pass
        try:
            self.handle.close()
        except Exception:
            pass
        self.handle = None
        self.locked = False


def _to_bool(value):
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return bool(value)


def _to_float(value, default=0.0):
    try:
        return float(value)
    except Exception:
        return default


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
        # OpenWrt 23.05 上的 cake 通常不会明确输出 ecn/noecn。
        # 只要没有看到 noecn，就按支持 ECN 处理。
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


def _load_policy_report_entries(limit=50):
    """读取 policy.jsonl 最近若干条记录。轻量实现，避免全量 readlines()。

    - 文件不存在 → 返回 ([], None)
    - 空文件 → 返回 ([], None)
    - 坏 JSON 行 → 跳过
    - 文件 >10MB → 只读尾部 10MB
    - limit=1 时只解析最后几行
    """
    MAX_BYTES = 10 * 1024 * 1024  # 10MB
    if not os.path.exists(POLICY_REPORT_FILE):
        return [], None
    entries = []
    try:
        fsize = os.path.getsize(POLICY_REPORT_FILE)
        with open(POLICY_REPORT_FILE, "r", encoding="utf-8") as fh:
            if fsize > MAX_BYTES:
                fh.seek(max(0, fsize - MAX_BYTES))
                fh.readline()  # 跳过不完整首行
            raw_lines = fh.readlines()
        for line in reversed(raw_lines):
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except Exception:
                continue
            if isinstance(entry, dict):
                entries.append(entry)
            if len(entries) >= limit:
                break
    except Exception as exc:
        return [], {"success": False, "error": "failed to read policy report", "details": str(exc)}
    return entries, None


def _append_jsonl_atomic(path, item):
    """追加一行 JSON 到日志文件，并在 Linux/OpenWrt 上用 flock 防并发覆盖。"""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    line = json.dumps(item, ensure_ascii=False) + "\n"
    lock_path = path + ".lock"
    with open(lock_path, "a+", encoding="utf-8") as lock_fh:
        locked = False
        try:
            try:
                import fcntl
                fcntl.flock(lock_fh.fileno(), fcntl.LOCK_EX)
                locked = True
            except Exception:
                locked = False
            if path == POLICY_REPORT_FILE:
                _rotate_file_if_needed(
                    POLICY_REPORT_FILE,
                    POLICY_REPORT_MAX_BYTES,
                    POLICY_REPORT_BACKUP_COUNT,
                )
            with open(path, "a", encoding="utf-8") as fh:
                fh.write(line)
                fh.flush()
                try:
                    os.fsync(fh.fileno())
                except Exception:
                    pass
        finally:
            if locked:
                try:
                    fcntl.flock(lock_fh.fileno(), fcntl.LOCK_UN)
                except Exception:
                    pass


def _get_adaptive_params():
    try:
        cfg = ConfigManager()
        cfg.load_config()
        adaptive = cfg.get_adaptive_settings()
        settings = cfg.get_settings().get("all", {})
        adaptive["upload_kbps"] = int(settings.get("upload_speed", settings.get("upload_bandwidth", 0)) or 0)
        adaptive["download_kbps"] = int(settings.get("download_speed", settings.get("download_bandwidth", 0)) or 0)
        return adaptive
    except Exception:
        return {
            "enabled": True, "mode": "auto", "product_mode": "auto",
            "mode_label": "智能自动",
            "latency_high_ms": 80, "loss_high_pct": 2,
            "jitter_high_ms": 30, "cooldown_min": 2, "debounce_count": 2,
            "gaming_floor_pct": 15, "streaming_floor_pct": 25,
            "bulk_cap_pct": 60, "bulk_ceil_pct": 60,
            "unknown_high_pct": 30,
            "upload_kbps": 0, "download_kbps": 0,
        }


def _build_policy_snapshot(congestion, traffic, decision, allocation,
                           dry_run=True, tc_applied=False,
                           classifier_scan=None):
    """整理 LuCI 和策略日志共用的策略快照结构。"""
    classes_raw = traffic.get("classes", {}) if isinstance(traffic, dict) else {}

    def class_kbps(name):
        item = classes_raw.get(name, {}) if isinstance(classes_raw.get(name, {}), dict) else {}
        return _to_float(item.get("kbps", item.get("value", 0)), 0.0)

    def class_pct(name):
        item = classes_raw.get(name, {}) if isinstance(classes_raw.get(name, {}), dict) else {}
        return _to_float(item.get("pct", 0), 0.0)

    total_kbps = _to_float(traffic.get("total_kbps", traffic.get("tc_kbps", 0)), 0.0)
    classified_kbps = sum(class_kbps(name) for name in ("gaming", "streaming", "bulk"))
    classification_ratio = _to_float(
        traffic.get("classification_ratio"),
        round(classified_kbps / max(total_kbps, 0.001) * 100.0, 1),
    )
    unknown_pct = _to_float(traffic.get("unknown_pct", 0), 0.0)

    traffic_health = str(traffic.get("health", "unknown"))
    traffic_success = traffic.get("success", True)
    tc_dt = _to_float(traffic.get("tc_dt", 0), 0.0)
    tc_reset = bool(traffic.get("tc_reset", False))
    scan = classifier_scan if isinstance(classifier_scan, dict) else {}

    if traffic_success is False:
        quality_level = "low"
        quality_reason = "traffic analyzer failed, classification quality unavailable"
    elif tc_reset or (total_kbps > 0 and tc_dt <= 0):
        quality_level = "medium"
        quality_reason = "traffic sampling window is resetting, classification quality is warming up"
    elif total_kbps <= 0 and unknown_pct <= 0:
        quality_level = "idle"
        quality_reason = "no traffic observed"
    elif unknown_pct > 70:
        quality_level = "low"
        quality_reason = "unknown exceeds 70%, classification unreliable"
    elif unknown_pct > 40:
        quality_level = "medium"
        quality_reason = f"unknown {unknown_pct:.1f}%, moderate classification coverage"
    else:
        quality_level = "high"
        quality_reason = f"unknown {unknown_pct:.1f}%, good classification coverage"

    if scan and scan.get("success") is False:
        quality_level = "low"
        quality_reason = "unknown flow scan failed: " + str(scan.get("error", "unknown error"))

    try:
        dns_stats = dns_mapper.get_stats()
        dns_rule_stats = dns_mapper.get_rule_hit_stats()
    except Exception:
        dns_stats = {}
        dns_rule_stats = []
    dns_top = [
        {"pattern": x["pattern"], "class": x["class"], "cache_entries": x["cache_entries"]}
        for x in dns_rule_stats if x.get("cache_entries", 0) > 0
    ][:5]

    dec = decision.get("decision", {}) if isinstance(decision.get("decision"), dict) else decision
    dec = dec if isinstance(dec, dict) else {}
    eval_ = decision.get("evaluation", {}) if isinstance(decision.get("evaluation"), dict) else {}
    decision_inputs = decision.get("inputs", {}) if isinstance(decision.get("inputs"), dict) else {}

    return {
        "time": int(time.time()),
        "engine": "policy",
        "dry_run": bool(dry_run),
        "congestion": congestion,
        "traffic": {
            "data_source": str(traffic.get("data_source", "")),
            "total_kbps": round(total_kbps, 2),
            "classified_kbps": round(classified_kbps, 2),
            "classification_ratio": round(classification_ratio, 1),
            "dominant": str(traffic.get("dominant", "none")),
            "unknown_pct": round(unknown_pct, 1),
            "health": str(traffic.get("health", "unknown")),
            "tc_dt": round(tc_dt, 3),
            "tc_reset": tc_reset,
            "tc_state_key": str(traffic.get("tc_state_key", "")),
            "classes": {
                name: {
                    "kbps": round(class_kbps(name), 2),
                    "pct": round(class_pct(name), 2),
                }
                for name in ("gaming", "streaming", "bulk", "other")
            },
        },
        "classification_quality": {
            "unknown_pct": round(unknown_pct, 1),
            "classified_ratio": round(classification_ratio, 1),
            "quality": quality_level,
            "reason": quality_reason,
            "traffic_health": traffic_health,
            "tc_dt": round(tc_dt, 3),
            "tc_reset": tc_reset,
            "scan_success": scan.get("success") if scan else None,
            "scan_logged": scan.get("logged") if scan else None,
            "scan_diagnosed": scan.get("diagnosed") if scan else None,
        },
        "dns_cache": {
            "cache_entries": int(dns_stats.get("cache_entries", 0) or 0),
            "lookup_hits": int(dns_stats.get("lookup_hits", 0) or 0),
            "total_mapped": int(dns_stats.get("total_mapped", 0) or 0),
            "top_patterns": dns_top,
        },
        "decision": {
            "from": str(dec.get("from", "")),
            "to": str(dec.get("to", "")),
            "changed": bool(dec.get("changed", False)),
            "reason": str(dec.get("reason", "")),
            "confidence": _to_float(dec.get("confidence", eval_.get("confidence", 0)), 0.0),
            "policy_mode": str(decision_inputs.get("policy_mode", "")),
            "product_mode": str(decision_inputs.get("product_mode", "")),
            "mode_label": str(decision_inputs.get("mode_label", "")),
        },
        "allocation": allocation,
        "tc_applied": bool(tc_applied),
    }


def _run_policy_chain(dev="ifb0", state_key=None, dry_run=True,
                      refresh_dns=True, scan_conntrack=True,
                      scan_min_bytes=4096, scan_state_path=None,
                      scan_record=True, include_tls_sni=False):
    """运行共用的策略判断链路，不在这里下发 TC 变更。"""
    # 统一策略链路入口：采集 -> 分析 -> 决策 -> 分配。
    # dry_run 只影响状态保存和后续下发，不影响当前这一轮判断结果。
    adaptive = _get_adaptive_params()

    dns_refresh = {}
    if refresh_dns:
        try:
            dns_refresh = dns_mapper.refresh()
        except Exception as exc:
            dns_refresh = {"success": False, "error": str(exc)}

    tls_sni_result = {}
    if include_tls_sni:
        try:
            tls_sni_result = tls_sni.sniff_and_import(timeout_sec=8, max_packets=80)
        except Exception as exc:
            tls_sni_result = {"success": False, "error": str(exc)}

    classifier_scan = {}
    if scan_conntrack:
        try:
            scan_kwargs = {"min_bytes": scan_min_bytes, "record": scan_record}
            if scan_state_path:
                scan_kwargs["state_path"] = scan_state_path
            classifier_scan = traffic_classifier.scan_conntrack(**scan_kwargs)
        except Exception as exc:
            classifier_scan = {"success": False, "error": str(exc)}

    congestion = congestion_detector.detect_live()
    if state_key is None:
        traffic = traffic_analyzer.full_analysis(dev=dev)
    else:
        traffic = traffic_analyzer.full_analysis(dev=dev, state_key=state_key)

    decision = decision_state.full_decision(
        congestion_result=congestion,
        traffic_result=traffic,
        cooldown_min=adaptive["cooldown_min"],
        debounce_count=adaptive["debounce_count"],
        policy_mode=adaptive.get("mode", "auto"),
        product_mode=adaptive.get("product_mode", adaptive.get("mode", "auto")),
        mode_label=adaptive.get("mode_label"),
        dry_run=dry_run,
    )
    allocation = adaptive_allocator.allocate_full(
        decision_result=decision,
        traffic_result=traffic,
        congestion_result=congestion,
        total_bandwidth_kbps=adaptive.get("download_kbps"),
        policy_config=adaptive,
    )
    # scan_conntrack → classify_flow → lookup() 产生了 hits/misses，
    # 在 refresh() 时的 _save_cache() 还未包含这些增量，此处补持久化。
    dns_mapper.save()
    return {
        "adaptive": adaptive,
        "dns_refresh": dns_refresh,
        "tls_sni": tls_sni_result,
        "classifier_scan": classifier_scan,
        "congestion": congestion,
        "traffic": traffic,
        "decision": decision,
        "allocation": allocation,
    }


def _append_policy_log(path):
    """执行完整策略 dry-run 决策链并将结果写入日志。"""
    started = time.time()
    chain = _run_policy_chain(dry_run=True, include_tls_sni=True)
    tls_sni_result = chain.get("tls_sni", {})
    entry = _build_policy_snapshot(
        congestion=chain.get("congestion", {}),
        traffic=chain.get("traffic", {}),
        decision=chain.get("decision", {}),
        allocation=chain.get("allocation", {}),
        dry_run=True,
        tc_applied=False,
        classifier_scan=chain.get("classifier_scan", {}),
    )
    entry["tls_sni"] = {
        "success": tls_sni_result.get("success", False),
        "sni_count": tls_sni_result.get("sni_count", 0),
        "imported": tls_sni_result.get("imported", 0),
    }
    entry["duration_ms"] = int(max(0.0, (time.time() - started) * 1000))
    try:
        _append_jsonl_atomic(path, entry)
        entry["logged"] = True
    except Exception as exc:
        entry["logged"] = False
        entry["log_error"] = str(exc)
    return entry


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
    dst_ip_match = re.search(r"\bip\s+daddr\s+(\S+)\b", line)
    if not dst_ip_match:
        dst_ip_match = re.search(r"\bip6\s+daddr\s+(\S+)\b", line)

    return {
        "proto": (proto_match.group(1).strip().lower() if proto_match else ""),
        "dport": (dport_match.group(1).strip().replace(":", "-") if dport_match else ""),
        "sport": (sport_match.group(1).strip().replace(":", "-") if sport_match else ""),
        "src_ip": src_ip_match.group(1).strip() if src_ip_match else "",
        "dst_ip": dst_ip_match.group(1).strip() if dst_ip_match else "",
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
            "upload_classes_ready": False,
            "download_classes_ready": False,
            "upload_qdiscs_ready": False,
            "download_qdiscs_ready": False,
            "upload_class_queues_ready": False,
            "download_class_queues_ready": False,
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


def _has_all_htb_classes(class_text, classids):
    text = str(class_text or "")
    return all(re.search(rf"\bclass htb {re.escape(classid)}\b", text) for classid in classids)


def _has_all_leaf_qdiscs(qdisc_text, classids):
    text = str(qdisc_text or "")
    qdisc_re = "|".join(re.escape(item) for item in ("fq_codel", "cake"))
    return all(
        re.search(rf"\bqdisc (?:{qdisc_re}) \S+:\s+parent {re.escape(classid)}\b", text)
        for classid in classids
    )


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
    upload_classes_ready = _has_all_htb_classes(upload_class_text, ("1:11", "1:12", "1:13"))
    download_classes_ready = _has_all_htb_classes(download_class_text, ("2:21", "2:22", "2:23"))
    upload_qdiscs_ready = _has_all_leaf_qdiscs(upload_qdisc_text, ("1:11", "1:12", "1:13"))
    download_qdiscs_ready = _has_all_leaf_qdiscs(download_qdisc_text, ("2:21", "2:22", "2:23"))
    upload_class_queues_ready = upload_classes_ready and upload_qdiscs_ready
    download_class_queues_ready = download_classes_ready and download_qdiscs_ready
    pipeline["tc"]["upload_root_ready"] = upload_root_ready
    pipeline["tc"]["download_root_ready"] = download_root_ready
    pipeline["tc"]["upload_classes_ready"] = upload_classes_ready
    pipeline["tc"]["download_classes_ready"] = download_classes_ready
    pipeline["tc"]["upload_qdiscs_ready"] = upload_qdiscs_ready
    pipeline["tc"]["download_qdiscs_ready"] = download_qdiscs_ready
    pipeline["tc"]["upload_class_queues_ready"] = upload_class_queues_ready
    pipeline["tc"]["download_class_queues_ready"] = download_class_queues_ready
    pipeline["tc"]["upload_filters_ready"] = upload_filters_ready
    pipeline["tc"]["download_filters_ready"] = download_filters_ready
    if (
        upload_root_ready and download_root_ready
        and upload_class_queues_ready and download_class_queues_ready
        and upload_filters_ready and download_filters_ready
    ):
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
        if total_kbps > 0 and not pipeline.get("tc", {}).get("download_class_queues_ready", False):
            diagnostics.append(
                {
                    "level": "error",
                    "code": "IFB_CLASSIFIER_CLASSES_MISSING",
                    "message": "ifb0 下载分类 class/qdisc 不完整，已标记流量会回退到默认类",
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

    dst_ip = rule.get("_dst_ip", "")
    if dst_ip and entry.get("dst_ip") != dst_ip:
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
            dst_ip = str(opts.get("dst_ip", "")).strip()
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
                    "dst_ip": dst_ip,
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
                    "_dst_ip": dst_ip,
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
        for key in ("_order", "_proto", "_dports", "_sports", "_src_ip", "_dst_ip", "_mark"):
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
    if summary["total_kbps"] == 0:
        summary["health"] = "idle"
    else:
        known_kbps = summary["classified_kbps"] + summary["other_kbps"]
        summary["health"] = "ok" if known_kbps > 0 else "degraded"
    result["diagnostics"] = _build_classifier_diagnostics(
        summary,
        categories,
        pipeline,
        focus_dev,
        result.get("window_sec", 0),
    )

    try:
        dns_mapper.refresh()
        dns_mapper.sync_hit_stats_from_cache()
        dns_hits_list = dns_mapper.get_rule_hit_stats()
    except Exception:
        dns_hits_list = []
    result["dns_rule_hits"] = dns_hits_list

    # 把 DNS 规则命中整理成规则行，再合并进规则表
    try:
        dns_prev_state = _read_json_file(DNS_RULE_WINDOW_STATE_FILE, {})
        dns_next_state = {}
        dns_rules = []
        now_ts = int(time.time())
        for dns_hit in dns_hits_list:
            hits = int(dns_hit.get("cache_entries", 0) or 0)
            if hits <= 0:
                continue
            pattern = dns_hit.get("pattern", "")
            cls = dns_hit.get("class", "other")
            confidence = float(dns_hit.get("confidence", 0) or 0)
            rule_id = "dns:" + pattern
            prev = dns_prev_state.get(rule_id, {}) if isinstance(
                dns_prev_state.get(rule_id), dict
            ) else {}
            prev_hits = int(prev.get("counter_packets", -1) or -1)
            window_hits = hits - prev_hits if prev_hits >= 0 and hits >= prev_hits else 0
            dns_next_state[rule_id] = {"counter_packets": hits, "time": now_ts}
            dns_rules.append({
                "id": rule_id,
                "category": cls,
                "proto": "dns",
                "dport": pattern,
                "sport": "--",
                "src_ip": "--",
                "mark": "%.2f" % confidence,
                "classid": "--",
                "counter_packets": hits,
                "counter_bytes": 0,
                "last_window_packets": window_hits,
                "last_window_bytes": 0,
                "status": "hit",
                "enabled": True,
                "priority": int(confidence * 100),
                "rule_type": "dns",
            })
        if dns_next_state:
            _write_json_atomic(DNS_RULE_WINDOW_STATE_FILE, dns_next_state)
        if dns_rules:
            result["rules"] = list(result.get("rules", [])) + dns_rules
            result["summary"]["rules_total"] = len(result["rules"])
    except Exception:
        pass

    return result


class SQMController:
    """将配置、TC、分类器和防火墙操作组织成一组可复用接口。"""
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
            cleanup = self._full_runtime_cleanup()
            all_ok = bool(cleanup.get("success"))
            return {
                "requested": True,
                "enabled": False,
                "applied": all_ok,
                "restart_success": all_ok,
                "message": "service disabled, runtime cleared" if all_ok else "service disabled, runtime clear failed",
                "cleanup": cleanup,
            }

        tc = TCManager(self.config)
        ok, queue_backend, nss_info = tc.setup_queues()
        if not ok:
            return {
                "requested": True,
                "enabled": True,
                "applied": False,
                "restart_success": False,
                "queue_backend": queue_backend,
                "nss": nss_info,
                "message": "failed to apply " + queue_backend + " queue rules",
            }

        if queue_backend == "nss":
            # NSS 硬件模式：nssfq_codel 单队列不支持业务分类，跳过分类下发
            classifier_runtime = {
                "requested": False,
                "enabled": False,
                "applied": True,
                "message": "NSS 硬件模式不支持业务分类，已跳过分类下发",
                "nss_skip": True,
            }
        else:
            classifier_runtime = self._apply_classifier_runtime()
        if not classifier_runtime.get("requested"):
            return {
                "requested": True,
                "enabled": True,
                "applied": True,
                "restart_success": True,
                "queue_backend": queue_backend,
                "nss": nss_info,
                "message": "queue rules applied",
                "classifier": classifier_runtime,
            }

        classifier_ok = bool(classifier_runtime.get("applied"))
        return {
            "requested": True,
            "enabled": True,
            "applied": classifier_ok,
            "restart_success": classifier_ok,
            "queue_backend": queue_backend,
            "nss": nss_info,
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

    def _full_runtime_cleanup(self):
        """统一清理：分类运行时（firewall + tc）+ NSS sqm section。
        由 disable()、_apply_runtime_config(enabled=False)、enable() 失败回滚三条路径共用。"""
        cleanup = self._clear_classifier_runtime()
        nss_cleanup = {}
        try:
            nss_cleanup = {"success": bool(TCManager(self.config).clear_sqm_runtime())}
        except Exception as exc:
            logging.exception("clear_sqm_runtime failed: %s", exc)
            nss_cleanup = {"success": False, "error": str(exc)}
        cleanup["nss_sqm"] = nss_cleanup
        if not nss_cleanup.get("success"):
            cleanup.setdefault("errors", []).append(f"nss_sqm: {nss_cleanup.get('error', 'clear failed')}")
        cleanup["success"] = bool(cleanup.get("success")) and bool(nss_cleanup.get("success"))
        return cleanup

    def _managed_tc_runtime_state(self):
        self._reload_config(force=True)
        iface = _validate_iface_main(self.config_manager.get_interface(), "interface")
        tc_wan = _run_with_timeout(
            ["tc", "qdisc", "show", "dev", iface], timeout=5,
            error_msg="tc qdisc show timed out",
        ).get("stdout", "")
        tc_ifb = _run_with_timeout(
            ["tc", "qdisc", "show", "dev", "ifb0"], timeout=5,
            error_msg="tc ifb0 show timed out",
        ).get("stdout", "")
        wan_managed = "qdisc htb 1:" in (tc_wan or "").lower()
        ifb_managed = "qdisc htb 2:" in (tc_ifb or "").lower()
        nss_managed = bool(re.search(r"nsstbl|nssfq_codel", (tc_wan or "") + (tc_ifb or "")))
        return {
            "iface": iface,
            "tc_wan": tc_wan,
            "tc_ifb": tc_ifb,
            "wan_managed": wan_managed,
            "ifb_managed": ifb_managed,
            "nss_managed": nss_managed,
            "running": wan_managed or ifb_managed or nss_managed,
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

        cleanup = self._full_runtime_cleanup()
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
        cleanup = self._full_runtime_cleanup()
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
        tc_wan_detail = _run_with_timeout(
            ["tc", "-d", "qdisc", "show", "dev", iface], timeout=5,
            error_msg="tc detail show timed out",
        ).get("stdout", "")
        tc_ifb_detail = _run_with_timeout(
            ["tc", "-d", "qdisc", "show", "dev", "ifb0"], timeout=5,
            error_msg="tc ifb0 detail show timed out",
        ).get("stdout", "")

        # 清理规则后，内核可能保留默认的 fq_codel 根队列。
        # 这里只在受控 HTB 根队列存在时，才认为 SQM 已真正挂载。
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
        # NSS 后端状态（供 LuCI 前端降级提示）
        try:
            qb = str(self.config.get("queue_backend", "auto") or "auto").strip().lower()
            nss_backend, nss_info = nss_detect.resolve_backend(qb)
            data["nss"] = {
                "configured": qb,
                "resolved_backend": nss_backend,
                "available": nss_info.get("available"),
                "model": nss_info.get("model", ""),
                "reason": nss_info.get("reason", ""),
                "error": nss_info.get("error", ""),
            }
        except Exception as exc:
            logging.exception("nss detect failed: %s", exc)
            data["nss"] = {"configured": "auto", "resolved_backend": "software", "available": False, "reason": "NSS 检测异常: %s" % exc}
        print(json.dumps(data, ensure_ascii=False))

    def rotate_logs_json(self):
        app_log_result = rotate_logs()
        policy_log_result = _rotate_file_if_needed(
            POLICY_REPORT_FILE,
            POLICY_REPORT_MAX_BYTES,
            POLICY_REPORT_BACKUP_COUNT,
        )
        result = {
            "success": bool(app_log_result.get("success", True)) and bool(policy_log_result.get("success", True)),
            "app_log": app_log_result,
            "policy_log": policy_log_result,
        }
        logging.info(
            "rotate_logs_json() app_rotated=%s policy_rotated=%s",
            app_log_result.get("rotated"),
            policy_log_result.get("rotated"),
        )
        print(json.dumps(result, ensure_ascii=False))

    def self_check_json(self):
        if not os.path.exists(SELF_CHECK_PY):
            print(json.dumps({"success": False, "error": "self_check.py not found"}, ensure_ascii=False))
            return
        result = _run_with_timeout(
            ["python3", SELF_CHECK_PY], timeout=30,
            error_msg="self_check timed out",
        )
        if not result["success"]:
            print(json.dumps({"success": False, "error": result.get("error", "self_check failed")}, ensure_ascii=False))
            return
        print(result["stdout"])

    def monitor_json(self):
        self._reload_config(force=True)
        iface = self.config_manager.get_interface()
        logging.info("monitor_json() iface=%s", iface)
        result = _run_with_timeout(
            ["/usr/lib/sqm-controller/monitor.py", "--iface", iface, "--record"],
            timeout=15, error_msg="monitor timed out",
        )
        if not result["success"]:
            print(json.dumps({"success": False, "error": result.get("error", "monitor failed")}, ensure_ascii=False))
            return
        print(result["stdout"])

    def monitor_history_json(self, window):
        self._reload_config(force=True)
        iface = self.config_manager.get_interface()
        if window not in {"1m", "5m", "1h", "6h", "24h"}:
            window = "5m"
        logging.info("monitor_history_json() iface=%s window=%s", iface, window)
        result = _run_with_timeout(
            ["/usr/lib/sqm-controller/monitor.py", "--iface", iface, "--history", "--window", str(window)],
            timeout=15, error_msg="monitor history timed out",
        )
        if not result["success"]:
            print(json.dumps({"success": False, "error": result.get("error", "monitor history failed")}, ensure_ascii=False))
            return
        print(result["stdout"])

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
            speed_result = _run_with_timeout(
                ["python3", SPEEDTEST_PY], timeout=60,
                error_msg="speedtest timed out",
            )
            if not speed_result["success"]:
                print(json.dumps({"success": False, "error": speed_result.get("error", "speedtest failed")}, ensure_ascii=False))
                return
            try:
                result = json.loads(speed_result["stdout"])
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

            # 预留 15% 带宽余量
            down_apply = int(down_kbps * 0.85)

            # 记录变更前（用于回显）
            before = self._current_all_settings()
            old_up = before.get("upload_speed")

            
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
                "upload": old_up,                
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


def _read_stdin_json(data_file=None):
    """从标准输入或文件读取 JSON；失败时返回 None。"""
    try:
        if data_file and os.path.exists(data_file):
            with open(data_file, "r", encoding="utf-8") as fh:
                return json.load(fh)
        raw = sys.stdin.read()
        if not raw.strip():
            return None
        return json.loads(raw)
    except Exception:
        return None


def _handle_list_port_heuristics():
    """返回系统端口启发式规则和用户端口规则。"""
    try:
        # 整理系统端口启发式规则
        system_rules = []
        for cls_name, proto_map in traffic_classifier.PORT_HEURISTICS.items():
            for proto, port_map in proto_map.items():
                for port_set, confidence in port_map.items():
                    ports_list = sorted(port_set)
                    system_rules.append({
                        "class": cls_name,
                        "proto": proto,
                        "ports": [list(p) for p in ports_list],
                        "confidence": confidence,
                    })

        # 读取用户端口规则
        user_rules = []
        user_path = "/etc/sqm_controller/port_heuristics.json"
        if os.path.exists(user_path):
            try:
                with open(user_path, "r", encoding="utf-8") as fh:
                    user_rules = json.load(fh)
                if not isinstance(user_rules, list):
                    user_rules = []
            except Exception:
                user_rules = []

    # 同时返回 UCI 里的 class_rule
        ctl = SQMController()
        ctl._reload_config(force=False)
        settings = ctl.config_manager.get_settings()
        class_rules = []
        for cr in settings.get("class_rules", []):
            opts = cr.get("options", {})
            class_rules.append({
                "name": cr.get("name", ""),
                "enabled": opts.get("enabled", "1") == "1",
                "category": opts.get("category", "other"),
                "proto": opts.get("proto", "all"),
                "dport": opts.get("dport", ""),
                "sport": opts.get("sport", ""),
                "src_ip": opts.get("src_ip", ""),
                "dst_ip": opts.get("dst_ip", ""),
                "priority": int(opts.get("priority", 50)),
            })

        return {
            "success": True,
            "system_rules": system_rules,
            "user_rules": user_rules,
            "class_rules": class_rules,
        }
    except Exception as exc:
        return {"success": False, "error": str(exc)}


def _handle_list_dns_rules():
    """返回系统域名规则、用户规则和 DNS 统计。"""
    try:
        dns_mapper.refresh()
        dns_mapper.sync_hit_stats_from_cache()

        # 这里直接返回前端可消费的数据结构，避免 LuCI 侧再次拼装规则元数据。
        system_rules = []
        current_section = "其他"
        for pattern, cls, confidence in dns_mapper.DOMAIN_RULES:
            system_rules.append({
                "pattern": pattern,
                "class": cls,
                "confidence": confidence,
            })

        # 读取用户 DNS 规则
        user_rules = []
        user_path = "/etc/sqm_controller/dns_rules.json"
        if os.path.exists(user_path):
            try:
                with open(user_path, "r", encoding="utf-8") as fh:
                    data = json.load(fh)
                user_rules = data if isinstance(data, list) else data.get("rules", [])
            except Exception:
                user_rules = []

        # 读取 DNS mapper 统计
        stats = dns_mapper.get_stats()
        rule_hit_stats = dns_mapper.get_rule_hit_stats()

        return {
            "success": True,
            "system_rules": system_rules,
            "user_rules": user_rules,
            "stats": stats,
            "rule_hit_stats": rule_hit_stats,
        }
    except Exception as exc:
        return {"success": False, "error": str(exc)}


def _handle_class_rule_crud(action, rule_name="", data_file=None):
    """新增、更新或删除一条 UCI class_rule。"""
    try:
        data = _read_stdin_json(data_file=data_file)
        if action in ("add", "update") and not data:
            return {"success": False, "error": "no JSON data provided on stdin"}

        ctl = SQMController()
        ctl._reload_config(force=False)
        mgr = ctl.config_manager
        settings = mgr.get_settings()
        class_rules = settings.get("class_rules", [])

        if action == "add":
            name = data.get("name", "").strip()
            if not name:
                return {"success": False, "error": "rule name is required"}
            # 检查规则名是否已存在
            for cr in class_rules:
                if cr.get("name") == name:
                    return {"success": False, "error": f"rule name '{name}' already exists"}
            new_rule = {
                "name": name,
                "options": {
                    "enabled": "1" if data.get("enabled", True) else "0",
                    "category": data.get("category", "other"),
                    "proto": data.get("proto", "all"),
                    "dport": str(data.get("dport", "")),
                    "sport": str(data.get("sport", "")),
                    "src_ip": str(data.get("src_ip", "")),
                    "dst_ip": str(data.get("dst_ip", "")),
                    "priority": str(data.get("priority", 50)),
                },
            }
            class_rules.append(new_rule)
            mgr.replace_sections("class_rule", class_rules)
            mgr.save_config()
            return {"success": True, "action": "add", "rule_name": name}

        elif action == "update":
            name = data.get("name", "").strip()
            old_name = str(data.get("old_name", name)).strip() or name
            if not name:
                return {"success": False, "error": "rule name is required"}
            if old_name != name:
                for cr in class_rules:
                    if cr.get("name") == name:
                        return {"success": False, "error": f"rule name '{name}' already exists"}
            found = False
            for cr in class_rules:
                if cr.get("name") == old_name:
                    cr["name"] = name
                    cr["options"]["enabled"] = "1" if data.get("enabled", True) else "0"
                    cr["options"]["category"] = data.get("category", cr["options"].get("category", "other"))
                    cr["options"]["proto"] = data.get("proto", cr["options"].get("proto", "all"))
                    cr["options"]["dport"] = str(data.get("dport", cr["options"].get("dport", "")))
                    cr["options"]["sport"] = str(data.get("sport", cr["options"].get("sport", "")))
                    cr["options"]["src_ip"] = str(data.get("src_ip", cr["options"].get("src_ip", "")))
                    cr["options"]["dst_ip"] = str(data.get("dst_ip", cr["options"].get("dst_ip", "")))
                    cr["options"]["priority"] = str(data.get("priority", cr["options"].get("priority", 50)))
                    found = True
                    break
            if not found:
                return {"success": False, "error": f"rule '{old_name}' not found"}
            mgr.replace_sections("class_rule", class_rules)
            mgr.save_config()
            return {"success": True, "action": "update", "rule_name": name, "old_name": old_name}

        elif action == "delete":
            name = rule_name.strip()
            if not name:
                # 优先尝试从标准输入读取
                if data and data.get("name"):
                    name = data["name"].strip()
                if not name:
                    return {"success": False, "error": "rule name is required"}
            new_rules = [cr for cr in class_rules if cr.get("name") != name]
            if len(new_rules) == len(class_rules):
                return {"success": False, "error": f"rule '{name}' not found"}
            mgr.replace_sections("class_rule", new_rules)
            mgr.save_config()
            return {"success": True, "action": "delete", "rule_name": name}

        return {"success": False, "error": f"unknown action: {action}"}

    except Exception as exc:
        return {"success": False, "error": str(exc)}


def _handle_save_dns_user_rules(data_file=None):
    """把用户自定义 DNS 规则保存到 JSON 文件。"""
    try:
        # 用户 DNS 规则统一落到一个 JSON 文件，手工编辑和 AI 导入走同一份规则库。
        data = _read_stdin_json(data_file=data_file)
        if data is None:
            return {"success": False, "error": "no JSON data provided"}

        rules = data if isinstance(data, list) else data.get("rules", [])
        user_path = "/etc/sqm_controller/dns_rules.json"
        os.makedirs(os.path.dirname(user_path), exist_ok=True)
        with open(user_path, "w", encoding="utf-8") as fh:
            json.dump(rules, fh, ensure_ascii=False, indent=2)
        return {"success": True, "count": len(rules)}
    except Exception as exc:
        return {"success": False, "error": str(exc)}


SNAPSHOT_CLASSIDS = {
    "upload": ["1:10", "1:11", "1:12", "1:13"],
    "download": ["2:20", "2:21", "2:22", "2:23"],
}


def _expected_snapshot_count():
    return sum(len(classids) for classids in SNAPSHOT_CLASSIDS.values())


def _snapshot_class_rates(upload_dev="eth1"):
    """读取当前 tc class 的 rate/ceil/prio，用于 apply 前的快照。

    返回：{"eth1:1:11": {dev, classid, rate, ceil, prio}, ...}
    """
    snapshot = {}
    dev_map = {
        str(upload_dev or "eth1").strip() or "eth1": SNAPSHOT_CLASSIDS["upload"],
        "ifb0": SNAPSHOT_CLASSIDS["download"],
    }
    for dev, classids in dev_map.items():
        try:
            proc = subprocess.run(
                ["tc", "class", "show", "dev", dev],
                capture_output=True, text=True, timeout=5,
            )
        except Exception:
            continue
        for classid in classids:
            for line in (proc.stdout or "").splitlines():
                if not re.search(r"\bclass htb " + re.escape(classid) + r"\b", line):
                    continue
                rate_m = re.search(r"\brate (\S+)", line)
                ceil_m = re.search(r"\bceil (\S+)", line)
                prio_m = re.search(r"\bprio (\d+)", line)
                if not rate_m or not ceil_m:
                    continue
                snapshot[f"{dev}:{classid}"] = {
                    "dev": dev,
                    "classid": classid,
                    "rate": rate_m.group(1),
                    "ceil": ceil_m.group(1),
                    "prio": int(prio_m.group(1)) if prio_m else 0,
                }
                break
    return snapshot


def _tc_rate_to_kbps(value):
    text = str(value or "").strip().lower()
    match = re.match(r"^([0-9]+(?:\.[0-9]+)?)([a-z/]+)?$", text)
    if not match:
        return None
    number = float(match.group(1))
    unit = (match.group(2) or "kbit").lower()
    if unit.startswith("gbit"):
        return int(round(number * 1000000))
    if unit.startswith("mbit"):
        return int(round(number * 1000))
    if unit.startswith("kbit"):
        return int(round(number))
    if unit.startswith("bit"):
        return max(1, int(round(number / 1000.0)))
    return int(round(number))


def _plan_snapshot_diff(plan, snapshot, upload_dev="eth1", tolerance_kbps=1):
    result = {"changed": [], "unchanged": [], "missing": []}
    groups = [
        (str(upload_dev or "eth1").strip() or "eth1", plan.get("upload_classes", [])),
        ("ifb0", plan.get("download_classes", [])),
    ]
    for dev, classes in groups:
        for item in classes:
            classid = item.get("classid", "")
            current = snapshot.get(f"{dev}:{classid}")
            if not current:
                result["missing"].append({"dev": dev, "classid": classid})
                continue
            current_rate = _tc_rate_to_kbps(current.get("rate"))
            current_ceil = _tc_rate_to_kbps(current.get("ceil"))
            target_rate = int(item.get("rate_kbps", 0) or 0)
            target_ceil = int(item.get("ceil_kbps", 0) or 0)
            target_prio = int(item.get("prio", current.get("prio", 0)) or 0)
            current_prio = int(current.get("prio", 0) or 0)
            changed = (
                current_rate is None or current_ceil is None
                or abs(current_rate - target_rate) > tolerance_kbps
                or abs(current_ceil - target_ceil) > tolerance_kbps
                or current_prio != target_prio
            )
            record = {
                "dev": dev,
                "classid": classid,
                "current": {"rate_kbps": current_rate, "ceil_kbps": current_ceil, "prio": current_prio},
                "target": {"rate_kbps": target_rate, "ceil_kbps": target_ceil, "prio": target_prio},
            }
            result["changed" if changed else "unchanged"].append(record)
    result["has_changes"] = bool(result["changed"] or result["missing"])
    return result


def _restore_class_rates(tc, snapshot):
    """用快照值恢复已修改的 class rate/ceil/prio。

    snapshot: _snapshot_class_rates 的返回值或子集。
    返回：{"success": bool, "applied": [...], "failed": [...]}
    """
    result = {"success": False, "applied": [], "failed": []}
    for key, item in snapshot.items():
        dev = item["dev"]
        classid = item["classid"]
        parent = "1:1" if dev != "ifb0" else "2:1"
        cmd = (
            f"tc class change dev {dev} parent {parent} classid {classid} "
            f"htb rate {item['rate']} ceil {item['ceil']} prio {item['prio']}"
        )
        try:
            ok, details = tc._run_checked(cmd, "restore-class-rate")
        except Exception as exc:
            ok = False
            details = str(exc)
        if ok:
            result["applied"].append(classid)
        else:
            result["failed"].append({"classid": classid, "error": str(details) if details else "unknown"})
    result["success"] = len(result["failed"]) == 0
    return result


def main():
    setup_logging()

    parser = argparse.ArgumentParser()
    parser.add_argument("--enable", action="store_true")
    parser.add_argument("--disable", action="store_true")
    parser.add_argument("--status-json", action="store_true")
    parser.add_argument("--monitor", action="store_true")
    parser.add_argument("--monitor-history", action="store_true")
    parser.add_argument("--window", choices=["1m", "5m", "1h", "6h", "24h"], default="5m")
    parser.add_argument("--speedtest", action="store_true")
    parser.add_argument("--rotate-logs", action="store_true")
    parser.add_argument("--self-check", action="store_true")
    parser.add_argument("--validate-config")
    parser.add_argument("--restore-config")
    parser.add_argument("--no-apply", action="store_true")
    parser.add_argument("--apply-classifier", action="store_true")
    parser.add_argument("--clear-classifier", action="store_true")
    parser.add_argument("--get-class-stats", action="store_true")
    parser.add_argument("--get-classifier-state", action="store_true")
    parser.add_argument("--policy-once", action="store_true")
    parser.add_argument("--export-report", action="store_true")
    parser.add_argument("--diag", action="store_true")
    parser.add_argument("--unknown-tail", type=int, default=0)
    parser.add_argument("--min-bytes", type=int, default=4096)
    parser.add_argument("--rules", choices=["list", "summary", "validate"], default=None)
    parser.add_argument("--analyze", action="store_true")
    parser.add_argument("--congestion", action="store_true")
    parser.add_argument("--decision", action="store_true")
    parser.add_argument("--allocate", action="store_true")
    parser.add_argument("--policy-status", action="store_true")
    parser.add_argument("--full-chain", action="store_true")
    parser.add_argument("--policy-apply", action="store_true")
    parser.add_argument("--format", choices=["json", "csv"], default="json")
    parser.add_argument("--dev", default="ifb0")
    parser.add_argument("--list-port-heuristics", action="store_true")
    parser.add_argument("--list-dns-rules", action="store_true")
    parser.add_argument("--add-class-rule", action="store_true")
    parser.add_argument("--update-class-rule", action="store_true")
    parser.add_argument("--delete-class-rule", type=str, default="")
    parser.add_argument("--get-policy-log", action="store_true")
    parser.add_argument("--aggregate-unknowns", action="store_true")
    parser.add_argument("--limit", type=int, default=20)
    parser.add_argument("--sort-by", choices=["bytes", "count"], default="bytes")
    parser.add_argument("--save-dns-user-rules", action="store_true")
    parser.add_argument("--export-unmatched-dns", action="store_true",
                        help="导出未匹配 DNS 域名供 AI 分析")
    parser.add_argument("--unmatched-min-count", type=int, default=3,
                        help="未匹配域名最低出现次数（默认3）")
    parser.add_argument("--unmatched-limit", type=int, default=150,
                        help="导出条数上限（默认150）")
    parser.add_argument("--import-ai-dns-rules", action="store_true",
                        help="导入 AI 生成的 DNS 规则")
    parser.add_argument("--ai-rules-data", type=str, default="",
                        help="AI 规则 JSON 文件路径（不指定则读 stdin）")
    parser.add_argument("--class-rule-data", type=str, default="",
                        help="Path to JSON file for add/update class-rule data")
    parser.add_argument("--dns-rule-data", type=str, default="",
                        help="Path to JSON file for save-dns-user-rules data")
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
            result = traffic_stats.collect(dev, state_key="ui")
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
            dns_mapper.refresh()
        except Exception:
            pass
        try:
            traffic_classifier.scan_conntrack(
                min_bytes=4096,
                state_path="/tmp/sqm_unknown_conntrack_state_ui.json",
                record=False,
            )
        except Exception:
            pass
        try:
            stats_result = traffic_stats.collect(focus_dev, state_key="ui")
        except Exception:
            stats_result = {"success": False, "time": int(time.time()), "dt": 0, "classes": {}, "total_kbps": 0}
        backend, rules = _build_classifier_rules(ctl.config_manager.config_path, focus_dev)
        pipeline = _build_classifier_pipeline(ctl.config_manager.get_interface(), backend)
        result = _build_classifier_state(stats_result, backend, focus_dev, rules=rules, pipeline=pipeline)
        print(json.dumps(result, ensure_ascii=False))
        raise SystemExit(0 if result.get("success") else 1)
    elif args.policy_once:
        lock = _BestEffortFileLock(POLICY_ONCE_LOCK_FILE)
        if not lock.acquire():
            result = {
                "success": True,
                "skipped": True,
                "dry_run": True,
                "tc_applied": False,
                "reason": "policy run skipped: another instance is running",
            }
            print(json.dumps(result, ensure_ascii=False))
            raise SystemExit(0)
        try:
            result = _append_policy_log(POLICY_REPORT_FILE)
            if result.get("logged"):
                dec = result.get("decision", {}) if isinstance(result.get("decision"), dict) else {}
                result["mode"] = dec.get("to") or "balanced"
                result["changed"] = bool(dec.get("changed", False))
                result["reason"] = dec.get("reason", "")
                result["current_mode"] = dec.get("to") or "balanced"
                result["last_change_ts"] = 0
                result["last_run_ts"] = result.get("time", 0)
                result["actions"] = [{"mode": result["mode"], "reason": result["reason"]}]
                result["success"] = True
        except Exception as exc:
            result = {"success": False, "error": str(exc), "mode": "balanced", "changed": False, "actions": [], "reason": str(exc)}
        finally:
            lock.release()
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
    elif args.diag:
        result = traffic_classifier.scan_conntrack(min_bytes=args.min_bytes)
        print(json.dumps(result, ensure_ascii=False))
        raise SystemExit(0 if result.get("success") else 1)
    elif args.unknown_tail > 0:
        result = unknown_flow_logger.tail_unknown_flows(limit=args.unknown_tail)
        print(json.dumps(result, ensure_ascii=False))
        raise SystemExit(0 if result.get("success") else 1)
    elif args.rules == "list":
        result = rule_manager.list_rules(ctl.config_manager.config_path)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        raise SystemExit(0 if result["count"] > 0 else 1)
    elif args.rules == "summary":
        result = rule_manager.get_rule_summary(ctl.config_manager.config_path)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        raise SystemExit(0)
    elif args.rules == "validate":
        result = rule_manager.list_rules(ctl.config_manager.config_path)
        if result["errors"]:
            print(json.dumps({"valid": False, "errors": result["errors"]}, ensure_ascii=False, indent=2))
        else:
            print(json.dumps({"valid": True, "count": result["count"], "message": "all rules valid"}, ensure_ascii=False))
        raise SystemExit(0 if not result["errors"] else 1)
    elif args.analyze:
        result = traffic_analyzer.full_analysis(dev="ifb0", state_key="cli")
        print(json.dumps(result, ensure_ascii=False, indent=2))
        raise SystemExit(0 if result.get("success") else 1)
    elif args.congestion:
        result = congestion_detector.detect_live()
        print(json.dumps(result, ensure_ascii=False, indent=2))
        raise SystemExit(0 if result.get("level") != "severe" else 1)
    elif args.decision:
        chain = _run_policy_chain(
            state_key="cli",
            dry_run=True,
            refresh_dns=False,
            scan_conntrack=False,
        )
        result = chain.get("decision", {})
        print(json.dumps(result, ensure_ascii=False, indent=2))
        raise SystemExit(0 if result.get("success") else 1)
    elif args.allocate:
        adaptive = _get_adaptive_params()
        decision = decision_state.load_state()
        traffic = traffic_analyzer.full_analysis(dev="ifb0", state_key="cli")
        congestion = congestion_detector.detect_live()
        result = adaptive_allocator.allocate_full(
            decision_result={"decision": {"to": decision.get("current_mode", "balanced")}, "state": decision},
            traffic_result=traffic,
            congestion_result=congestion,
            total_bandwidth_kbps=adaptive.get("download_kbps"),
            policy_config=adaptive,
        )
        print(json.dumps(result, ensure_ascii=False, indent=2))
        raise SystemExit(0 if result.get("success") else 1)
    elif args.policy_status:
        ctl._reload_config(force=False)
        settings = ctl.config_manager.get_settings().get("all", {})
        up_kbps = int(settings.get("upload_speed", settings.get("upload_bandwidth", 0)) or 0)
        down_kbps = int(settings.get("download_speed", settings.get("download_bandwidth", 0)) or 0)
        qdisc = str(settings.get("queue_algorithm", "fq_codel")).strip().lower()
        chain = _run_policy_chain(
            state_key="ui_policy",
            dry_run=True,
            scan_state_path="/tmp/sqm_unknown_conntrack_state_ui.json",
            scan_record=False,
        )
        classifier_scan = chain.get("classifier_scan", {})
        congestion = chain.get("congestion", {})
        traffic = chain.get("traffic", {})
        decision = chain.get("decision", {})
        allocation = chain.get("allocation", {})
        plan = adaptive_allocator.build_tc_plan(
            allocation=allocation.get("allocation", {}),
            upload_kbps=up_kbps,
            download_kbps=down_kbps,
            qdisc=qdisc,
        )

        current = _build_policy_snapshot(
            congestion=congestion,
            traffic=traffic,
            decision=decision,
            allocation=allocation,
            dry_run=True,
            tc_applied=False,
            classifier_scan=classifier_scan,
        )

        policy_log, _policy_log_error = _load_policy_report_entries(limit=10)
        policy_log = [
            entry for entry in policy_log
            if isinstance(entry, dict) and entry.get("engine") in {"policy", "v" + "4"}
        ][:10]

        unknown_flows = []
        try:
            uf_result = unknown_flow_logger.tail_unknown_flows(limit=10)
            if isinstance(uf_result, dict) and uf_result.get("success"):
                unknown_flows = uf_result.get("flows", [])
        except Exception:
            pass

        result = {
            "success": True,
            "time": int(time.time()),
            "config": {
                "upload_kbps": up_kbps,
                "download_kbps": down_kbps,
                "qdisc": qdisc,
            },
            "current": current,
            "congestion": congestion,
            "traffic": traffic,
            "decision": decision,
            "allocation": allocation,
            "tc_plan": plan,
            "policy_log": policy_log,
            "unknown_flows": unknown_flows,
            "dns_mapper": {
                "stats": dns_mapper.get_stats(),
                "cache_snapshot": dns_mapper.get_cache_snapshot(20),
            },
        }
        print(json.dumps(result, ensure_ascii=False, indent=2))
        raise SystemExit(0)
    elif args.full_chain:
        chain = _run_policy_chain(
            state_key="cli",
            dry_run=True,
            refresh_dns=False,
            scan_conntrack=False,
        )
        result = {
            "success": True,
            "time": int(time.time()),
            "congestion": chain.get("congestion", {}),
            "traffic": chain.get("traffic", {}),
            "decision": chain.get("decision", {}),
            "allocation": chain.get("allocation", {}),
        }
        print(json.dumps(result, ensure_ascii=False, indent=2))
        raise SystemExit(0)
    elif args.policy_apply:
        ctl._reload_config(force=True)
        _qb = str(ctl.config_manager.basic_config.get("queue_backend", "auto") or "auto").strip().lower()
        _nb, _ni = nss_detect.resolve_backend(_qb)
        if _nb == "nss":
            result = {
                "success": False,
                "tc_applied": False,
                "error": "NSS 硬件模式不支持策略中心（nssfq_codel 单队列），请切换到软件模式",
                "stage": "policy_apply",
            }
            print(json.dumps(result, ensure_ascii=False, indent=2))
            raise SystemExit(1)
        lock = _BestEffortFileLock(POLICY_ONCE_LOCK_FILE)
        if not lock.acquire():
            result = {
                "success": False,
                "tc_applied": False,
                "error": "policy apply skipped: another policy instance is running",
                "stage": "policy_apply",
            }
            print(json.dumps(result, ensure_ascii=False, indent=2))
            raise SystemExit(1)
        try:
            started = time.time()
            ctl._reload_config(force=True)
            settings = ctl.config_manager.get_settings().get("all", {})
            iface = str(settings.get("interface", "eth0")).strip() or "eth0"
            up_kbps = int(settings.get("upload_speed", settings.get("upload_bandwidth", 0)) or 0)
            down_kbps = int(settings.get("download_speed", settings.get("download_bandwidth", 0)) or 0)
            qdisc = str(settings.get("queue_algorithm", "fq_codel")).strip().lower()
            chain = _run_policy_chain(dry_run=True)
            classifier_scan = chain.get("classifier_scan", {})
            congestion = chain.get("congestion", {})
            traffic = chain.get("traffic", {})
            decision = chain.get("decision", {})
            allocation = chain.get("allocation", {})

            plan = adaptive_allocator.build_tc_plan(
                allocation=allocation.get("allocation", {}),
                upload_kbps=up_kbps,
                download_kbps=down_kbps,
                qdisc=qdisc,
            )

            # 先做快照，再尝试下发；如果失败就回滚。
            tc_restore_result = {}
            state_saved = False
            tc_skipped_noop = False
            plan_diff = {}
            snapshot_expected = _expected_snapshot_count()
            snapshot = _snapshot_class_rates(upload_dev=iface)
            if len(snapshot) < snapshot_expected:
                tc_applied = False
                snapshot_error = "only {}/{} classids found, tc tree may be incomplete".format(
                    len(snapshot), snapshot_expected
                )
                logging.error("policy apply: %s", snapshot_error)
                tc_apply_result = {"applied": [], "failed": [], "not_attempted": []}
                tc_restored = False
                user_action = "建议执行 /etc/init.d/sqm-controller restart 重建 tc class tree"
            else:
                tc = TCManager(settings)
                plan_diff = _plan_snapshot_diff(plan, snapshot, upload_dev=iface)
                if not plan_diff.get("has_changes"):
                    tc_skipped_noop = True
                    tc_applied = False
                    state_saved = decision_state.save_state(decision.get("state", {}))
                    tc_apply_result = {
                        "success": True,
                        "applied": [],
                        "failed": [],
                        "not_attempted": [],
                        "commands": [],
                        "skipped": "no class rate changes needed",
                    }
                    tc_restored = False
                    snapshot_error = ""
                    user_action = "" if state_saved else "策略未变化，但状态文件保存失败；建议检查 /tmp 写权限"
                else:
                    tc_apply_result = tc.update_class_rates(plan)
                    tc_applied = tc_apply_result.get("success", False)

                if (not tc_skipped_noop) and tc_applied:
                    state_saved = decision_state.save_state(decision.get("state", {}))
                    tc_restored = False
                    snapshot_error = ""
                    user_action = "" if state_saved else "策略已下发，但状态文件保存失败；建议检查 /tmp 写权限"
                elif not tc_skipped_noop:
                    restore_targets = tc_apply_result.get("applied", [])
                    snapshot_subset = {
                        k: v for k, v in snapshot.items()
                        if v["classid"] in restore_targets
                    }
                    if snapshot_subset:
                        tc_restore_result = _restore_class_rates(tc, snapshot_subset)
                        tc_restored = tc_restore_result.get("success", False)
                    else:
                        tc_restored = True
                        tc_restore_result = {"applied": [], "failed": []}
                    snapshot_error = ""
                    user_action = (
                        ""
                        if tc_restored
                        else "建议执行 /etc/init.d/sqm-controller restart 重建 tc class tree"
                    )

            entry = _build_policy_snapshot(
                congestion=congestion,
                traffic=traffic,
                decision=decision,
                allocation=allocation,
                dry_run=False,
                tc_applied=tc_applied,
                classifier_scan=classifier_scan,
            )
            entry.update({
                "tc_plan": plan,
                "tc_snapshot": snapshot,
                "tc_apply_result": tc_apply_result,
                "tc_restored": tc_restored,
                "state_saved": state_saved,
                "tc_skipped_noop": tc_skipped_noop,
                "tc_plan_diff": plan_diff,
                "duration_ms": int(max(0.0, (time.time() - started) * 1000)),
            })
            if not tc_applied and not tc_skipped_noop:
                entry["snapshot_error"] = snapshot_error
                entry["tc_restore_result"] = tc_restore_result
            if user_action:
                entry["user_action"] = user_action
            _append_jsonl_atomic(POLICY_REPORT_FILE, entry)

            result = {
                "success": tc_applied or tc_skipped_noop,
                "tc_applied": tc_applied,
                "tc_skipped_noop": tc_skipped_noop,
                "duration_ms": entry.get("duration_ms", 0),
                "tc_snapshot": snapshot,
                "tc_apply_result": tc_apply_result,
                "tc_plan_diff": plan_diff,
                "decision": decision.get("decision", {}),
                "allocation": allocation.get("allocation", {}),
            }
            if not tc_applied and not tc_skipped_noop:
                result["snapshot_error"] = snapshot_error
                result["tc_restored"] = tc_restored
                result["tc_restore_result"] = tc_restore_result
            if user_action:
                result["user_action"] = user_action
            print(json.dumps(result, ensure_ascii=False, indent=2))
            raise SystemExit(0 if result.get("success") else 1)
        except Exception as exc:
            duration_ms = int(max(0.0, (time.time() - started) * 1000)) if 'started' in locals() else 0
            result = {"success": False, "tc_applied": False, "error": str(exc), "stage": "policy_apply", "duration_ms": duration_ms}
            try:
                _append_jsonl_atomic(POLICY_REPORT_FILE, {"time": int(time.time()), "engine": "policy", "dry_run": False, "tc_applied": False, "success": False, "error": str(exc), "stage": "policy_apply", "duration_ms": duration_ms})
            except Exception:
                pass
            print(json.dumps(result, ensure_ascii=False, indent=2))
            raise SystemExit(1)
        finally:
            lock.release()
    elif args.list_port_heuristics:
        result = _handle_list_port_heuristics()
        print(json.dumps(result, ensure_ascii=False))
        raise SystemExit(0 if result.get("success") else 1)
    elif args.list_dns_rules:
        result = _handle_list_dns_rules()
        print(json.dumps(result, ensure_ascii=False))
        raise SystemExit(0 if result.get("success") else 1)
    elif args.get_policy_log:
        entries, err = _load_policy_report_entries(limit=args.limit)
        if err:
            print(json.dumps({"success": False, "error": err.get("error", "failed")}, ensure_ascii=False))
        else:
            print(json.dumps({"success": True, "entries": entries, "limit": args.limit}, ensure_ascii=False))
        raise SystemExit(0)
    elif args.aggregate_unknowns:
        result = unknown_flow_logger.aggregate_unknown_flows(
            limit=args.limit, sort_by=args.sort_by,
        )
        print(json.dumps(result, ensure_ascii=False))
        raise SystemExit(0 if result.get("success") else 1)
    elif args.add_class_rule:
        result = _handle_class_rule_crud("add", data_file=args.class_rule_data or None)
        print(json.dumps(result, ensure_ascii=False))
        raise SystemExit(0 if result.get("success") else 1)
    elif args.update_class_rule:
        result = _handle_class_rule_crud("update", data_file=args.class_rule_data or None)
        print(json.dumps(result, ensure_ascii=False))
        raise SystemExit(0 if result.get("success") else 1)
    elif args.delete_class_rule:
        result = _handle_class_rule_crud("delete", rule_name=args.delete_class_rule)
        print(json.dumps(result, ensure_ascii=False))
        raise SystemExit(0 if result.get("success") else 1)
    elif args.export_unmatched_dns:
        dns_mapper.refresh()
        stats = dns_mapper.get_unmatched_stats(
            min_count=args.unmatched_min_count,
            limit=args.unmatched_limit,
        )
        # 组装 AI 友好的导出格式
        existing_sample = [
            {"pattern": r[0], "class": r[1]}
            for r in dns_mapper.DOMAIN_RULES[:20]
        ]
        result = {
            "title": "SQM Controller 未分类 DNS 域名分析请求",
            "instruction": (
                "你是 SQM Controller 的离线 DNS 流量分类助手。\n\n"
                "任务：只分析 unmatched 数组中列出的未分类域名，并生成可导入的 DNS 分类规则。\n\n"
                "必须严格遵守输出格式：\n"
                "1. 只返回一个 JSON 对象，不要 Markdown，不要代码块，不要解释文字。\n"
                "2. JSON 顶层必须是 {\"rules\": [...]}。\n"
                "3. rules 中每条规则必须包含且只需包含：pattern、class、confidence、reason。\n"
                "4. class 只能是 streaming、gaming、bulk、other 四者之一。\n"
                "5. confidence 必须是 0.0 到 1.0 的数字，不要写百分号或字符串。\n"
                "6. 如果没有值得新增的规则，返回 {\"rules\": []}。\n\n"
                "分类定义：\n"
                "- streaming：视频、音乐、直播、音视频会议等持续媒体流。\n"
                "- gaming：联机游戏、游戏平台登录/匹配/语音等低时延业务。\n"
                "- bulk：大文件下载、系统更新、网盘同步、应用商店、游戏 CDN 下载。\n"
                "- other：普通网页、搜索、电商、社交、AI 工具、浏览器服务、统计、遥测、证书校验、安全软件、无法确认用途的后端 API。\n\n"
                "规则生成原则：\n"
                "1. 只能基于 unmatched 中出现的域名生成规则，不要凭空添加新平台规则。\n"
                "2. 普通网页、搜索、电商、社交、AI 工具、企业官网、统计/遥测、证书 OCSP、安全软件默认归 other。\n"
                "3. 音视频会议相关域名（如 Teams、Zoom、腾讯会议、Wemeet、TRTC、会议连接/媒体/许可证/接入服务）优先归 streaming，不要归 other。\n"
                "4. 通用 CDN、云服务、WAF、GTM、APM、混淆域名、随机子域名，除非能明确识别服务归属，否则归 other 且 confidence <= 0.65。\n"
                "5. 优先参考 domain、subdomain_samples、suggested_pattern 三项一起判断；如果能看出原始业务域名，不要只根据最终 CDN/调度域名下结论。\n"
                "6. 如果 domain 或 suggested_pattern 明显带有 eo.dnse、sched、entry.v51124、queniu、cdngslb、bytedns、akadns 等 CDN/调度后缀，优先回退到更干净的业务域名；只有无法确认原始域名时，才保留该精确域名并降低 confidence。\n"
                "7. 不要过度泛化。不要把 *.com、*.cn、*.net、*.org、*.qq.com、*.baidu.com、*.aliyuncs.com、*.qcloud.com、*.cloudfront.net、*.akamai.net、*.fastly.net、*.edgesuite.net 等宽泛域名作为 pattern。\n"
                "8. 如果 suggested_pattern 是精确域名且无法确认同后缀都属于同一业务，请保留精确域名，不要擅自改成泛域名。\n"
                "9. 只有多个样本明确属于同一产品/业务时，才使用更窄的通配符，例如 *.music.126.net。\n"
                "10. Microsoft/Google/Apple/浏览器组件不等于 bulk，只有明确下载/更新/应用商店 CDN 才归 bulk。\n"
                "11. 如果某个未匹配域名明显只是已知业务的 CDN 别名，而该业务在 existing_rules_sample 中已经有覆盖规则，尽量不要重复输出等价规则；除非现有规则明显覆盖不到当前域名且补充后能提高命中。\n"
                "12. 低置信度规则宁可归 other，不要强行归 streaming/gaming/bulk。\n"
                "13. 对混淆域名、一次性调度域名、看不出稳定业务归属的域名，宁可不输出，也不要为了凑数量强行给规则。\n\n"
                "confidence 建议：\n"
                "- 0.80-0.92：明确平台和业务类型。\n"
                "- 0.65-0.79：较可能但存在混合用途。\n"
                "- 0.50-0.64：弱线索或通用服务，只建议 other。\n"
                "- 低于 0.50：不要输出该规则。\n\n"
                "reason 要简短说明判断依据，例如“Chrome 自动填充服务，属于浏览器功能”。\n\n"
                "再次提醒：输出时请优先选择更稳定、更具体、不过宽的 pattern；会议类不要归 other；能回到业务原始域名时，不要停留在 CDN 最终域名。"
            ),
            "summary": {
                "total_unmatched": stats["total_unmatched"],
                "exported_top": stats["exported_top"],
                "min_count": stats["min_count"],
                "time": stats["time"],
            },
            "existing_rules_sample": existing_sample,
            "unmatched": stats["entries"],
            "output_format": {
                "description": "请只返回如下 JSON 对象，不要附加任何解释、Markdown 或代码块。",
                "schema": {
                    "rules": [
                        {
                            "pattern": "string; 域名或窄通配符",
                            "class": "streaming|gaming|bulk|other",
                            "confidence": "number; 0.0-1.0",
                            "reason": "string; 简短中文理由",
                        }
                    ]
                },
                "example": {
                    "rules": [
                        {"pattern": "*.music.126.net", "class": "streaming", "confidence": 0.85, "reason": "网易云音乐音频CDN"},
                        {"pattern": "*.gtimg.cn", "class": "other", "confidence": 0.60, "reason": "腾讯通用CDN（地图/图片/视频混合），低置信度归 other"},
                    ],
                },
            },
        }
        print(json.dumps(result, ensure_ascii=False, indent=2))
        raise SystemExit(0)
    elif args.import_ai_dns_rules:
        data = _read_stdin_json(data_file=args.ai_rules_data or None)
        if data is None:
            result = {"success": False, "error": "no JSON data provided (stdin or --ai-rules-data required)"}
        else:
            rules_list = data if isinstance(data, list) else data.get("rules", [])
            result = dns_mapper.import_ai_rules(rules_list)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        raise SystemExit(0 if result.get("success") else 1)
    elif args.save_dns_user_rules:
        result = _handle_save_dns_user_rules(data_file=args.dns_rule_data or None)
        print(json.dumps(result, ensure_ascii=False))
        raise SystemExit(0 if result.get("success") else 1)
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
