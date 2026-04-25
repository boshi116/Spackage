#!/usr/bin/env python3
import argparse
import json
import os
import re
import subprocess
import time

from config_manager import ConfigManager
from tc_manager import TCManager


POLICY_STATE_FILE = "/tmp/sqm_policy_state.json"
POLICY_LOG_FILE = "/var/log/sqm_policy.jsonl"
MONITOR_STATE_FILE = "/tmp/sqm_controller_monitor_state.json"
MONITOR_HISTORY_FILE = "/tmp/sqm_controller_monitor_history.json"
MONITOR_SCRIPT = "/usr/lib/sqm-controller/monitor.py"
TRAFFIC_STATS_SCRIPT = "/usr/lib/sqm-controller/traffic_stats.py"

DEFAULT_POLICY = {
    "enabled": True,
    "mode": "auto",
    "latency_high_ms": 80,
    "loss_high_pct": 2,
    "bulk_cap_pct": 60,
    "gaming_floor_pct": 15,
    "streaming_floor_pct": 25,
    "cooldown_min": 2,
}

VALID_MODES = {"auto", "balanced", "gaming", "streaming", "bulk"}
CLASS_PRIORITY = {"gaming": 10, "streaming": 20, "bulk": 30}
CLASS_FLOW = {
    "gaming": "2:21",
    "streaming": "2:22",
    "bulk": "2:23",
}


def _read_json(path, default):
    try:
        with open(path, "r", encoding="utf-8") as file_handle:
            data = json.load(file_handle)
        return data if data is not None else default
    except Exception:
        return default


def _write_json_atomic(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp_path = path + ".tmp"
    with open(tmp_path, "w", encoding="utf-8") as file_handle:
        json.dump(data, file_handle, ensure_ascii=False)
    os.replace(tmp_path, path)


def _append_jsonl_atomic(path, item):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp_path = path + ".tmp"
    line = json.dumps(item, ensure_ascii=False) + "\n"
    old = ""
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as file_handle:
                old = file_handle.read()
        except Exception:
            old = ""
    with open(tmp_path, "w", encoding="utf-8") as file_handle:
        file_handle.write(old)
        file_handle.write(line)
    os.replace(tmp_path, path)


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


def _to_int(value, default):
    try:
        return int(str(value).strip())
    except Exception:
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
        for raw in file_handle:
            line = _strip_inline_comment(raw.strip())
            if not line:
                continue
            m_cfg = re.match(r"^config\s+([A-Za-z0-9_]+)(?:\s+(.+))?$", line)
            if m_cfg:
                current = {
                    "type": m_cfg.group(1),
                    "name": _unquote(m_cfg.group(2) or ""),
                    "options": {},
                }
                sections.append(current)
                continue
            m_opt = re.match(r"^option\s+([A-Za-z0-9_]+)\s+(.+)$", line)
            if m_opt and current is not None:
                current["options"][m_opt.group(1)] = _unquote(m_opt.group(2))
    return sections


def _get_policy_options(config_path):
    policy = DEFAULT_POLICY.copy()
    try:
        sections = _parse_uci_sections(config_path)
    except Exception:
        return policy

    for section in sections:
        if section.get("type") != "policy":
            continue
        opts = section.get("options", {})
        policy["enabled"] = _to_bool(opts.get("enabled"), policy["enabled"])
        mode = str(opts.get("mode", policy["mode"])).strip().lower()
        policy["mode"] = mode if mode in VALID_MODES else policy["mode"]
        policy["latency_high_ms"] = _to_int(opts.get("latency_high_ms"), policy["latency_high_ms"])
        policy["loss_high_pct"] = _to_int(opts.get("loss_high_pct"), policy["loss_high_pct"])
        policy["bulk_cap_pct"] = _to_int(opts.get("bulk_cap_pct"), policy["bulk_cap_pct"])
        policy["gaming_floor_pct"] = _to_int(opts.get("gaming_floor_pct"), policy["gaming_floor_pct"])
        policy["streaming_floor_pct"] = _to_int(opts.get("streaming_floor_pct"), policy["streaming_floor_pct"])
        policy["cooldown_min"] = _to_int(opts.get("cooldown_min"), policy["cooldown_min"])
        break
    return policy


def _extract_latency_loss(data):
    if not isinstance(data, dict):
        return None
    latency = data.get("latency")
    loss = data.get("loss")
    if latency is None or loss is None:
        return None
    try:
        lat_val = float(latency)
        loss_val = float(loss)
    except Exception:
        return None
    return {"latency": lat_val, "loss": loss_val}


def _monitor_from_state():
    data = _read_json(MONITOR_STATE_FILE, None)
    item = _extract_latency_loss(data)
    if item is None:
        return None
    item["source"] = MONITOR_STATE_FILE
    return item


def _monitor_from_history():
    data = _read_json(MONITOR_HISTORY_FILE, None)
    sample = None
    if isinstance(data, list) and data:
        sample = data[-1]
    elif isinstance(data, dict):
        points = data.get("points")
        if isinstance(points, list) and points:
            sample = points[-1]
        elif isinstance(data.get("current"), dict):
            sample = data.get("current")

    item = _extract_latency_loss(sample)
    if item is None:
        return None
    item["source"] = MONITOR_HISTORY_FILE
    return item


def _monitor_by_script(iface):
    cmd = ["python3", MONITOR_SCRIPT, "--iface", iface, "--record"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True)
    except Exception as exc:
        return None, {"error": f"monitor.py exec failed: {exc}", "raw": ""}
    stdout = (proc.stdout or "").strip()
    stderr = (proc.stderr or "").strip()
    raw = "\n".join(part for part in (stdout, stderr) if part).strip()
    if proc.returncode != 0:
        return None, {"error": f"monitor.py failed: rc={proc.returncode}", "raw": raw}
    try:
        data = json.loads(stdout or "{}")
    except Exception:
        return None, {"error": "monitor.py returned invalid json", "raw": raw}
    item = _extract_latency_loss(data)
    if item is None:
        return None, {"error": "monitor data lacks latency/loss", "raw": raw}
    item["source"] = "monitor.py"
    return item, None


def _collect_monitor_current(iface):
    item = _monitor_from_state()
    if item is not None:
        return item, None

    item = _monitor_from_history()
    if item is not None:
        return item, None

    return _monitor_by_script(iface)


def _collect_traffic_stats():
    cmd = ["python3", TRAFFIC_STATS_SCRIPT, "--dev", "ifb0"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True)
    except Exception as exc:
        return None, {"error": f"traffic_stats.py exec failed: {exc}", "raw": ""}
    stdout = (proc.stdout or "").strip()
    stderr = (proc.stderr or "").strip()
    raw = "\n".join(part for part in (stdout, stderr) if part).strip()
    if proc.returncode != 0:
        return None, {"error": f"traffic_stats.py failed: rc={proc.returncode}", "raw": raw}
    try:
        data = json.loads(stdout or "{}")
    except Exception:
        return None, {"error": "traffic_stats.py returned invalid json", "raw": raw}
    if not data.get("success"):
        return None, {"error": data.get("error", "traffic_stats.py returned success=false"), "raw": data.get("raw", raw)}
    return data, None


def _clamp_pct(value):
    try:
        v = int(value)
    except Exception:
        v = 0
    return max(1, min(v, 95))


def _alloc_shares(target_mode, policy):
    gaming_floor = _clamp_pct(policy["gaming_floor_pct"])
    streaming_floor = _clamp_pct(policy["streaming_floor_pct"])
    bulk_cap = _clamp_pct(policy["bulk_cap_pct"])

    if target_mode == "gaming":
        shares = {"gaming": max(gaming_floor, 60), "streaming": max(streaming_floor, 20), "bulk": min(bulk_cap, 20)}
    elif target_mode == "streaming":
        shares = {"gaming": max(gaming_floor, 20), "streaming": max(streaming_floor, 60), "bulk": min(bulk_cap, 20)}
    elif target_mode == "bulk":
        shares = {"gaming": max(gaming_floor, 10), "streaming": max(streaming_floor, 15), "bulk": min(bulk_cap, 70)}
    else:
        shares = {"gaming": max(gaming_floor, 20), "streaming": max(streaming_floor, 25), "bulk": min(bulk_cap, 40)}

    total = shares["gaming"] + shares["streaming"] + shares["bulk"]
    if total > 95:
        scale = 95.0 / total
        for key in shares:
            shares[key] = max(1, int(round(shares[key] * scale)))
    return shares


def _resolve_mode(policy_mode, monitor_current, traffic_stats, policy):
    if policy_mode != "auto":
        return policy_mode, f"manual mode={policy_mode}", False

    latency = float(monitor_current.get("latency", 0))
    loss = float(monitor_current.get("loss", 0))
    lat_hi = max(1.0, float(policy.get("latency_high_ms", 80)))
    loss_hi = max(0.1, float(policy.get("loss_high_pct", 2)))
    severe = latency >= (lat_hi * 2.0) or loss >= (loss_hi * 2.0)

    if severe:
        return "gaming", "severe congestion", True
    if latency >= lat_hi or loss >= loss_hi:
        return "balanced", "congestion detected", False

    classes = traffic_stats.get("classes", {}) if isinstance(traffic_stats, dict) else {}
    s_pct = float(classes.get("streaming", {}).get("pct", 0) or 0)
    g_pct = float(classes.get("gaming", {}).get("pct", 0) or 0)
    b_pct = float(classes.get("bulk", {}).get("pct", 0) or 0)

    if s_pct >= 40 and s_pct >= g_pct:
        return "streaming", "streaming dominant", False
    if g_pct >= 30 and g_pct > s_pct:
        return "gaming", "gaming dominant", False
    if b_pct >= 50:
        return "bulk", "bulk dominant", False
    return "balanced", "normal balanced state", False


def _build_plan(settings, target_mode, policy):
    down_total = _to_int(settings.get("download_speed", settings.get("download_bandwidth", 0)), 0)
    if down_total <= 0:
        down_total = 1000

    qdisc = str(settings.get("queue_algorithm", "fq_codel")).strip().lower()
    if qdisc not in ("fq_codel", "cake"):
        qdisc = "fq_codel"

    shares = _alloc_shares(target_mode, policy)
    download_classes = []
    for category in ("gaming", "streaming", "bulk"):
        share_pct = shares[category]
        rate = max(1, int(round(down_total * share_pct / 100.0)))
        download_classes.append(
            {
                "classid": CLASS_FLOW[category],
                "rate_kbps": rate,
                "ceil_kbps": rate,
                "prio": CLASS_PRIORITY[category],
                "qdisc": qdisc,
            }
        )

    return {"upload_classes": [], "download_classes": download_classes}


def run_once(config_path=None):
    now_ts = int(time.time())
    result = {"success": False, "mode": "", "reason": "", "actions": [], "changed": False}

    def _finalize(payload):
        if not isinstance(payload, dict):
            payload = {"success": False, "error": "invalid policy result", "changed": False}
        if not isinstance(payload.get("actions"), list):
            payload["actions"] = []
        return payload

    cfg = ConfigManager(config_path=config_path)
    cfg.load_config()
    settings = cfg.get_settings().get("all", {})
    iface = str(settings.get("interface", "eth0")).strip() or "eth0"
    policy = _get_policy_options(cfg.config_path)

    if not policy.get("enabled", False):
        result.update({"success": True, "mode": "disabled", "reason": "policy disabled", "changed": False})
        return _finalize(result)

    monitor_current, monitor_err = _collect_monitor_current(iface)
    if monitor_err:
        result["error"] = monitor_err["error"]
        result["details"] = {"raw": monitor_err.get("raw", "")}
        return _finalize(result)

    traffic_stats, traffic_err = _collect_traffic_stats()
    if traffic_err:
        result["error"] = traffic_err["error"]
        result["details"] = {"raw": traffic_err.get("raw", "")}
        return _finalize(result)

    policy_state = _read_json(POLICY_STATE_FILE, {})
    current_mode = str(policy_state.get("current_mode", "")).strip().lower()
    last_change_ts = int(policy_state.get("last_change_ts", 0) or 0)

    target_mode, reason, severe_override = _resolve_mode(policy["mode"], monitor_current, traffic_stats, policy)
    result["mode"] = target_mode
    result["reason"] = reason

    cooldown_sec = max(0, _to_int(policy.get("cooldown_min", 0), 0)) * 60
    elapsed = now_ts - last_change_ts if last_change_ts > 0 else 10**9

    should_change = (not current_mode) or (target_mode != current_mode)
    if should_change and cooldown_sec > 0 and elapsed < cooldown_sec and not severe_override:
        should_change = False
        result["reason"] = f"cooldown active: {elapsed}s < {cooldown_sec}s"

    plan = _build_plan(settings, target_mode, policy)
    if should_change:
        tc = TCManager(settings)
        ok = tc.apply_classes(plan)
        if not ok:
            result["error"] = "tc.apply_classes failed"
            result["details"] = {"plan": plan}
            return _finalize(result)
        result["changed"] = True
        result["actions"] = [{"type": "apply_classes", "mode": target_mode, "download_classes": plan["download_classes"]}]

    new_state = {
        "current_mode": target_mode if should_change else (current_mode or target_mode),
        "last_change_ts": now_ts if should_change else last_change_ts,
        "last_run_ts": now_ts,
        "reason": result["reason"],
        "actions": result["actions"],
    }
    _write_json_atomic(POLICY_STATE_FILE, new_state)

    log_item = {
        "time": now_ts,
        "inputs": {
            "policy": policy,
            "monitor": monitor_current,
            "traffic_stats": {
                "total_kbps": traffic_stats.get("total_kbps", 0),
                "classes": traffic_stats.get("classes", {}),
            },
        },
        "decision": {"mode": target_mode, "reason": result["reason"]},
        "changed": result["changed"],
        "actions": result["actions"],
    }
    _append_jsonl_atomic(POLICY_LOG_FILE, log_item)

    result["success"] = True
    return _finalize(result)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--once", action="store_true", help="run policy once")
    parser.add_argument("--config", default=None)
    args = parser.parse_args()

    # Default behavior is one-shot execution even without --once.
    _ = args.once
    result = run_once(config_path=args.config)
    print(json.dumps(result, ensure_ascii=False))
    raise SystemExit(0 if result.get("success") else 1)


if __name__ == "__main__":
    main()
