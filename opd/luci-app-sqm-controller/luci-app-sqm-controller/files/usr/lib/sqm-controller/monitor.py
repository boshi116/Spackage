#!/usr/bin/env python3
import argparse
import json
import os
import glob
import re
import subprocess
import time


PING_HOST = "8.8.8.8"
STATE_FILE = "/tmp/sqm_controller_monitor_state.json"
HISTORY_FILE = "/tmp/sqm_controller_monitor_history.json"
MAX_POINTS = 900
WINDOW_SECONDS = {"1m": 60, "5m": 300, "1h": 3600}
PING_COUNT = 4
PING_TIMEOUT = 1


def _read_json(path, default):
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if data is not None else default
    except Exception:
        return default


def _write_json(path, data):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False)
    os.replace(tmp, path)


def get_iface_total_bytes(iface):
    rx_path = f"/sys/class/net/{iface}/statistics/rx_bytes"
    tx_path = f"/sys/class/net/{iface}/statistics/tx_bytes"
    try:
        with open(rx_path, "r", encoding="utf-8") as f:
            rx = int((f.read() or "0").strip())
        with open(tx_path, "r", encoding="utf-8") as f:
            tx = int((f.read() or "0").strip())
        return rx + tx
    except Exception:
        return 0


def get_bandwidth_kbps(iface, ts, state):
    total = get_iface_total_bytes(iface)
    prev_ts = state.get("ts")
    prev_total = state.get("total")
    prev_iface = state.get("iface")
    kbps = 0.0

    if (
        prev_iface == iface
        and isinstance(prev_ts, (int, float))
        and isinstance(prev_total, int)
        and ts > prev_ts
        and total >= prev_total
    ):
        delta_bits = (total - prev_total) * 8.0
        delta_seconds = ts - float(prev_ts)
        kbps = delta_bits / delta_seconds / 1000.0 if delta_seconds > 0 else 0.0

    return round(max(kbps, 0.0), 2), total


def get_ping_stats(host=PING_HOST):
    # Keep sampling fast to avoid blocking the UI.
    # Use 4 probes so loss granularity is 25% instead of only 0/50/100.
    out = subprocess.getoutput(f"ping -c {PING_COUNT} -W {PING_TIMEOUT} {host} 2>/dev/null")

    loss = 100
    m_loss = re.search(r"(\d+)% packet loss", out)
    if m_loss:
        loss = int(m_loss.group(1))

    latency = None
    m_rtt = re.search(r"=\s*([\d\.]+)/([\d\.]+)/([\d\.]+)/", out)
    if m_rtt:
        latency = float(m_rtt.group(2))
    else:
        m_time = re.search(r"time=([\d\.]+)\s*ms", out)
        if m_time:
            latency = float(m_time.group(1))

    return latency, loss


def get_cpu_usage(state):
    usage = None
    cpu_total = None
    cpu_idle = None
    load1 = None

    try:
        with open("/proc/loadavg", "r", encoding="utf-8") as f:
            load1 = round(float((f.read().split() or ["0"])[0]), 2)
    except Exception:
        load1 = None

    try:
        with open("/proc/stat", "r", encoding="utf-8") as f:
            line = f.readline().strip()
        fields = [int(value) for value in line.split()[1:]]
        if not fields:
            return usage, load1, cpu_total, cpu_idle

        cpu_total = sum(fields)
        cpu_idle = fields[3] + (fields[4] if len(fields) > 4 else 0)

        prev_total = state.get("cpu_total")
        prev_idle = state.get("cpu_idle")
        if (
            isinstance(prev_total, int)
            and isinstance(prev_idle, int)
            and cpu_total > prev_total
            and cpu_idle >= prev_idle
        ):
            delta_total = cpu_total - prev_total
            delta_idle = cpu_idle - prev_idle
            if delta_total > 0:
                usage = round((1.0 - (delta_idle / delta_total)) * 100.0, 2)
    except Exception:
        usage = None
        cpu_total = None
        cpu_idle = None

    return usage, load1, cpu_total, cpu_idle


def get_memory_usage():
    metrics = {}
    try:
        with open("/proc/meminfo", "r", encoding="utf-8") as f:
            for line in f:
                parts = line.split(":", 1)
                if len(parts) != 2:
                    continue
                key = parts[0].strip()
                value = parts[1].strip().split()[0]
                metrics[key] = int(value)
    except Exception:
        return None, None, None

    total_kb = metrics.get("MemTotal")
    available_kb = metrics.get("MemAvailable")
    if not total_kb or available_kb is None:
        return None, None, None

    used_kb = max(total_kb - available_kb, 0)
    total_mb = round(total_kb / 1024.0, 1)
    used_mb = round(used_kb / 1024.0, 1)
    usage = round((used_kb / total_kb) * 100.0, 2) if total_kb > 0 else None
    return used_mb, total_mb, usage


def get_temperature_c():
    candidates = []

    for path in glob.glob("/sys/class/thermal/thermal_zone*/temp"):
        candidates.append(path)
    for path in glob.glob("/sys/class/hwmon/hwmon*/temp*_input"):
        candidates.append(path)

    values = []
    for path in candidates:
        try:
            with open(path, "r", encoding="utf-8") as f:
                raw = (f.read() or "").strip()
            if not raw:
                continue
            value = float(raw)
            if value > 1000:
                value = value / 1000.0
            if 0 <= value <= 150:
                values.append(value)
        except Exception:
            continue

    if not values:
        return None

    return round(max(values), 1)


def _last_valid_latency(history):
    if not isinstance(history, list):
        return None
    for item in reversed(history):
        if not isinstance(item, dict):
            continue
        value = item.get("latency")
        if value is None:
            continue
        try:
            value = float(value)
        except Exception:
            continue
        if value >= 0:
            return round(value, 3)
    return None


def collect_sample(iface):
    ts = int(time.time())
    state = _read_json(STATE_FILE, {})
    bandwidth_kbps, total_bytes = get_bandwidth_kbps(iface, ts, state)
    latency, loss = get_ping_stats()
    cpu_usage, load1, cpu_total, cpu_idle = get_cpu_usage(state)
    memory_used_mb, memory_total_mb, memory_usage = get_memory_usage()
    temperature_c = get_temperature_c()

    # If current latency probe failed, reuse the previous valid latency.
    # If no history is available, keep it as null.
    if latency is None:
        history = _read_json(HISTORY_FILE, [])
        latency = _last_valid_latency(history)

    next_state = {"iface": iface, "ts": ts, "total": total_bytes}
    if cpu_total is not None:
        next_state["cpu_total"] = cpu_total
    if cpu_idle is not None:
        next_state["cpu_idle"] = cpu_idle
    _write_json(STATE_FILE, next_state)

    return {
        "time": ts,
        "bandwidth_kbps": bandwidth_kbps,
        "bandwidth": bandwidth_kbps,
        "latency": latency,
        "loss": loss,
        "cpu_usage": cpu_usage,
        "load1": load1,
        "memory_used_mb": memory_used_mb,
        "memory_total_mb": memory_total_mb,
        "memory_usage": memory_usage,
        "temperature_c": temperature_c,
    }


def append_history(sample):
    history = _read_json(HISTORY_FILE, [])
    if not isinstance(history, list):
        history = []
    history.append(sample)
    if len(history) > MAX_POINTS:
        history = history[-MAX_POINTS:]
    _write_json(HISTORY_FILE, history)
    return history


def get_window_history(window, include_current=True, sample=None):
    if window not in WINDOW_SECONDS:
        window = "5m"

    history = _read_json(HISTORY_FILE, [])
    if not isinstance(history, list):
        history = []

    if include_current and sample is not None:
        history = append_history(sample)

    now = int(time.time())
    cutoff = now - WINDOW_SECONDS[window]
    points = [p for p in history if isinstance(p, dict) and int(p.get("time", 0)) >= cutoff]

    return {"window": window, "points": points}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--iface", default="eth0")
    parser.add_argument("--history", action="store_true")
    parser.add_argument("--window", choices=["1m", "5m", "1h"], default="5m")
    parser.add_argument("--record", action="store_true")
    args = parser.parse_args()

    sample = collect_sample(args.iface)

    if args.history:
        data = get_window_history(args.window, include_current=True, sample=sample)
        data["current"] = sample
        data["success"] = True
        print(json.dumps(data, ensure_ascii=False))
        return

    if args.record:
        append_history(sample)

    print(json.dumps(sample, ensure_ascii=False))


if __name__ == "__main__":
    main()
