#!/usr/bin/env python3
import argparse
import json
import os
import glob
import re
import subprocess
import sys
import time


STATE_FILE = "/tmp/sqm_controller_monitor_state.json"
HISTORY_FILE = "/etc/sqm_controller/monitor_history.jsonl"
MAX_POINTS = 2880
COMPACT_AT = MAX_POINTS * 2
WINDOW_SECONDS = {"1m": 60, "5m": 300, "1h": 3600, "6h": 21600, "24h": 86400}
DEFAULT_PING_HOST = "223.5.5.5"
DEFAULT_PING_COUNT = 4
DEFAULT_PING_TIMEOUT = 1
PING_HOST_PATTERN = re.compile(r"^[A-Za-z0-9.:_-]+$")


def _read_json(path, default):
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if data is not None else default
    except Exception:
        return default


def _write_json(path, data):
    d = os.path.dirname(path)
    if d and not os.path.isdir(d):
        try:
            os.makedirs(d, exist_ok=True)
        except Exception:
            pass
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False)
    os.replace(tmp, path)


def _read_history():
    """读取监控历史：新格式 JSONL 按行解析；旧格式 JSON 数组整体解析（兼容迁移）。"""
    if not os.path.exists(HISTORY_FILE):
        return []
    try:
        with open(HISTORY_FILE, "r", encoding="utf-8") as f:
            raw = f.read()
    except Exception:
        return []
    if not raw:
        return []
    stripped = raw.lstrip()
    history = []
    if stripped.startswith("["):
        # 旧版 JSON 数组
        try:
            data = json.loads(raw)
            return data if isinstance(data, list) else []
        except Exception:
            return []
    # JSONL: 每行一个样本
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
            if isinstance(item, dict):
                history.append(item)
        except Exception:
            continue
    return history


def _write_history_jsonl(history):
    """逐行写 JSONL（压缩/迁移专用，绝不写 JSON 数组）。返回 bool 表示是否成功。"""
    d = os.path.dirname(HISTORY_FILE)
    if d and not os.path.isdir(d):
        try:
            os.makedirs(d, exist_ok=True)
        except Exception:
            return False
    tmp = HISTORY_FILE + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            for item in history:
                f.write(json.dumps(item, ensure_ascii=False) + "\n")
        os.replace(tmp, HISTORY_FILE)
    except Exception:
        return False
    return True


def _migrate_legacy_history():
    """若历史文件仍是旧版 JSON 数组，迁移为 JSONL（追加前调用）。空数组也迁移。
    返回 True=无需迁移或迁移成功；False=迁移失败（调用方应停止追加，避免混合格式）。"""
    try:
        with open(HISTORY_FILE, "r", encoding="utf-8") as f:
            head = f.read(4096)
    except FileNotFoundError:
        return True
    except Exception:
        return False
    if not head or not head.lstrip().startswith("["):
        return True
    # 合法旧 JSON 数组（含空数组 []）都迁移为 JSONL 格式
    history = _read_history()
    return _write_history_jsonl(history)
def _uci_get(option, default=None):
    out = subprocess.getoutput("uci -q get " + option + " 2>/dev/null").strip()
    return out if out else default


def get_ping_config():
    host = _uci_get("sqm_controller.monitor.ping_host", DEFAULT_PING_HOST)
    if not host or not PING_HOST_PATTERN.match(host):
        host = DEFAULT_PING_HOST
    try:
        count = int(_uci_get("sqm_controller.monitor.ping_count", str(DEFAULT_PING_COUNT)) or DEFAULT_PING_COUNT)
    except ValueError:
        count = DEFAULT_PING_COUNT
    count = max(1, min(count, 10))
    try:
        timeout = int(_uci_get("sqm_controller.monitor.ping_timeout", str(DEFAULT_PING_TIMEOUT)) or DEFAULT_PING_TIMEOUT)
    except ValueError:
        timeout = DEFAULT_PING_TIMEOUT
    timeout = max(1, min(timeout, 5))
    return host, count, timeout


def get_iface_bytes(iface):
    rx_path = f"/sys/class/net/{iface}/statistics/rx_bytes"
    tx_path = f"/sys/class/net/{iface}/statistics/tx_bytes"
    try:
        with open(rx_path, "r", encoding="utf-8") as f:
            rx = int((f.read() or "0").strip())
        with open(tx_path, "r", encoding="utf-8") as f:
            tx = int((f.read() or "0").strip())
        return rx, tx
    except Exception:
        return 0, 0


def get_bandwidth_kbps(iface, ts, state):
    rx, tx = get_iface_bytes(iface)
    total = rx + tx
    prev_ts = state.get("ts")
    prev_total = state.get("total")
    prev_rx = state.get("rx")
    prev_tx = state.get("tx")
    prev_iface = state.get("iface")
    kbps = 0.0
    rx_kbps = 0.0
    tx_kbps = 0.0

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

        if isinstance(prev_rx, int) and rx >= prev_rx:
            rx_kbps = (rx - prev_rx) * 8.0 / delta_seconds / 1000.0
        if isinstance(prev_tx, int) and tx >= prev_tx:
            tx_kbps = (tx - prev_tx) * 8.0 / delta_seconds / 1000.0

    return (
        round(max(kbps, 0.0), 2),
        round(max(rx_kbps, 0.0), 2),
        round(max(tx_kbps, 0.0), 2),
        rx,
        tx,
        total,
    )


def get_ping_stats(host, count=DEFAULT_PING_COUNT, timeout=DEFAULT_PING_TIMEOUT):
    # 采样保持轻量，避免拖慢页面刷新。
    # 这里默认发 4 个探测包，丢包粒度能细到 25%。
    out = subprocess.getoutput(f"ping -c {count} -W {timeout} {host} 2>/dev/null")

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


def collect_sample(iface):
    ts = int(time.time())
    state = _read_json(STATE_FILE, {})
    bandwidth_kbps, rx_kbps, tx_kbps, rx_bytes, tx_bytes, total_bytes = get_bandwidth_kbps(iface, ts, state)
    ping_host, ping_count, ping_timeout = get_ping_config()
    latency, loss = get_ping_stats(ping_host, ping_count, ping_timeout)
    cpu_usage, load1, cpu_total, cpu_idle = get_cpu_usage(state)
    memory_used_mb, memory_total_mb, memory_usage = get_memory_usage()
    temperature_c = get_temperature_c()

    next_state = {
        "iface": iface,
        "ts": ts,
        "rx": rx_bytes,
        "tx": tx_bytes,
        "total": total_bytes,
    }
    if cpu_total is not None:
        next_state["cpu_total"] = cpu_total
    if cpu_idle is not None:
        next_state["cpu_idle"] = cpu_idle
    _write_json(STATE_FILE, next_state)

    return {
        "time": ts,
        "bandwidth_kbps": bandwidth_kbps,
        "bandwidth": bandwidth_kbps,
        "rx_kbps": rx_kbps,
        "tx_kbps": tx_kbps,
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
    """JSONL 追加写入；追加前迁移旧格式；行数超阈值时压缩为最近 MAX_POINTS 条。"""
    if not _migrate_legacy_history():
        # 迁移失败：停止追加，避免向旧数组末尾混写 JSONL 造成格式损坏
        print("monitor: legacy history migration failed, append skipped", file=sys.stderr)
        return _read_history()
    d = os.path.dirname(HISTORY_FILE)
    if d and not os.path.isdir(d):
        try:
            os.makedirs(d, exist_ok=True)
        except Exception:
            pass
    try:
        with open(HISTORY_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(sample, ensure_ascii=False) + "\n")
    except Exception:
        return _read_history()
    # 低频压缩：避免无限增长；间隔约 MAX_POINTS*2 条才全量重写一次
    try:
        with open(HISTORY_FILE, "r", encoding="utf-8") as f:
            line_count = sum(1 for _ in f)
    except Exception:
        line_count = 0
    if line_count > COMPACT_AT:
        history = _read_history()[-MAX_POINTS:]
        if not _write_history_jsonl(history):
            print("monitor: history compaction failed (format remains JSONL)", file=sys.stderr)
    return _read_history()


def get_window_history(window, include_current=True, sample=None):
    """只读查询；include_current 时把当前样本并入内存返回，不写文件。"""
    if window not in WINDOW_SECONDS:
        window = "5m"

    history = _read_history()
    if not isinstance(history, list):
        history = []

    if include_current and sample is not None:
        history = history + [sample]

    now = int(time.time())
    cutoff = now - WINDOW_SECONDS[window]
    points = [p for p in history if isinstance(p, dict) and int(p.get("time", 0)) >= cutoff]

    return {"window": window, "points": points}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--iface", default="eth0")
    parser.add_argument("--history", action="store_true")
    parser.add_argument("--window", choices=["1m", "5m", "1h", "6h", "24h"], default="5m")
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
