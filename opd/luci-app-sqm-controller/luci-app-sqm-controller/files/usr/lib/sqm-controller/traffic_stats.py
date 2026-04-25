#!/usr/bin/env python3
import argparse
import json
import os
import re
import shutil
import subprocess
import time


STATE_PREFIX = "/tmp/sqm_traffic_stats_state_"
RESET_DT_MAX = 3600

UPLOAD_CLASSES = {
    "other": "1:10",
    "gaming": "1:11",
    "streaming": "1:12",
    "bulk": "1:13",
}
DOWNLOAD_CLASSES = {
    "other": "2:20",
    "gaming": "2:21",
    "streaming": "2:22",
    "bulk": "2:23",
}

RE_CLASS = re.compile(r"^\s*class\s+\S+\s+([0-9A-Fa-f:]+)\b")
RE_SENT = re.compile(r"^\s*Sent\s+(\d+)\s+bytes\s+(\d+)\s+(?:pkt|packets)\b")


def _safe_dev_name(dev):
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "_", str(dev or "").strip())
    return cleaned or "unknown"


def _state_path(dev):
    return f"{STATE_PREFIX}{_safe_dev_name(dev)}.json"


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


def _find_tc():
    tc_path = shutil.which("tc")
    if tc_path:
        return tc_path

    for candidate in ("/sbin/tc", "/usr/sbin/tc", "/usr/libexec/tc-bpf"):
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None


def _run_tc_class_show(dev):
    tc_path = _find_tc()
    if not tc_path:
        return {"ok": False, "error": "tc not found", "raw": "", "stdout": "", "stderr": ""}

    cmd = [tc_path, "-s", "class", "show", "dev", dev]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True)
    except Exception as exc:
        err = f"tc exec failed: {exc}"
        return {"ok": False, "error": err, "raw": err, "stdout": "", "stderr": ""}

    stdout = (proc.stdout or "").strip()
    stderr = (proc.stderr or "").strip()
    raw = "\n".join(part for part in (stdout, stderr) if part).strip()
    if proc.returncode != 0:
        err = stderr or f"tc command failed with rc={proc.returncode}"
        return {"ok": False, "error": err, "raw": raw, "stdout": stdout, "stderr": stderr}
    return {"ok": True, "error": "", "raw": raw, "stdout": stdout, "stderr": stderr}


def _parse_tc_class_stats(raw, classids):
    stats = {cid: {"bytes": 0, "packets": 0} for cid in classids}
    current = None
    for line in (raw or "").splitlines():
        m_class = RE_CLASS.match(line)
        if m_class:
            cid = m_class.group(1)
            current = cid if cid in stats else None
            continue

        if current is None:
            continue

        m_sent = RE_SENT.match(line)
        if m_sent:
            stats[current]["bytes"] = int(m_sent.group(1))
            stats[current]["packets"] = int(m_sent.group(2))
            continue

    return stats


def _compute_rates(current, prev_state, now_ts):
    prev_ts = prev_state.get("time")
    dt = float(now_ts) - float(prev_ts) if isinstance(prev_ts, (int, float)) else 0.0
    dt_out = round(dt, 3) if dt > 0 else 0.0

    classids = list(current.keys())
    kbps_map = {cid: 0.0 for cid in classids}
    reset = False

    if dt <= 0 or dt > RESET_DT_MAX:
        reset = True

    prev_classes = prev_state.get("classes", {}) if isinstance(prev_state, dict) else {}
    if not isinstance(prev_classes, dict):
        prev_classes = {}

    if not reset:
        for cid in classids:
            cur_bytes = int(current[cid].get("bytes", 0))
            prev_entry = prev_classes.get(cid, {})
            prev_bytes = prev_entry.get("bytes", cur_bytes)
            try:
                prev_bytes = int(prev_bytes)
            except Exception:
                prev_bytes = cur_bytes

            if cur_bytes < prev_bytes:
                reset = True
                break

            delta_bytes = cur_bytes - prev_bytes
            kbps = (delta_bytes * 8.0 / dt / 1000.0) if dt > 0 else 0.0
            kbps_map[cid] = round(max(kbps, 0.0), 2)

    if reset:
        kbps_map = {cid: 0.0 for cid in classids}

    total_kbps = round(sum(kbps_map.values()), 2)
    return {"dt": dt_out, "reset": reset, "kbps_map": kbps_map, "total_kbps": total_kbps}


def collect(dev):
    now_ts = int(time.time())
    class_map = DOWNLOAD_CLASSES if dev == "ifb0" else UPLOAD_CLASSES
    classids = list(class_map.values())

    run = _run_tc_class_show(dev)
    if not run["ok"]:
        return {
            "success": False,
            "time": now_ts,
            "dt": 0,
            "device": dev,
            "classes": {},
            "total_kbps": 0,
            "error": run["error"],
            "raw": run["raw"],
        }

    parsed = _parse_tc_class_stats(run["stdout"], classids)
    state_path = _state_path(dev)
    prev_state = _read_json(state_path, {})
    calc = _compute_rates(parsed, prev_state, now_ts)

    classes = {}
    total_kbps = calc["total_kbps"]
    for category, cid in class_map.items():
        kbps = float(calc["kbps_map"].get(cid, 0.0))
        pct = round((kbps / total_kbps * 100.0), 2) if total_kbps > 0 else 0.0
        classes[category] = {
            "classid": cid,
            "bytes": int(parsed.get(cid, {}).get("bytes", 0)),
            "packets": int(parsed.get(cid, {}).get("packets", 0)),
            "kbps": round(kbps, 2),
            "pct": pct,
        }

    _write_json(
        state_path,
        {
            "time": now_ts,
            "classes": {cid: {"bytes": int(parsed[cid]["bytes"])} for cid in classids},
        },
    )

    return {
        "success": True,
        "time": now_ts,
        "dt": calc["dt"],
        "device": dev,
        "classes": classes,
        "total_kbps": total_kbps,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dev", required=True)
    args = parser.parse_args()

    result = collect(str(args.dev).strip())
    print(json.dumps(result, ensure_ascii=False))
    raise SystemExit(0 if result.get("success") else 1)


if __name__ == "__main__":
    main()
