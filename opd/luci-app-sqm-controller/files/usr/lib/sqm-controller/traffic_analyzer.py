#!/usr/bin/env python3
"""SQM Controller 业务占比统计模块。

从 tc class 统计数据中计算 gaming/streaming/bulk/other 的实时占比，
结合 unknown 流量日志估算未识别流量比例，输出主导业务和健康评估。
unknown 仅作为诊断信号，不是真实的 HTB class。
"""
import json
import os
import subprocess
import time

MODULE = "traffic_analyzer"
VERSION = "4.0"
ACTIVE = True
OFFICIAL_CLASSES = ("gaming", "streaming", "bulk", "other")

TRAFFIC_STATS_PY = "/usr/lib/sqm-controller/traffic_stats.py"
UNKNOWN_LOG = "/var/log/sqm_unknown_flows.jsonl"
UNKNOWN_WINDOW_SEC = 120  # 最近多少秒内的 unknown 日志参与统计
MIN_DOMINANT_KBPS = 10.0
MIN_DOMINANT_PCT = 10.0
CONTROL_PLANE_PORTS = {22, 53, 67, 68, 123}


def _safe_float(value, default=0.0):
    try:
        return float(value)
    except (ValueError, TypeError):
        return default


def _safe_int(value, default=0):
    try:
        return int(value)
    except (ValueError, TypeError):
        return default


def collect_from_tc(dev="ifb0", state_key="policy"):
    """调用 traffic_stats.py 获取 tc class 实时数据。"""
    cmd = ["python3", TRAFFIC_STATS_PY, "--dev", dev]
    if state_key:
        cmd.extend(["--state-key", str(state_key)])
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True, text=True, timeout=15
        )
        if proc.returncode != 0:
            return {"success": False, "error": f"traffic_stats rc={proc.returncode}", "raw": proc.stderr}
        return json.loads(proc.stdout or "{}")
    except FileNotFoundError:
        return {"success": False, "error": "traffic_stats.py not found"}
    except subprocess.TimeoutExpired:
        return {"success": False, "error": "traffic_stats timed out"}
    except Exception as exc:
        return {"success": False, "error": str(exc)}


def estimate_unknown_bytes(window_sec=None):
    """从 unknown_flows.jsonl 估算最近 unknown 流量字节数。

    文件不存在 = 无 unknown 数据，不算错误。
    文件读取/解析异常 = 返回 error 字段，上游应视为 unknown 数据不可用。
    """
    if window_sec is None:
        window_sec = UNKNOWN_WINDOW_SEC

    if not os.path.exists(UNKNOWN_LOG):
        return {"bytes": 0, "flows": 0, "window_sec": window_sec, "error": None}

    now_ts = int(time.time())
    cutoff_ts = now_ts - window_sec
    total_bytes = 0
    flow_count = 0
    parse_errors = 0
    read_error = None

    try:
        with open(UNKNOWN_LOG, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    parse_errors += 1
                    continue
                # 用日志时间戳过滤（格式: "YYYY-MM-DD HH:MM:SS"）
                try:
                    entry_time = time.mktime(time.strptime(entry.get("time", ""), "%Y-%m-%d %H:%M:%S"))
                except (ValueError, TypeError):
                    parse_errors += 1
                    continue
                if entry_time < cutoff_ts:
                    continue
                if str(entry.get("ct_mark", "")).strip().lower() in {"0x10", "0x010"}:
                    continue
                sport = _safe_int(entry.get("sport", 0))
                dport = _safe_int(entry.get("dport", 0))
                if sport in CONTROL_PLANE_PORTS or dport in CONTROL_PLANE_PORTS:
                    continue
                total_bytes += _safe_int(entry.get("bytes", 0))
                flow_count += 1
    except PermissionError:
        read_error = "permission denied reading unknown log"
    except OSError as exc:
        read_error = f"OS error reading unknown log: {exc}"
    except Exception as exc:
        read_error = f"unexpected error reading unknown log: {exc}"

    return {
        "bytes": total_bytes,
        "flows": flow_count,
        "window_sec": window_sec,
        "parse_errors": parse_errors,
        "error": read_error,
    }


def analyze(class_bytes=None, class_kbps=None, unknown_bytes=0, unknown_kbps=None):
    """计算业务占比，判断主导业务，评估健康度。

    - class_bytes: dict，各业务累计字节数（若未提供 class_kbps）
    - class_kbps: dict，各业务当前速率，优先级高于 class_bytes
    - unknown_bytes: 未识别流量累计字节数
    - unknown_kbps: 未识别流量折算速率，优先级高于 unknown_bytes
    unknown 仅作为诊断信号，不会作为独立 HTB class 输出。
    """
    values = {}
    total = 0.0

    if class_kbps and isinstance(class_kbps, dict):
        for name in OFFICIAL_CLASSES:
            v = _safe_float(class_kbps.get(name, 0))
            values[name] = v
            total += v
        data_source = "kbps"
    elif class_bytes and isinstance(class_bytes, dict):
        for name in OFFICIAL_CLASSES:
            v = _safe_int(class_bytes.get(name, 0))
            values[name] = v
            total += float(v)
        data_source = "bytes"
    else:
        for name in OFFICIAL_CLASSES:
            values[name] = 0
        data_source = "empty"
        total = 0.0

    # unknown 取值：优先用 kbps（速率），否则用 bytes
    if unknown_kbps is not None:
        unknown_val = _safe_float(unknown_kbps)
        unknown_unit = "kbps"
    else:
        unknown_val = _safe_int(unknown_bytes) if isinstance(unknown_bytes, (int, float)) else 0
        unknown_unit = "bytes"

    # unknown 诊断流通常已经落入 other class，tc total 中已经包含它。
    # 因此不能用 total + unknown_val 作为分母，否则 unknown 会被重复计入，
    # 全部未知流量也可能只显示为 50%。用 max() 保留诊断估算超过 tc
    # 瞬时采样时的保护效果，同时避免低估 unknown 占比。
    observed_total = max(total, unknown_val)

    # 各业务占比
    classes = {}
    for name in OFFICIAL_CLASSES:
        pct = round((values[name] / total * 100.0) if total > 0 else 0.0, 2)
        classes[name] = {"value": values[name], "pct": pct, "data_source": data_source}

    unknown_pct = round((unknown_val / observed_total * 100.0) if observed_total > 0 else 0.0, 2)

    # 主导业务
    dominant = "none"
    if total > 0:
        ranked = sorted(
            [name for name in OFFICIAL_CLASSES if name != "other" and values[name] > 0],
            key=lambda n: values[n],
            reverse=True,
        )
        if ranked:
            top = ranked[0]
            if data_source == "kbps" and values[top] < MIN_DOMINANT_KBPS:
                dominant = "none"
            elif classes[top]["pct"] < MIN_DOMINANT_PCT:
                dominant = "none"
            elif len(ranked) >= 2 and classes[top]["pct"] - classes[ranked[1]]["pct"] < 15:
                dominant = "mixed"
            else:
                dominant = top

    # 警告与健康度
    warning = ""
    health = "ok"
    if unknown_pct >= 30.0:
        health = "degraded"
        warning = "unknown 诊断占比过高（>=30%），策略引擎应更保守"
    elif unknown_pct >= 15.0:
        health = "caution"
        warning = "unknown 诊断占比偏高（>=15%）"

    if total == 0 and unknown_val == 0:
        health = "idle"
        warning = "无流量"

    return {
        "success": True,
        "data_source": data_source,
        "classes": classes,
        "dominant": dominant,
        "unknown": {
            "value": unknown_val,
            "unit": unknown_unit,
            "pct": unknown_pct,
            "diagnostic_only": True,
        },
        "unknown_pct": unknown_pct,
        "health": health,
        "warning": warning,
        "time": int(time.time()),
    }


def full_analysis(dev="ifb0", unknown_window_sec=None, state_key="policy"):
    """执行完整业务分析：tc 数据 + unknown 诊断。"""
    tc_data = collect_from_tc(dev, state_key=state_key)

    if not tc_data.get("success"):
        return {
            "success": False,
            "error": tc_data.get("error", "failed to collect tc data"),
            "time": int(time.time()),
        }

    # 提取各类别 kbps（当前速率，比累计 bytes 更有意义）
    class_kbps = {}
    class_bytes = {}
    tc_classes = tc_data.get("classes", {})
    for name in OFFICIAL_CLASSES:
        item = tc_classes.get(name, {})
        class_kbps[name] = _safe_float(item.get("kbps", 0))
        class_bytes[name] = _safe_int(item.get("bytes", 0))

    unknown_info = estimate_unknown_bytes(window_sec=unknown_window_sec)
    unknown_raw_bytes = unknown_info.get("bytes", 0)
    window = unknown_info.get("window_sec", UNKNOWN_WINDOW_SEC)

    # 将 unknown 累计字节折算为 kbps，与 tc class 速率统一单位
    unknown_kbps = round((unknown_raw_bytes * 8.0) / (window * 1000.0), 2) if window > 0 else 0.0

    result = analyze(class_kbps=class_kbps, unknown_kbps=unknown_kbps)

    result["device"] = dev
    result["tc_kbps"] = tc_data.get("total_kbps", 0)
    result["tc_dt"] = tc_data.get("dt", 0)
    result["tc_reset"] = bool(tc_data.get("reset", False))
    result["tc_state_key"] = tc_data.get("state_key", state_key or "default")
    result["unknown_raw_bytes"] = unknown_raw_bytes
    result["unknown_kbps"] = unknown_kbps
    result["unknown_flows_count"] = unknown_info.get("flows", 0)
    result["unknown_window_sec"] = window
    # unknown 日志读取异常 → health 降级 + warning，避免策略误判分类质量
    unknown_error = unknown_info.get("error")
    if unknown_error:
        result["health"] = "degraded"
        result["warning"] = f"unknown flow data unavailable: {unknown_error}"
        result["unknown_error"] = unknown_error
    result["unknown_parse_errors"] = unknown_info.get("parse_errors", 0)
    return result


def self_test():
    sample = full_analysis(dev="ifb0")
    return {
        "ok": sample.get("success", False),
        "module": MODULE,
        "version": VERSION,
        "active": ACTIVE,
        "time": int(time.time()),
        "sample": analyze(
            class_kbps={"gaming": 0, "streaming": 70, "bulk": 0.5, "other": 0.3},
            unknown_kbps=15.0,
        ),
    }


def main():
    import argparse
    parser = argparse.ArgumentParser(description="SQM 业务占比统计")
    parser.add_argument("--dev", default="ifb0", help="tc 设备名，默认 ifb0")
    parser.add_argument("--unknown-window", type=int, default=UNKNOWN_WINDOW_SEC,
                        help="unknown 日志回溯秒数")
    parser.add_argument("--state-key", default="policy", help="traffic_stats 独立采样状态名")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        print(json.dumps(self_test(), ensure_ascii=False, indent=2))
    else:
        result = full_analysis(
            dev=args.dev,
            unknown_window_sec=args.unknown_window,
            state_key=str(args.state_key or "").strip() or None,
        )
        print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
