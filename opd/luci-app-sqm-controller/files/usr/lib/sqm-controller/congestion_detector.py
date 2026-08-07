#!/usr/bin/env python3
"""SQM Controller 拥塞等级检测模块。

从监控数据读取 RTT/丢包/抖动，结合可配置阈值判断拥塞等级。
纯延迟高但无丢包 → mild（可能是基线高，如移动热点）。
延迟高 + 丢包/抖动 → severe。不修改任何 tc 规则。
"""
import json
import os
import time

MODULE = "congestion_detector"
VERSION = "4.0"
ACTIVE = True

MONITOR_HISTORY_FILE = "/etc/sqm_controller/monitor_history.jsonl"
MONITOR_STATE_FILE = "/tmp/sqm_controller_monitor_state.json"
UCI_CONFIG = "/etc/config/sqm_controller"

DEFAULT_THRESHOLDS = {
    "latency_high_ms": 80.0,
    "loss_high_pct": 2.0,
    "jitter_high_ms": 30.0,
}


def _float_value(data, key, default=0.0):
    try:
        return float(data.get(key, default) or default)
    except (ValueError, TypeError):
        return default


def _int_value(data, key, default=0):
    try:
        return int(data.get(key, default) or default)
    except (ValueError, TypeError):
        return default


def _read_json(path, default=None):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return data if data is not None else default
    except Exception:
        return default


def _read_monitor_history():
    """兼容读取监控历史：新格式 JSONL 按行解析；旧格式 JSON 数组整体解析。"""
    try:
        with open(MONITOR_HISTORY_FILE, "r", encoding="utf-8") as fh:
            raw = fh.read()
    except Exception:
        return None
    if not raw:
        return None
    stripped = raw.lstrip()
    if stripped.startswith("["):
        try:
            data = json.loads(raw)
            return data if isinstance(data, list) else None
        except Exception:
            return None
    history = []
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
    return history if history else None

def _parse_uci_policy(path=None):
    """简单解析 UCI 配置中 policy 段的阈值。"""
    thresholds = DEFAULT_THRESHOLDS.copy()
    path = path or UCI_CONFIG
    try:
        with open(path, "r", encoding="utf-8") as fh:
            content = fh.read()
    except Exception:
        return thresholds

    import re
    in_policy = False
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("config policy"):
            in_policy = True
            continue
        if in_policy and line.startswith("config "):
            break
        if not in_policy:
            continue
        m = re.match(r"option\s+(\w+)\s+['\"]?([\d.]+)['\"]?", line)
        if m:
            key = m.group(1)
            try:
                val = float(m.group(2))
            except ValueError:
                continue
            if key == "latency_high_ms":
                thresholds["latency_high_ms"] = val
            elif key == "loss_high_pct":
                thresholds["loss_high_pct"] = val
            elif key == "jitter_high_ms":
                thresholds["jitter_high_ms"] = val
    return thresholds


def collect_metrics():
    """从监控历史文件中读取最新一条有效指标。

    兼容三种数据格式：
    1. 单条采样点 dict（含 latency key）
    2. dict 含 points 数组
    3. JSON 数组（monitor.py --history 输出格式）

    latency 为 null 或 0 的采样点会被跳过。
    """
    data = _read_monitor_history()
    metrics = {}

    if isinstance(data, dict):
        if "latency" in data and data.get("latency") is not None:
            metrics = _extract_point(data)
        elif isinstance(data.get("points"), list):
            for point in reversed(data["points"]):
                if isinstance(point, dict) and point.get("latency") is not None:
                    metrics = _extract_point(point)
                    break
    elif isinstance(data, list):
        for point in reversed(data):
            if isinstance(point, dict) and point.get("latency") is not None:
                metrics = _extract_point(point)
                break

    # 如果历史文件没有有效数据，尝试 state 文件
    if not metrics or metrics.get("avg_rtt_ms") is None:
        state = _read_json(MONITOR_STATE_FILE, {})
        if isinstance(state, dict) and state.get("latency") is not None and state.get("latency") != 0:
            metrics = {
                "avg_rtt_ms": _float_value(state, "latency"),
                "loss_pct": _float_value(state, "loss", 0),
                "bandwidth_kbps": 0,
                "time": _int_value(state, "ts"),
            }

    # jitter 目前 monitor.py 未采集，暂设为 0
    metrics.setdefault("jitter_ms", 0.0)
    metrics.setdefault("max_rtt_ms", metrics.get("avg_rtt_ms", 0.0) * 1.5)
    return metrics


def _extract_point(point):
    """从单个采样点 dict 提取指标。"""
    return {
        "avg_rtt_ms": _float_value(point, "latency"),
        "loss_pct": _float_value(point, "loss"),
        "bandwidth_kbps": _float_value(point, "bandwidth_kbps"),
        "time": _int_value(point, "time"),
    }


def detect(metrics=None, thresholds=None):
    """判断拥塞等级。不修改任何 tc 规则。

    判断逻辑：
    - 延迟 + 丢包/抖动同时超标 → severe（真正的拥塞）
    - 仅延迟超标 → mild（可能是基线高，如移动热点、VPN）
    - 仅丢包超标 → mild；丢包达到严重阈值（默认阈值的 2 倍）→ severe
    - 全部正常 → normal

    返回 {level, score, reason, triggered_metrics}
    """
    metrics = metrics if isinstance(metrics, dict) else {}
    thresholds = thresholds if isinstance(thresholds, dict) else DEFAULT_THRESHOLDS.copy()

    avg_rtt = _float_value(metrics, "avg_rtt_ms", _float_value(metrics, "latency", 0.0))
    max_rtt = _float_value(metrics, "max_rtt_ms", avg_rtt * 1.5)
    jitter = _float_value(metrics, "jitter_ms", 0.0)
    loss = _float_value(metrics, "loss_pct", _float_value(metrics, "loss", 0.0))

    rtt_high = _float_value(thresholds, "latency_high_ms", 80.0)
    loss_high = _float_value(thresholds, "loss_high_pct", 2.0)
    jitter_high = _float_value(thresholds, "jitter_high_ms", 30.0)

    score = 0.0
    triggered = []

    # 延迟超标
    latency_exceeded = avg_rtt >= rtt_high
    latency_severe = avg_rtt >= rtt_high * 2

    if latency_exceeded:
        score += 0.35
        triggered.append("avg_rtt_high")
    if max_rtt >= rtt_high * 2.5:
        score += 0.15
        triggered.append("max_rtt_spike")

    # 丢包超标
    if loss >= loss_high:
        score += 0.35
        triggered.append("loss_high")

    # 抖动超标
    if jitter >= jitter_high:
        score += 0.15
        triggered.append("jitter_high")

    # 严重判断：需要延迟 + 至少一个其他指标同时超标
    has_loss_or_jitter = (loss >= loss_high) or (jitter >= jitter_high)
    severe_loss = loss >= loss_high * 2

    if severe_loss:
        level = "severe"
    elif latency_severe and has_loss_or_jitter:
        level = "severe"
    elif score > 0:
        level = "mild"
    else:
        level = "normal"

    if not triggered:
        reason = "normal"
    elif level == "severe":
        reason = "severe: " + ", ".join(triggered)
    else:
        reason = "mild: " + ", ".join(triggered)

    return {
        "level": level,
        "score": round(min(score, 1.0), 2),
        "reason": reason,
        "triggered_metrics": triggered,
        "readings": {
            "avg_rtt_ms": round(avg_rtt, 2),
            "max_rtt_ms": round(max_rtt, 2),
            "loss_pct": round(loss, 2),
            "jitter_ms": round(jitter, 2),
        },
        "thresholds_used": {
            "latency_high_ms": rtt_high,
            "loss_high_pct": loss_high,
            "jitter_high_ms": jitter_high,
        },
    }


def detect_live():
    """从实时监控数据 + UCI 阈值做拥塞判断。"""
    metrics = collect_metrics()
    thresholds = _parse_uci_policy()
    result = detect(metrics=metrics, thresholds=thresholds)
    result["time"] = int(time.time())
    # avg_rtt_ms 为 None 表示数据不可用；0.0 是合法值（链路空闲时）
    metrics_available = metrics.get("avg_rtt_ms") is not None
    result["metrics_source"] = "monitor_history" if metrics_available else "none"
    result["metrics_available"] = metrics_available
    if not metrics_available:
        result["warning"] = "monitor data unavailable, congestion defaults to normal"
        result["reason"] = "monitor data unavailable"
    return result


def self_test():
    # 场景1：纯延迟高（模拟移动热点）
    case1 = detect(
        metrics={"avg_rtt_ms": 259, "loss_pct": 0, "jitter_ms": 5},
        thresholds=DEFAULT_THRESHOLDS,
    )
    # 场景2：延迟+丢包都高（真实拥塞）
    case2 = detect(
        metrics={"avg_rtt_ms": 200, "loss_pct": 5, "jitter_ms": 40},
        thresholds=DEFAULT_THRESHOLDS,
    )
    # 场景3：正常
    case3 = detect(
        metrics={"avg_rtt_ms": 30, "loss_pct": 0.5, "jitter_ms": 10},
        thresholds=DEFAULT_THRESHOLDS,
    )
    return {
        "ok": True,
        "module": MODULE,
        "version": VERSION,
        "active": ACTIVE,
        "time": int(time.time()),
        "test_cases": {
            "high_latency_only": case1,
            "true_congestion": case2,
            "normal": case3,
        },
    }


def main():
    import argparse
    parser = argparse.ArgumentParser(description="SQM 拥塞等级检测")
    parser.add_argument("--live", action="store_true", help="读取实时监控数据判断")
    parser.add_argument("--self-test", action="store_true", help="运行自检")
    args = parser.parse_args()

    if args.live:
        result = detect_live()
        print(json.dumps(result, ensure_ascii=False, indent=2))
    elif args.self_test:
        print(json.dumps(self_test(), ensure_ascii=False, indent=2))
    else:
        print(json.dumps(self_test(), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
