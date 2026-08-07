#!/usr/bin/env python3
"""SQM Controller 策略状态机模块。

根据拥塞等级、主导业务、unknown 占比判断目标模式，
通过防抖和冷却机制避免策略频繁切换。
不修改任何 tc 规则。
"""
import json
import os
import time

MODULE = "decision_state"
VERSION = "4.0"
ACTIVE = True
DEFAULT_STATE_FILE = "/tmp/sqm_decision_state.json"
LEGACY_STATE_FILE = "/tmp/sqm_decision_state_" + "v" + "4.json"
VALID_STATES = {"auto", "balanced", "gaming", "streaming", "bulk", "live", "meeting", "download"}
PRODUCT_MODE_LABELS = {
    "auto": "智能自动",
    "balanced": "均衡模式",
    "gaming": "游戏模式",
    "live": "直播模式",
    "meeting": "会议模式",
    "download": "下载模式",
    "streaming": "直播模式",
    "bulk": "下载模式",
}

# 主导业务 → 默认目标模式（auto 模式下无拥塞时）
DOMINANT_MODE_MAP = {
    "gaming": "gaming",
    "streaming": "streaming",
    "bulk": "bulk",
    "mixed": "balanced",
    "none": "balanced",
}


def normalize_mode(mode, default="balanced"):
    mode = str(mode or default).strip().lower()
    if mode not in VALID_STATES:
        return default
    return mode


def _safe_int(value, default=0):
    try:
        return int(value)
    except (ValueError, TypeError):
        return default


def _safe_float(value, default=0.0):
    try:
        return float(value)
    except (ValueError, TypeError):
        return default


def load_state(path=DEFAULT_STATE_FILE):
    candidates = [path]
    if path == DEFAULT_STATE_FILE and LEGACY_STATE_FILE not in candidates:
        candidates.append(LEGACY_STATE_FILE)
    for candidate in candidates:
        if not candidate:
            continue
        try:
            with open(candidate, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            return data if isinstance(data, dict) else {}
        except Exception:
            continue
    return {}


def save_state(state, path=DEFAULT_STATE_FILE):
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


def evaluate_target(congestion_level, dominant_traffic, unknown_pct=0.0,
                    manual_mode=False, current_mode=None):
    """根据输入指标计算目标模式，不涉及冷却和防抖。

    参数：
    - congestion_level: "normal" | "mild" | "severe"
    - dominant_traffic: "gaming" | "streaming" | "bulk" | "mixed" | "none"
    - unknown_pct: 未识别流量诊断占比 (0-100)
    - manual_mode: 是否手动模式
    - current_mode: 当前模式（手动模式时保持不变）

    返回：{target_mode, reason, confidence}
    """
    level = str(congestion_level or "normal").strip().lower()
    dominant = str(dominant_traffic or "none").strip().lower()
    unknown = _safe_float(unknown_pct)

    if level not in {"normal", "mild", "severe"}:
        level = "normal"
    if dominant not in DOMINANT_MODE_MAP:
        dominant = "none"

    if manual_mode:
        return {
            "target_mode": normalize_mode(current_mode, "balanced"),
            "reason": "manual mode active",
            "confidence": 1.0,
        }

    # unknown > 70% 硬约束：分类不可靠，强制保守
    # severe 拥塞时仍保留拥塞保护（由 adaptive_allocator 的 balanced+severe 组合触发）
    if unknown > 70.0:
        if level == "severe":
            return {
                "target_mode": "balanced",
                "reason": "severe congestion, but classification unreliable (unknown>70%), protect low-latency with conservative floor",
                "confidence": 0.25,
            }
        return {
            "target_mode": "balanced",
            "reason": "classification unreliable (unknown traffic ratio exceeds 70%)",
            "confidence": 0.30,
        }

    # unknown 占比过高时倾向保守
    conservative = unknown >= 30.0
    base_mode = DOMINANT_MODE_MAP.get(dominant, "balanced")

    if level == "severe":
        # 严重拥塞：优先保护低时延业务
        if dominant == "gaming":
            target = "gaming"
            reason = "severe congestion, gaming traffic dominant, prioritize low latency"
        elif dominant == "streaming":
            target = "streaming"
            reason = "severe congestion, streaming traffic dominant, prioritize media"
        elif conservative:
            target = "balanced"
            reason = "severe congestion, high unknown traffic (>=30%), conservative fallback to balanced"
        else:
            target = "gaming"
            reason = "severe congestion, protect interactive traffic by default"
    elif level == "mild":
        # 轻度拥塞：倾向按主导业务调整，但 unknown 高时保守
        if conservative and base_mode != "balanced":
            target = "balanced"
            reason = f"mild congestion, dominant={dominant}, but high unknown (>=30%), fallback to balanced"
        else:
            target = base_mode
            reason = f"mild congestion, dominant={dominant}, target={target}"
    else:
        # 无拥塞：按主导业务正常分配
        if conservative and base_mode != "balanced":
            target = "balanced"
            reason = f"normal link, dominant={dominant}, but high unknown (>=30%), fallback to balanced"
        else:
            target = base_mode
            reason = f"normal link, dominant={dominant}, target={target}"

    confidence = 0.5 if conservative else 0.85
    if level == "severe":
        confidence = 0.9

    return {
        "target_mode": target,
        "reason": reason,
        "confidence": round(confidence, 2),
    }


def decide(target_mode, state=None, cooldown_min=2, debounce_count=2,
           manual_mode=False, reason="", unknown_pct=0.0):
    """根据目标模式执行状态转移，含冷却和防抖。

    参数：
    - target_mode: 目标模式（来自 evaluate_target 或手动指定）
    - state: 当前持久化状态 dict
    - cooldown_min: 冷却时间（分钟）
    - debounce_count: 连续命中次数阈值
    - manual_mode: 手动模式（不自动切换）
    - reason: 切换原因描述
    - unknown_pct: 未识别流量占比（高时增加 debounce 要求）

    返回：{from, to, changed, reason, cooldown_active, state}
    """
    now_ts = int(time.time())
    state = state if isinstance(state, dict) else {}
    current = normalize_mode(state.get("current_mode"), "balanced")
    target = normalize_mode(target_mode or current, current)

    if target == "auto":
        target = "balanced"
    if current == "auto":
        current = "balanced"

    if manual_mode:
        return {
            "from": current,
            "to": current,
            "changed": False,
            "reason": "manual mode active",
            "cooldown_active": False,
            "state": state,
        }

    unknown = _safe_float(unknown_pct)
    effective_debounce = max(1, int(debounce_count or 1))
    if unknown >= 30.0:
        effective_debounce += 1

    cooldown_sec = max(0, int(cooldown_min or 0)) * 60
    last_switch = _safe_int(state.get("last_switch_time"))
    cooldown_active = bool(cooldown_sec and last_switch and now_ts - last_switch < cooldown_sec)

    pending = str(state.get("pending_mode") or "").strip().lower()
    hits = _safe_int(state.get("pending_hits"))

    if target == current:
        pending = ""
        hits = 0
    elif target == pending:
        hits += 1
    else:
        pending = target
        hits = 1

    changed = False
    output_reason = reason or "no change"

    if target != current and not cooldown_active and hits >= effective_debounce:
        current = target
        changed = True
        pending = ""
        hits = 0
        last_switch = now_ts
        output_reason = reason or f"switch to {target}"
    elif cooldown_active:
        remaining = cooldown_sec - (now_ts - last_switch)
        output_reason = f"cooldown active ({remaining}s remaining)"
    elif target != current:
        output_reason = reason or f"debounce pending ({hits}/{effective_debounce})"

    new_state = {
        "current_mode": current,
        "pending_mode": pending,
        "pending_hits": hits,
        "last_switch_time": last_switch,
        "last_run_time": now_ts,
        "reason": output_reason,
    }

    return {
        "from": normalize_mode(state.get("current_mode"), "balanced"),
        "to": current,
        "changed": changed,
        "reason": output_reason,
        "cooldown_active": cooldown_active,
        "state": new_state,
    }


def full_decision(congestion_result=None, traffic_result=None,
                  state_path=None, cooldown_min=2, debounce_count=2,
                  dry_run=False, policy_mode="auto",
                  product_mode=None, mode_label=None):
    """执行一次完整的决策：评估目标 + 状态转移。

    参数：
    - congestion_result: congestion_detector.detect() 的输出
    - traffic_result: traffic_analyzer.analyze() 的输出
    - state_path: 持久化状态文件路径
    - cooldown_min: 冷却时间（分钟）
    - debounce_count: 防抖计数
    - dry_run: True 时只计算不保存状态文件
    - policy_mode: 内部策略模式；auto 时自动判断，其他模式按配置目标执行
    - product_mode: 用户配置的场景模式（如 live/meeting/download），仅用于展示和日志
    - mode_label: 用户可读模式名

    返回：完整决策结果 dict
    """
    state_path = state_path or DEFAULT_STATE_FILE
    prev_state = load_state(state_path)

    # 提取输入
    congestion = congestion_result if isinstance(congestion_result, dict) else {}
    traffic = traffic_result if isinstance(traffic_result, dict) else {}

    congestion_level = congestion.get("level", "normal")
    dominant = traffic.get("dominant", "none")
    unknown_pct = _safe_float(traffic.get("unknown_pct", 0))
    if traffic.get("success") is False:
        dominant = "none"
        unknown_pct = 100.0

    # 检查手动模式
    manual_mode = str(prev_state.get("manual_mode") or "").strip().lower() in ("1", "true", "yes", "on")

    configured_mode = normalize_mode(policy_mode, "auto")
    product_mode = str(product_mode or configured_mode or "auto").strip().lower()
    display_label = mode_label or PRODUCT_MODE_LABELS.get(product_mode, product_mode)

    # 评估目标模式
    if configured_mode != "auto":
        evaluation = {
            "target_mode": configured_mode,
            "reason": f"configured product mode={product_mode}, target={configured_mode}",
            "confidence": 1.0,
        }
    else:
        evaluation = evaluate_target(
            congestion_level=congestion_level,
            dominant_traffic=dominant,
            unknown_pct=unknown_pct,
            manual_mode=manual_mode,
            current_mode=prev_state.get("current_mode", "balanced"),
        )

    # 状态转移
    effective_cooldown_min = 0 if configured_mode != "auto" else cooldown_min
    effective_debounce_count = 1 if configured_mode != "auto" else debounce_count
    decision = decide(
        target_mode=evaluation["target_mode"],
        state=prev_state,
        cooldown_min=effective_cooldown_min,
        debounce_count=effective_debounce_count,
        manual_mode=manual_mode,
        reason=evaluation["reason"],
        unknown_pct=unknown_pct,
    )

    # 持久化新状态（dry_run 时跳过写入，但 new_state 仍可在返回值中使用）
    new_state = decision.get("state", {})
    if not dry_run and isinstance(new_state, dict):
        save_state(new_state, state_path)

    return {
        "success": True,
        "time": int(time.time()),
        "inputs": {
            "congestion_level": congestion_level,
            "dominant_traffic": dominant,
            "unknown_pct": unknown_pct,
            "policy_mode": configured_mode,
            "product_mode": product_mode,
            "mode_label": display_label,
        },
        "evaluation": evaluation,
        "decision": {
            "from": decision.get("from"),
            "to": decision.get("to"),
            "changed": decision.get("changed"),
            "reason": decision.get("reason"),
            "cooldown_active": decision.get("cooldown_active"),
        },
        "state": new_state,
    }


def self_test():
    now_ts = int(time.time())
    test_state = {"current_mode": "balanced", "last_switch_time": now_ts - 600}

    # 场景1：严重拥塞 + 游戏主导 → gaming
    ev1 = evaluate_target("severe", "gaming", 5.0)
    d1 = decide(ev1["target_mode"], state=test_state.copy(),
                cooldown_min=0, debounce_count=1, reason=ev1["reason"])

    # 场景2：轻度拥塞 + 流媒体主导 → streaming
    ev2 = evaluate_target("mild", "streaming", 10.0)
    d2 = decide(ev2["target_mode"], state=test_state.copy(),
                cooldown_min=0, debounce_count=1, reason=ev2["reason"])

    # 场景3：无拥塞 + 高 unknown → 退回 balanced
    ev3 = evaluate_target("normal", "gaming", 35.0)
    d3 = decide(ev3["target_mode"], state=test_state.copy(),
                cooldown_min=0, debounce_count=1, reason=ev3["reason"])

    # 场景4：防抖测试 — 需要连续命中才切换
    state4 = {"current_mode": "balanced"}
    d4a = decide("gaming", state=state4, cooldown_min=0, debounce_count=2,
                 reason="first hit")
    d4b = decide("gaming", state=d4a["state"], cooldown_min=0, debounce_count=2,
                 reason="second hit")

    return {
        "ok": True,
        "module": MODULE,
        "version": VERSION,
        "active": ACTIVE,
        "time": now_ts,
        "test_cases": {
            "severe_gaming": {"evaluation": ev1, "decision": d1},
            "mild_streaming": {"evaluation": ev2, "decision": d2},
            "normal_high_unknown": {"evaluation": ev3, "decision": d3},
            "debounce_test": {
                "first": {"changed": d4a["changed"], "state": d4a["state"]},
                "second": {"changed": d4b["changed"], "state": d4b["state"]},
            },
        },
    }


def main():
    import argparse
    parser = argparse.ArgumentParser(description="SQM 策略状态机")
    parser.add_argument("--evaluate", action="store_true", help="根据输入评估目标模式")
    parser.add_argument("--level", default="normal", choices=["normal", "mild", "severe"])
    parser.add_argument("--dominant", default="none",
                        choices=["gaming", "streaming", "bulk", "mixed", "none"])
    parser.add_argument("--unknown-pct", type=float, default=0.0)
    parser.add_argument("--decide", action="store_true", help="执行状态转移")
    parser.add_argument("--target", default="balanced",
                        choices=sorted(VALID_STATES))
    parser.add_argument("--cooldown", type=int, default=2, help="冷却时间（分钟）")
    parser.add_argument("--debounce", type=int, default=2, help="防抖计数")
    parser.add_argument("--state-file", default=DEFAULT_STATE_FILE)
    parser.add_argument("--state-json", help="JSON 格式的当前状态")
    parser.add_argument("--reset-state", action="store_true", help="重置状态文件")
    parser.add_argument("--self-test", action="store_true", help="运行自检")
    args = parser.parse_args()

    if args.reset_state:
        os.remove(args.state_file) if os.path.exists(args.state_file) else None
        print(json.dumps({"ok": True, "message": "state reset"}, ensure_ascii=False))
    elif args.evaluate:
        result = evaluate_target(args.level, args.dominant, args.unknown_pct)
        print(json.dumps(result, ensure_ascii=False, indent=2))
    elif args.decide:
        if args.state_json:
            state = json.loads(args.state_json)
        else:
            state = load_state(args.state_file)
        result = decide(args.target, state=state, cooldown_min=args.cooldown,
                        debounce_count=args.debounce, reason="cli decision",
                        unknown_pct=args.unknown_pct)
        save_state(result.get("state", {}), args.state_file)
        print(json.dumps(result, ensure_ascii=False, indent=2))
    elif args.self_test:
        print(json.dumps(self_test(), ensure_ascii=False, indent=2))
    else:
        print(json.dumps(self_test(), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
