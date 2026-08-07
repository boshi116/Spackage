#!/usr/bin/env python3
"""SQM Controller 自适应带宽分配模块。

根据策略模式、拥塞等级、业务占比、unknown 诊断占比，
计算 gaming/streaming/bulk/other 的 rate/ceil 分配比例。
unknown 仅作为风险输入，不作为分配对象。
"""
import json
import time

MODULE = "adaptive_allocator"
VERSION = "4.0"
ACTIVE = True
OFFICIAL_CLASSES = ("gaming", "streaming", "bulk", "other")

# 各模式下的基础分配 (rate_pct)
MODE_BASE_RATES = {
    "auto":         {"gaming": 20, "streaming": 25, "bulk": 25, "other": 30},
    "normal":       {"gaming": 20, "streaming": 25, "bulk": 25, "other": 30},
    "balanced":     {"gaming": 20, "streaming": 25, "bulk": 25, "other": 30},
    "gaming":       {"gaming": 35, "streaming": 25, "bulk": 10, "other": 30},
    "streaming":    {"gaming": 18, "streaming": 38, "bulk": 14, "other": 30},
    "bulk":         {"gaming": 12, "streaming": 18, "bulk": 45, "other": 25},
    "live":         {"gaming": 15, "streaming": 42, "bulk": 13, "other": 30},
    "meeting":      {"gaming": 28, "streaming": 24, "bulk": 10, "other": 38},
    "download":     {"gaming": 10, "streaming": 15, "bulk": 50, "other": 25},
}

# 各模式下的基础 ceil
MODE_BASE_CEILS = {
    "auto":         {"gaming": 100, "streaming": 100, "bulk": 80, "other": 100},
    "normal":       {"gaming": 100, "streaming": 100, "bulk": 80, "other": 100},
    "balanced":     {"gaming": 100, "streaming": 100, "bulk": 80, "other": 100},
    "gaming":       {"gaming": 100, "streaming": 100, "bulk": 50, "other": 100},
    "streaming":    {"gaming": 100, "streaming": 100, "bulk": 60, "other": 100},
    "bulk":         {"gaming": 80, "streaming": 90, "bulk": 100, "other": 100},
    "live":         {"gaming": 100, "streaming": 100, "bulk": 55, "other": 100},
    "meeting":      {"gaming": 100, "streaming": 100, "bulk": 45, "other": 100},
    "download":     {"gaming": 80, "streaming": 90, "bulk": 100, "other": 100},
}

# 无流量业务的最小保障（避免浪费带宽）
IDLE_CLASS_FLOOR_PCT = 3

# 各业务绝对最低保障
ABSOLUTE_FLOORS = {"gaming": 8, "streaming": 10, "bulk": 3, "other": 5}


def _safe_float(value, default=0.0):
    try:
        return float(value)
    except (ValueError, TypeError):
        return default


def _safe_int(value, default=0):
    try:
        return int(float(value))
    except (ValueError, TypeError):
        return default


def _clamp_pct(value, default):
    return max(0, min(100, _safe_int(value, default)))


def _normalize_rates(rates):
    """归一化 rate_pct 到总和为 100。"""
    total = sum(max(0, int(rates.get(name, 0))) for name in OFFICIAL_CLASSES)
    if total <= 0:
        return {name: 25 for name in OFFICIAL_CLASSES}
    if total == 100:
        return {name: max(0, int(rates.get(name, 0))) for name in OFFICIAL_CLASSES}

    scale = 100.0 / total
    normalized = {}
    for name in OFFICIAL_CLASSES:
        normalized[name] = max(1, int(round(max(0, int(rates.get(name, 0))) * scale)))

    # 微调使总和恰好为 100
    diff = 100 - sum(normalized.values())
    if diff > 0:
        largest = max(OFFICIAL_CLASSES, key=lambda n: normalized[n])
        normalized[largest] += diff
    elif diff < 0:
        while sum(normalized.values()) > 100:
            largest = max(OFFICIAL_CLASSES, key=lambda n: normalized[n])
            if normalized[largest] > 1:
                normalized[largest] -= 1
            else:
                break

    return normalized


def allocate(mode="balanced", congestion="normal", class_pct=None,
             unknown_pct=0.0, total_bandwidth_kbps=None,
             policy_config=None):
    """根据策略模式和链路状态生成 rate/ceil 分配比例。

    参数：
    - mode: 策略模式 (normal/balanced/gaming/streaming/bulk)
    - congestion: 拥塞等级 (normal/mild/severe)
    - class_pct: 各业务当前占比 dict（用于识别空闲业务）
    - unknown_pct: 未识别流量诊断占比 (0-100)
    - total_bandwidth_kbps: 总带宽 kbps（影响低带宽场景策略）
    - policy_config: UCI policy/adaptive 配置，用于 floor/cap 阈值

    返回：{gaming/streaming/bulk/other: {rate_pct, ceil_pct}}
    """
    mode = str(mode or "balanced").strip().lower()
    congestion = str(congestion or "normal").strip().lower()
    unknown = _safe_float(unknown_pct)
    total_kbps = _safe_float(total_bandwidth_kbps) if total_bandwidth_kbps else None
    policy = policy_config if isinstance(policy_config, dict) else {}
    if mode not in MODE_BASE_RATES:
        mode = "balanced"
    if congestion not in ("normal", "mild", "severe"):
        congestion = "normal"

    floor_map = dict(ABSOLUTE_FLOORS)
    explicit_scene = mode in {"gaming", "streaming", "bulk", "live", "meeting", "download"}
    if not explicit_scene:
        floor_map["gaming"] = max(
            floor_map["gaming"],
            _clamp_pct(policy.get("gaming_floor_pct", floor_map["gaming"]), floor_map["gaming"]),
        )
        floor_map["streaming"] = max(
            floor_map["streaming"],
            _clamp_pct(policy.get("streaming_floor_pct", floor_map["streaming"]), floor_map["streaming"]),
        )
    elif congestion == "severe":
    # 明确场景在正常情况下保持各自分配风格，
    # 但严重拥塞时仍要保留低时延保护下限。
        floor_map["gaming"] = max(floor_map["gaming"], 12)
        floor_map["streaming"] = max(floor_map["streaming"], 12)
    floor_overflow = sum(floor_map.values()) - 100
    for name in ("streaming", "gaming"):
        if floor_overflow <= 0:
            break
        reducible = max(0, floor_map[name] - ABSOLUTE_FLOORS[name])
        take = min(reducible, floor_overflow)
        floor_map[name] -= take
        floor_overflow -= take
    bulk_cap_pct = _clamp_pct(
        policy.get("bulk_cap_pct", policy.get("bulk_ceil_pct", 100)),
        100,
    )
    unknown_high_pct = max(1.0, _safe_float(policy.get("unknown_high_pct", 30.0), 30.0))

    rates = dict(MODE_BASE_RATES.get(mode, MODE_BASE_RATES["balanced"]))
    ceils = dict(MODE_BASE_CEILS.get(mode, MODE_BASE_CEILS["balanced"]))

    # 解析各业务当前占比
    pct = {}
    if isinstance(class_pct, dict):
        for name in OFFICIAL_CLASSES:
            pct[name] = _safe_float(class_pct.get(name, 0))
    else:
        for name in OFFICIAL_CLASSES:
            pct[name] = 0.0

    # ---- 拥塞等级调整 ----
    if congestion == "severe":
        rates["gaming"] = max(rates["gaming"], 30)
        rates["streaming"] = max(rates["streaming"], 22)
        rates["bulk"] = min(rates["bulk"], 10)
        ceils["bulk"] = min(ceils["bulk"], 45)
        ceils["gaming"] = 100
        ceils["streaming"] = 100
    elif congestion == "mild":
        rates["bulk"] = min(rates["bulk"], 18)
        ceils["bulk"] = min(ceils["bulk"], 65)

    # ---- unknown 占比调整 ----
    if unknown >= unknown_high_pct:
        rates["gaming"] = max(rates["gaming"], 22)
        rates["streaming"] = max(rates["streaming"], 25)
        ceils["bulk"] = min(ceils["bulk"], 55)
    elif unknown >= (unknown_high_pct / 2.0):
        rates["gaming"] = max(rates["gaming"], 18)
        rates["streaming"] = max(rates["streaming"], 22)
        ceils["bulk"] = min(ceils["bulk"], 65)

    # ---- 空闲业务释放带宽 ----
    # 如果某个业务实际占比为 0，降低其最小分配，将带宽转移给活跃业务
    active_classes = [n for n in OFFICIAL_CLASSES if pct.get(n, 0) > 1.0]
    idle_classes = [n for n in OFFICIAL_CLASSES if pct.get(n, 0) <= 1.0]

    if idle_classes and active_classes:
        reclaimed = 0
        for name in idle_classes:
            if congestion == "severe" and name in ("gaming", "streaming"):
                continue
            # 空闲业务只保留最低保障
            floor = max(IDLE_CLASS_FLOOR_PCT, floor_map.get(name, 3))
            if rates[name] > floor:
                reclaimed += rates[name] - floor
                rates[name] = floor

        # 将回收的带宽按比例分配给活跃业务，舍入误差由归一化处理
        if reclaimed > 0 and active_classes:
            active_total = sum(rates[n] for n in active_classes)
            for name in active_classes:
                if active_total > 0:
                    share = int(round(reclaimed * rates[name] / active_total))
                    rates[name] += share

    # ---- 低带宽场景额外保护 ----
    if total_kbps is not None and total_kbps < 10000:
        rates["gaming"] = max(rates["gaming"], 25)
        rates["bulk"] = min(rates["bulk"], 15)
        ceils["bulk"] = min(ceils["bulk"], 50)

    # ---- 归一化 ----
    rates = _normalize_rates(rates)

    # ---- 保障绝对最低值（归一化后，确保不会被稀释） ----
    for name in OFFICIAL_CLASSES:
        rates[name] = max(rates[name], floor_map.get(name, 3))
    # 如果绝对最低值导致总和超过 100，按比例压缩
    overflow = sum(rates.values()) - 100
    if overflow > 0:
        candidates = [n for n in OFFICIAL_CLASSES if rates[n] > floor_map.get(n, 3)]
        while overflow > 0 and candidates:
            total_candidate = sum(rates[n] for n in candidates)
            if total_candidate == 0:
                break
            for name in list(candidates):
                reduction = max(1, int(round(overflow * rates[name] / total_candidate)))
                reduction = min(reduction, rates[name] - floor_map.get(name, 3))
                if reduction > 0:
                    rates[name] -= reduction
                    overflow -= reduction
                if rates[name] <= floor_map.get(name, 3):
                    candidates.remove(name)
                if overflow <= 0:
                    break

    # ---- UCI bulk cap：限制批量类最低保证和最高可借用上限 ----
    bulk_floor = floor_map.get("bulk", ABSOLUTE_FLOORS["bulk"])
    effective_bulk_cap = max(bulk_floor, bulk_cap_pct)
    if rates["bulk"] > effective_bulk_cap:
        reclaimed = rates["bulk"] - effective_bulk_cap
        rates["bulk"] = effective_bulk_cap
        receivers = [n for n in ("gaming", "streaming", "other") if n in rates]
        receiver_total = sum(rates[n] for n in receivers) or len(receivers)
        remaining = reclaimed
        for idx, name in enumerate(receivers):
            share = remaining if idx == len(receivers) - 1 else int(round(reclaimed * rates[name] / receiver_total))
            share = max(0, share)
            rates[name] += share
            remaining -= share
    ceils["bulk"] = min(ceils.get("bulk", 100), effective_bulk_cap)

    # 严重拥塞时把保护约束重新压实。前面的归一化和空闲释放会四舍五入，
    # 这里确保最终结果仍符合低时延保护意图。
    if congestion == "severe":
        def give(dst, amount):
            if amount <= 0:
                return 0
            rates[dst] += amount
            return amount

        def take_from(donors, amount):
            taken = 0
            for donor, minimum in donors:
                if taken >= amount:
                    break
                spare = max(0, rates.get(donor, 0) - minimum)
                if spare <= 0:
                    continue
                part = min(spare, amount - taken)
                rates[donor] -= part
                taken += part
            return taken

        if rates["bulk"] > 10:
            excess = rates["bulk"] - 10
            rates["bulk"] = 10
            if rates["gaming"] < 30:
                excess -= give("gaming", min(excess, 30 - rates["gaming"]))
            if excess > 0 and rates["streaming"] < 22:
                excess -= give("streaming", min(excess, 22 - rates["streaming"]))
            if excess > 0:
                give("other", excess)

        if rates["gaming"] < 30:
            need = 30 - rates["gaming"]
            got = take_from(
                [("bulk", floor_map.get("bulk", 3)), ("other", floor_map.get("other", 5)), ("streaming", 22)],
                need,
            )
            rates["gaming"] += got

        if rates["streaming"] < 22:
            need = 22 - rates["streaming"]
            got = take_from(
                [("bulk", floor_map.get("bulk", 3)), ("other", floor_map.get("other", 5)), ("gaming", 30)],
                need,
            )
            rates["streaming"] += got

        if rates["bulk"] > 10:
            excess = rates["bulk"] - 10
            rates["bulk"] = 10
            rates["other"] += excess
        ceils["bulk"] = min(ceils.get("bulk", 100), 45, max(10, effective_bulk_cap))

    # ---- other 最低保障 ----
    _raise_other_floor(rates, unknown, congestion)

    # ---- 组装结果 ----
    result = {}
    for name in OFFICIAL_CLASSES:
        rate = rates[name]
        ceil = max(rate, int(ceils.get(name, rate)))
        result[name] = {"rate_pct": rate, "ceil_pct": ceil}

    return result


def _raise_other_floor(rates, unknown_pct, congestion):
    """确保 other 类别不低于最低保障。

    unknown > 70 → other_min = 15
    severe      → other_min = 12
    其他         → other_min = 10

    回收顺序：bulk → streaming → gaming，每类不低于 ABSOLUTE_FLOORS。
    """
    if unknown_pct > 70:
        other_min = 15
    elif congestion == "severe":
        other_min = 12
    else:
        other_min = 10

    deficit = other_min - rates.get("other", 0)
    if deficit <= 0:
        return

    for name in ("bulk", "streaming", "gaming"):
        floor = ABSOLUTE_FLOORS.get(name, 3)
        available = max(0, rates.get(name, 0) - floor)
        take = min(deficit, available)
        if take > 0:
            rates[name] -= take
            rates["other"] += take
            deficit -= take
        if deficit <= 0:
            break


def allocate_full(decision_result=None, traffic_result=None,
                  congestion_result=None, total_bandwidth_kbps=None,
                  policy_config=None):
    """从完整决策链路生成分配方案。

    参数：
    - decision_result: decision_state.full_decision() 的输出
    - traffic_result: traffic_analyzer.analyze() 的输出
    - congestion_result: congestion_detector.detect() 的输出
    - total_bandwidth_kbps: 总带宽
    - policy_config: UCI policy/adaptive 配置

    返回：完整分配结果 dict
    """
    decision = decision_result if isinstance(decision_result, dict) else {}
    traffic = traffic_result if isinstance(traffic_result, dict) else {}
    congestion = congestion_result if isinstance(congestion_result, dict) else {}

    mode = decision.get("decision", {}).get("to") or decision.get("state", {}).get("current_mode") or "balanced"
    congestion_level = congestion.get("level", "normal")
    unknown_pct = _safe_float(traffic.get("unknown_pct", 0))

    class_pct = {}
    classes = traffic.get("classes", {})
    if isinstance(classes, dict):
        for name in OFFICIAL_CLASSES:
            item = classes.get(name, {})
            class_pct[name] = _safe_float(item.get("pct", 0)) if isinstance(item, dict) else 0.0

    allocation = allocate(
        mode=mode,
        congestion=congestion_level,
        class_pct=class_pct,
        unknown_pct=unknown_pct,
        total_bandwidth_kbps=total_bandwidth_kbps,
        policy_config=policy_config,
    )

    policy = policy_config if isinstance(policy_config, dict) else {}
    return {
        "success": True,
        "time": int(time.time()),
        "inputs": {
            "mode": mode,
            "congestion": congestion_level,
            "unknown_pct": unknown_pct,
            "total_bandwidth_kbps": total_bandwidth_kbps,
            "policy": {
                "product_mode": policy.get("product_mode"),
                "mode_label": policy.get("mode_label"),
                "gaming_floor_pct": policy.get("gaming_floor_pct"),
                "streaming_floor_pct": policy.get("streaming_floor_pct"),
                "bulk_cap_pct": policy.get("bulk_cap_pct", policy.get("bulk_ceil_pct")),
                "unknown_high_pct": policy.get("unknown_high_pct"),
            },
        },
        "allocation": allocation,
    }


# 分类 classid 映射（与 3.0 tc_manager 中 UPLOAD_CLASS_IDS / DOWNLOAD_CLASS_IDS 一致）
CLASSID_MAP = {
    "other":     {"upload": "1:10", "download": "2:20"},
    "gaming":    {"upload": "1:11", "download": "2:21"},
    "streaming": {"upload": "1:12", "download": "2:22"},
    "bulk":      {"upload": "1:13", "download": "2:23"},
}

# 默认 class 的优先级（lower = higher priority）
CLASS_PRIO = {"gaming": 10, "streaming": 20, "bulk": 30, "other": 40}


def build_tc_plan(allocation, upload_kbps, download_kbps, qdisc="fq_codel"):
    """将策略分配百分比转换为 tc class plan。

    参数：
    - allocation: allocate() 返回的 {class: {rate_pct, ceil_pct}}
    - upload_kbps: 上传总带宽 (kbps)
    - download_kbps: 下载总带宽 (kbps)
    - qdisc: 叶节点 qdisc 类型

    返回：tc_manager.update_class_rates() 兼容的 plan dict
    """
    up = max(1, int(upload_kbps or 0))
    down = max(1, int(download_kbps or 0))

    upload_classes = []
    download_classes = []

    for cls_name, classids in CLASSID_MAP.items():
        item = allocation.get(cls_name, {}) if isinstance(allocation, dict) else {}
        rate_pct = _safe_float(item.get("rate_pct", 0)) if isinstance(item, dict) else 0
        ceil_pct = _safe_float(item.get("ceil_pct", rate_pct)) if isinstance(item, dict) else rate_pct

        up_rate = max(1, int(round(up * rate_pct / 100.0)))
        up_ceil = max(up_rate, int(round(up * ceil_pct / 100.0)))
        down_rate = max(1, int(round(down * rate_pct / 100.0)))
        down_ceil = max(down_rate, int(round(down * ceil_pct / 100.0)))

        upload_classes.append({
            "classid": classids["upload"],
            "rate_kbps": up_rate,
            "ceil_kbps": up_ceil,
            "prio": CLASS_PRIO.get(cls_name, 40),
            "qdisc": qdisc,
        })
        download_classes.append({
            "classid": classids["download"],
            "rate_kbps": down_rate,
            "ceil_kbps": down_ceil,
            "prio": CLASS_PRIO.get(cls_name, 40),
            "qdisc": qdisc,
        })

    return {"upload_classes": upload_classes, "download_classes": download_classes}


def self_test():
    test_cases = {}

    # 场景1：正常 + 平衡模式
    test_cases["normal_balanced"] = allocate(
        mode="balanced", congestion="normal",
        class_pct={"gaming": 10, "streaming": 40, "bulk": 20, "other": 30},
        unknown_pct=5,
    )

    # 场景2：严重拥塞 + gaming
    test_cases["severe_gaming"] = allocate(
        mode="gaming", congestion="severe",
        class_pct={"gaming": 50, "streaming": 20, "bulk": 10, "other": 20},
        unknown_pct=10,
    )

    # 场景3：高 unknown + streaming
    test_cases["high_unknown_media"] = allocate(
        mode="streaming", congestion="mild",
        class_pct={"gaming": 5, "streaming": 45, "bulk": 10, "other": 40},
        unknown_pct=35,
    )

    # 场景4：bulk 无拥塞
    test_cases["throughput_normal"] = allocate(
        mode="bulk", congestion="normal",
        class_pct={"gaming": 5, "streaming": 15, "bulk": 60, "other": 20},
        unknown_pct=5,
    )

    # 场景5：低带宽场景
    test_cases["low_bandwidth"] = allocate(
        mode="balanced", congestion="mild",
        class_pct={"gaming": 30, "streaming": 40, "bulk": 10, "other": 20},
        unknown_pct=10, total_bandwidth_kbps=5000,
    )

    # 场景6：游戏空闲，带宽转移
    test_cases["gaming_idle"] = allocate(
        mode="balanced", congestion="normal",
        class_pct={"gaming": 0, "streaming": 50, "bulk": 30, "other": 20},
        unknown_pct=5,
    )

    # 场景7：live 模式 + mild 拥塞（直播推流场景）
    test_cases["live_mild"] = allocate(
        mode="live", congestion="mild",
        class_pct={"gaming": 5, "streaming": 55, "bulk": 10, "other": 30},
        unknown_pct=10,
    )

    # 场景8：meeting 模式 + normal（视频会议场景）
    test_cases["meeting_normal"] = allocate(
        mode="meeting", congestion="normal",
        class_pct={"gaming": 30, "streaming": 20, "bulk": 8, "other": 42},
        unknown_pct=15,
    )

    # 场景9：download 模式 + normal（大文件下载场景）
    test_cases["download_normal"] = allocate(
        mode="download", congestion="normal",
        class_pct={"gaming": 3, "streaming": 10, "bulk": 65, "other": 22},
        unknown_pct=5,
    )

    # 场景10：balanced + severe + other 被压低 → other 不低于 12
    test_cases["other_floor_severe"] = allocate(
        mode="balanced", congestion="severe",
        class_pct={"gaming": 30, "streaming": 30, "bulk": 30, "other": 10},
        unknown_pct=10,
    )

    # 场景11：unknown > 70 + severe → other 不低于 15
    test_cases["other_floor_unknown_high"] = allocate(
        mode="balanced", congestion="severe",
        class_pct={"gaming": 30, "streaming": 30, "bulk": 30, "other": 10},
        unknown_pct=75,
    )

    # 场景12：gaming severe + bulk dominant → 优先从 bulk 回收，gaming 不低于自身 floor
    test_cases["severe_bulk_heavy"] = allocate(
        mode="gaming", congestion="severe",
        class_pct={"gaming": 5, "streaming": 10, "bulk": 80, "other": 5},
        unknown_pct=5,
    )

    # 验证约束
    errors = []
    for case_name, alloc in test_cases.items():
        total_rate = sum(v["rate_pct"] for v in alloc.values())
        if total_rate != 100:
            errors.append(f"{case_name}: rate sum={total_rate}")
        for cls, vals in alloc.items():
            if vals["ceil_pct"] < vals["rate_pct"]:
                errors.append(f"{case_name}/{cls}: ceil < rate")
            if vals["rate_pct"] <= 0:
                errors.append(f"{case_name}/{cls}: rate <= 0")
        # other floor 约束检查
        other_rate = alloc.get("other", {}).get("rate_pct", 0)
        if "other_floor_unknown_high" in case_name and other_rate < 15:
            errors.append(f"{case_name}: other={other_rate} < 15 (unknown>70 floor)")
        if "other_floor_severe" in case_name and other_rate < 12:
            errors.append(f"{case_name}: other={other_rate} < 12 (severe floor)")
        if "severe_bulk_heavy" in case_name:
            gaming_rate = alloc.get("gaming", {}).get("rate_pct", 0)
            if gaming_rate < ABSOLUTE_FLOORS["gaming"]:
                errors.append(f"{case_name}: gaming={gaming_rate} < absolute floor {ABSOLUTE_FLOORS['gaming']}")
        if case_name == "download_normal":
            bulk_rate = alloc.get("bulk", {}).get("rate_pct", 0)
            if bulk_rate < 45:
                errors.append(f"{case_name}: bulk={bulk_rate} < 45 (download mode should favor bulk)")
        if case_name == "live_mild":
            streaming_rate = alloc.get("streaming", {}).get("rate_pct", 0)
            if streaming_rate < 40:
                errors.append(f"{case_name}: streaming={streaming_rate} < 40 (live mode should favor streaming)")
        if case_name == "meeting_normal":
            gaming_rate = alloc.get("gaming", {}).get("rate_pct", 0)
            if gaming_rate < 25:
                errors.append(f"{case_name}: gaming={gaming_rate} < 25 (meeting mode should protect low latency)")

    return {
        "ok": len(errors) == 0,
        "module": MODULE,
        "version": VERSION,
        "active": ACTIVE,
        "time": int(time.time()),
        "test_cases": test_cases,
        "errors": errors,
    }


def main():
    import argparse
    parser = argparse.ArgumentParser(description="SQM 自适应带宽分配")
    parser.add_argument("--mode", default="balanced",
                        choices=list(MODE_BASE_RATES.keys()))
    parser.add_argument("--congestion", default="normal",
                        choices=["normal", "mild", "severe"])
    parser.add_argument("--unknown-pct", type=float, default=0.0)
    parser.add_argument("--gaming-pct", type=float, default=20.0)
    parser.add_argument("--streaming-pct", type=float, default=25.0)
    parser.add_argument("--bulk-pct", type=float, default=25.0)
    parser.add_argument("--other-pct", type=float, default=30.0)
    parser.add_argument("--total-kbps", type=float, default=None)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        print(json.dumps(self_test(), ensure_ascii=False, indent=2))
    else:
        class_pct = {
            "gaming": args.gaming_pct,
            "streaming": args.streaming_pct,
            "bulk": args.bulk_pct,
            "other": args.other_pct,
        }
        result = allocate(
            mode=args.mode,
            congestion=args.congestion,
            class_pct=class_pct,
            unknown_pct=args.unknown_pct,
            total_bandwidth_kbps=args.total_kbps,
        )
        print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
