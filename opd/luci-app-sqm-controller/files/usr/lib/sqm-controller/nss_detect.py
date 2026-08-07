#!/usr/bin/env python3
"""NSS 硬件检测模块。

检测设备是否具备 Qualcomm NSS 硬件队列整形能力（IPQ807x 平台）：
1. 设备型号是否为 IPQ807x（IPQ8074 / 8072A / 8071A 等）
2. NSS 内核模块是否加载（kmod-qca-nss-drv-qdisc / igs）
3. nss-zk.qos 脚本是否安装（sqm-scripts-nss）
4. sqm-scripts 运行时是否可用（/etc/init.d/sqm）

环境变量钩子（测试用，不影响真机）：
    SQM_FORCE_NSS=1  强制视为 NSS 可用（模拟 IPQ807x 环境）
    SQM_FORCE_NSS=0  强制视为 NSS 不可用
"""
import os
import re
import subprocess

# IPQ807x 平台型号特征（来自 sqm-scripts-nss / 高通文档）
NSS_MODEL_PATTERN = re.compile(r"(ipq807x|ipq8074|8072a|8071a|8074a|8076a)", re.I)
# NSS 相关内核模块
NSS_KMOD_PATTERN = re.compile(r"(qca-nss|nss_drv|nss.*qdisc|nss.*igs|nss_common)", re.I)

NSS_QOS_SCRIPT = "/usr/lib/sqm/nss-zk.qos"
SQM_INIT_SCRIPT = "/etc/init.d/sqm"

# 真机可用性缓存（同进程内避免重复检测）
_CACHE = {"ts": 0, "data": None}


def _run(cmd):
    try:
        return subprocess.getoutput(cmd + " 2>/dev/null")
    except Exception:
        return ""


def get_board_model():
    """优先从设备树/系统文件读型号，失败则回退 ubus 查询。"""
    for path in ("/proc/device-tree/model", "/tmp/sysinfo/model"):
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                value = f.read().strip().rstrip("\x00").strip()
            if value:
                return value
        except Exception:
            continue
    out = _run("ubus call system board")
    m = re.search(r'"model"\s*:\s*"([^"]+)"', out)
    return m.group(1) if m else ""


def detect_nss(use_cache=True):
    """返回检测结果 dict:
    {
        available: bool,   # NSS 是否可用
        model: str,        # 设备型号
        reason: str,       # 检测结论/原因说明
    }
    """
    if use_cache and _CACHE["data"] is not None:
        return _CACHE["data"]

    env = os.environ.get("SQM_FORCE_NSS", "")
    if env == "1":
        result = {
            "available": True,
            "model": "IPQ8074 (mock)",
            "reason": "SQM_FORCE_NSS=1 模拟 NSS 环境",
        }
    elif env == "0":
        result = {
            "available": False,
            "model": "",
            "reason": "SQM_FORCE_NSS=0 模拟非 NSS 环境",
        }
    else:
        model = get_board_model()
        if not NSS_MODEL_PATTERN.search(model or ""):
            result = {
                "available": False,
                "model": model or "未知",
                "reason": "非 IPQ807x 平台，NSS 硬件加速不可用",
            }
        elif not NSS_KMOD_PATTERN.search(_run("lsmod")):
            result = {
                "available": False,
                "model": model,
                "reason": "IPQ807x 平台但未加载 NSS 内核模块，请安装 kmod-qca-nss-drv-qdisc / kmod-qca-nss-drv-igs",
            }
        elif not os.path.exists(NSS_QOS_SCRIPT):
            result = {
                "available": False,
                "model": model,
                "reason": "缺少 %s，请安装 sqm-scripts-nss（nss-zk.qos 脚本）" % NSS_QOS_SCRIPT,
            }
        elif not os.path.exists(SQM_INIT_SCRIPT):
            result = {
                "available": False,
                "model": model,
                "reason": "缺少 sqm-scripts 运行时（/etc/init.d/sqm），请 opkg install sqm-scripts",
            }
        else:
            result = {
                "available": True,
                "model": model,
                "reason": "NSS 硬件就绪，队列整形将走 nssfq_codel 硬件卸载",
            }

    _CACHE["data"] = result
    return result


def resolve_backend(configured):
    """根据用户配置（auto/software/nss）和硬件检测，决定实际后端。

    返回 (backend, info)：
        backend: "software" | "nss"
        info: 检测结果 dict，强制 nss 但失败时带 error 字段
    """
    cfg = str(configured or "auto").strip().lower()
    if cfg not in ("auto", "software", "nss"):
        cfg = "auto"

    det = detect_nss()

    if cfg == "nss":
        if det["available"]:
            return "nss", det
        return "software", dict(
            det,
            error="配置为强制 NSS 模式，但检测失败：%s（已回退软件模式运行）" % det["reason"],
        )
    if cfg == "software":
        return "software", dict(det, note="用户配置为软件模式（HTB 多类）")
    # auto
    if det["available"]:
        return "nss", dict(det, note="自动检测到 NSS 硬件，使用硬件加速队列")
    return "software", dict(det, note="自动检测未发现 NSS 硬件，使用软件模式（HTB 多类）")


if __name__ == "__main__":
    import json
    import sys
    mode = sys.argv[1] if len(sys.argv) > 1 else "auto"
    backend, info = resolve_backend(mode)
    info["resolved_backend"] = backend
    print(json.dumps(info, ensure_ascii=False, indent=2))
