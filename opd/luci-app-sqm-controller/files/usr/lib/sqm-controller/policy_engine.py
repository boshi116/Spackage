#!/usr/bin/env python3
"""旧策略入口的兼容包装器。

当前实际生效的策略入口是 main.py --policy-once / --policy-apply。
保留这个文件只是为了兼容旧命令，不再单独修改 tc class。
"""

import argparse
import json
import os
import subprocess
import sys


APP_MAIN = os.path.join(os.path.dirname(os.path.abspath(__file__)), "main.py")


def run_once(config_path=None):
    """给旧调用方转到当前 dry-run 策略路径。

    config_path 仅为兼容旧接口保留；当前控制器实际从 main.py 读取 UCI 配置。
    """
    cmd = [sys.executable or "python3", APP_MAIN, "--policy-once"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    except Exception as exc:
        return {
            "success": False,
            "legacy_entry": True,
            "dry_run": True,
            "tc_applied": False,
            "error": "legacy policy wrapper failed: {}".format(exc),
            "actions": [],
        }

    stdout = (proc.stdout or "").strip()
    stderr = (proc.stderr or "").strip()
    try:
        result = json.loads(stdout or "{}")
    except Exception:
        result = {
            "success": False,
            "error": "main.py --policy-once returned invalid JSON",
            "output": stdout,
        }

    if not isinstance(result, dict):
        result = {"success": False, "error": "invalid policy result", "output": stdout}

    result["legacy_entry"] = True
    result["legacy_note"] = "policy_engine.py is a compatibility wrapper; active engine is main.py --policy-once"
    result["dry_run"] = True
    result["tc_applied"] = False
    if stderr:
        result["stderr"] = stderr
    if proc.returncode != 0 and result.get("success", True):
        result["success"] = False
        result["error"] = result.get("error") or "main.py --policy-once failed"
    return result


def main():
    parser = argparse.ArgumentParser(description="legacy SQM policy compatibility wrapper")
    parser.add_argument("--once", action="store_true", help="accepted for compatibility")
    parser.add_argument("--config", default=None, help="accepted for compatibility")
    args = parser.parse_args()

    result = run_once(config_path=args.config)
    print(json.dumps(result, ensure_ascii=False))
    raise SystemExit(0 if result.get("success") else 1)


if __name__ == "__main__":
    main()
