#!/usr/bin/env python3
import json
import os
import shutil
import subprocess


DEFAULT_URL = "https://speed.cloudflare.com/__down?bytes=50000000"


def run_download_speedtest():
    url = os.environ.get("SPEEDTEST_DL_URL", "").strip() or DEFAULT_URL
    curl_cmd = shutil.which("curl") or "curl"

    try:
        seconds = int(os.environ.get("SPEEDTEST_SECONDS", "12").strip())
    except Exception:
        seconds = 12
    seconds = max(3, min(seconds, 60))

    fmt = (
        "http_code=%{http_code}\\n"
        "size=%{size_download}\\n"
        "speed=%{speed_download}\\n"
        "time=%{time_total}\\n"
        "url=%{url_effective}\\n"
    )
    cmd = [
        curl_cmd,
        "-L",
        "--connect-timeout",
        "5",
        "--max-time",
        str(seconds),
        "-o",
        "/dev/null",
        "-s",
        "-w",
        fmt,
        url,
    ]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, check=False).stdout.strip()
    except OSError as exc:
        return {
            "error": "测速工具不可用",
            "detail": str(exc),
            "url": url,
        }

    values = {}
    for line in out.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip()

    def get_int(key, default=0):
        try:
            return int(values.get(key, str(default)))
        except Exception:
            return default

    def get_float(key, default=0.0):
        try:
            return float(values.get(key, str(default)))
        except Exception:
            return default

    http_code = get_int("http_code", 0)
    size_download = get_int("size", 0)
    speed_bps = get_float("speed", 0.0)
    time_total = get_float("time", 0.0)
    effective_url = values.get("url", "")

    # 低带宽或测试窗口较短时，下载量可能不大，但结果仍然有效。
    # 这里只要 HTTP 正常且测得速率大于 0，就认为测速成功。
    if http_code not in (200, 206) or speed_bps <= 0:
        return {
            "error": "测速失败",
            "raw": out,
            "url": url,
            "url_effective": effective_url,
            "http_code": http_code,
            "size_download": size_download,
            "time_total": time_total,
        }

    # bytes/s 转为 kbit/s
    download_kbps = int(speed_bps * 8 / 1000)

    return {
        "download": download_kbps,
        "upload": "",
        "backend": "curl-download-only",
        "url": url,
        "url_effective": effective_url,
        "http_code": http_code,
        "size_download": size_download,
        "time_total": round(time_total, 2),
    }


if __name__ == "__main__":
    print(json.dumps(run_download_speedtest(), ensure_ascii=False))
