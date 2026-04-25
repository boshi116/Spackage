#!/usr/bin/env python3
import json
import os
import subprocess


DEFAULT_URL = "https://speed.cloudflare.com/__down?bytes=50000000"


def sh(cmd):
    return subprocess.getoutput(cmd)


def run_download_speedtest():
    url = os.environ.get("SPEEDTEST_DL_URL", "").strip() or DEFAULT_URL

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
    cmd = (
        f"curl -L --connect-timeout 5 --max-time {seconds} "
        f"-o /dev/null -s -w '{fmt}' '{url}'"
    )
    out = sh(cmd).strip()

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

    # On low-bandwidth/limited test windows, size_download can be small but still valid.
    # Treat speed test as success when HTTP is OK and measured speed is positive.
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

    # bytes/s -> kbit/s
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
