#!/usr/bin/env python3
"""SQM Controller 未识别流量日志模块。"""
import json
import os
import time


MODULE = "unknown_flow_logger"
VERSION = "4.0"
ACTIVE = True
DEFAULT_LOG_FILE = "/var/log/sqm_unknown_flows.jsonl"


def _to_int(value, default=0):
    try:
        return int(value)
    except Exception:
        return default


def _to_float(value, default=0.0):
    try:
        return float(value)
    except Exception:
        return default


def normalize_flow(flow):
    """把一条未识别流量记录整理成统一格式。"""
    flow = flow if isinstance(flow, dict) else {}
    now = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    confidence = max(0.0, min(_to_float(flow.get("confidence", 0.0)), 1.0))
    return {
        "time": str(flow.get("time") or now),
        "src": str(flow.get("src", "")),
        "dst": str(flow.get("dst", "")),
        "proto": str(flow.get("proto", "")).lower(),
        "sport": _to_int(flow.get("sport", 0)),
        "dport": _to_int(flow.get("dport", 0)),
        "bytes": max(0, _to_int(flow.get("bytes", 0))),
        "duration": max(0, _to_int(flow.get("duration", 0))),
        "guess": str(flow.get("guess", "unknown")).lower(),
        "confidence": confidence,
        "reason": str(flow.get("reason", "unknown flow logger")),
    }


# 日志轮转参数
ROTATE_MAX_BYTES = 2 * 1024 * 1024   # 2MB 触发轮转
ROTATE_BACKUP_COUNT = 3               # 保留 .1 / .2 / .3


def _rotate_log(path):
    """轮转 JSONL 日志文件：path → path.1 → path.2 → path.3。

    轮转失败不抛异常，不影响主流程。
    """
    try:
        # 删除最旧的备份
        oldest = f"{path}.{ROTATE_BACKUP_COUNT}"
        try:
            os.remove(oldest)
        except FileNotFoundError:
            pass
        except OSError:
            pass
        # 依次后移备份文件，最后把当前文件转成 .1
        for i in range(ROTATE_BACKUP_COUNT - 1, 0, -1):
            src = path if i == 1 else f"{path}.{i - 1}"
            dst = f"{path}.{i}"
            try:
                os.replace(src, dst)
            except FileNotFoundError:
                pass
            except OSError:
                pass
    except Exception:
        pass


def _should_rotate(path):
    """检查文件是否超过轮转阈值。"""
    try:
        return os.path.getsize(path) >= ROTATE_MAX_BYTES
    except OSError:
        return False


def append_unknown_flow(flow, path=DEFAULT_LOG_FILE):
    """追加一条诊断记录；失败时返回结果，不向外抛异常。

    写入前检查文件大小，超过阈值时自动轮转（current → .1 → .2 → .3）。
    """
    record = normalize_flow(flow)
    try:
        directory = os.path.dirname(path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        if _should_rotate(path):
            _rotate_log(path)
        with open(path, "a", encoding="utf-8") as file_handle:
            file_handle.write(json.dumps(record, ensure_ascii=False) + "\n")
        return {"success": True, "path": path, "record": record}
    except Exception as exc:
        return {"success": False, "path": path, "error": str(exc), "record": record}


MAX_JSONL_BYTES = 10 * 1024 * 1024      # 10MB，超过则只读尾部
MAX_JSONL_LINES = 50000                 # 最多读取行数
MAX_SAMPLE_SRC_IPS = 5

# P2P 建议规则的触发阈值
P2P_MIN_COUNT = 100          # 至少出现次数
P2P_MIN_SRC_COUNT = 20       # 至少 20 个不同外部对端
P2P_MIN_BYTES = 100 * 1024 * 1024  # 100MB
SERVICE_PORT_MIN_COUNT = 5
SERVICE_PORT_MIN_LOCAL_PORTS = 3
SERVICE_PORT_MIN_BYTES = 1024 * 1024


def _is_private_ip(ip):
    """判断 IP 是否属于私有地址 / 本地地址。"""
    if not ip or not isinstance(ip, str):
        return False
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        o1, o2 = int(parts[0]), int(parts[1])
    except Exception:
        return False
    if o1 == 10:
        return True
    if o1 == 172 and 16 <= o2 <= 31:
        return True
    if o1 == 192 and o2 == 168:
        return True
    if o1 == 127:
        return True
    if o1 == 169 and o2 == 254:
        return True
    return False


def _lookup_device(ip):
    """从 dhcp.leases / proc/net/arp 查设备 MAC 和 hostname。

    返回 {host_mac, hostname} 或 {}。
    """
    if not ip:
        return {}

    dhcp_leases = "/tmp/dhcp.leases"
    if os.path.exists(dhcp_leases):
        try:
            with open(dhcp_leases, "r", encoding="utf-8") as fh:
                for line in fh:
                    parts = line.strip().split()
                    if len(parts) >= 4 and parts[2] == ip:
                        return {"host_mac": parts[1], "hostname": parts[3]}
        except Exception:
            pass

    arp_file = "/proc/net/arp"
    if os.path.exists(arp_file):
        try:
            with open(arp_file, "r", encoding="utf-8") as fh:
                for line in fh:
                    parts = line.strip().split()
                    if len(parts) >= 4 and parts[0] == ip:
                        hw = parts[3]
                        return {"host_mac": hw, "hostname": ""}
        except Exception:
            pass

    return {}


def _generate_suggestions(entries):
    """从聚合结果中识别可疑 P2P/BT 入站端口，生成建议规则。

    仅做展示，不修改 UCI/nftables/tc。
    dst_ip 规则已支持，但 suggestions 仅用于展示，保持手动确认和 auto_apply=false。
    """
    suggestions = []
    for e in entries:
        proto = e["proto"]
        dst_ip = e["dst_ip"]
        dport = e["dport"]
        count = e["count"]
        src_count = e["src_count"]
        total_bytes = e["total_bytes"]

        # 只看 UDP 的高位端口
        if proto != "udp":
            continue
        if dport < 1024:
            continue
        # 目标 IP 必须是本地私有地址
        if not _is_private_ip(dst_ip):
            continue
        # 满足高频、多对端和大流量，才认为有建议价值
        if count < P2P_MIN_COUNT:
            continue
        if src_count < P2P_MIN_SRC_COUNT:
            continue
        if total_bytes < P2P_MIN_BYTES:
            continue

        device = _lookup_device(dst_ip)
        host_mac = device.get("host_mac", "")
        hostname = device.get("hostname", "")
        bindable_as = "device_port" if host_mac else "host_port"
        stability = "temporary" if not host_mac else "lease_bound"

        has_fields = bool(dst_ip and proto and dport)
        applicable = has_fields and proto == "udp" and dport >= 1024

        suggestions.append({
            "proto": proto,
            "host_ip": dst_ip,
            "dport": dport,
            "suggested_class": "bulk",
            "confidence": 0.85,
            "reason": (
                f"P2P/BT local peer port detected"
                f" ({count} flows, {total_bytes} bytes, {src_count} peers)"
            ),
            "scope": "host_port",
            "bindable_as": bindable_as,
            "stability": stability,
            "host_mac": host_mac,
            "hostname": hostname,
            "auto_apply": False,
            "applicable": applicable,
            "applicable_blocker": (
                "" if applicable
                else "missing required fields (host_ip/proto/dport)"
            ),
            "target_direction": "inbound",
            "target_rule": f"dst_ip={dst_ip}, proto={proto}, dport={dport} -> bulk",
        })
    return suggestions


def _generate_service_port_suggestions(service_groups):
    """
    识别远端服务端口固定、本地临时端口变化的入站下载型 unknown。
    """
    suggestions = []
    for g in service_groups:
        proto = g.get("proto", "")
        dst_ip = g.get("dst_ip", "")
        sport = _to_int(g.get("sport", 0))
        count = _to_int(g.get("count", 0))
        total_bytes = _to_int(g.get("total_bytes", 0))
        local_ports = g.get("local_ports", {})
        srcs = g.get("srcs", {})

        if proto not in ("tcp", "udp"):
            continue
        if sport < 1024:
            continue
        if not _is_private_ip(dst_ip):
            continue
        if count < SERVICE_PORT_MIN_COUNT:
            continue
        if len(local_ports) < SERVICE_PORT_MIN_LOCAL_PORTS:
            continue
        if total_bytes < SERVICE_PORT_MIN_BYTES:
            continue

        device = _lookup_device(dst_ip)
        host_mac = device.get("host_mac", "")
        hostname = device.get("hostname", "")
        confidence = 0.75 if total_bytes >= 5 * 1024 * 1024 else 0.65

        suggestions.append({
            "proto": proto,
            "host_ip": dst_ip,
            "sport": sport,
            "suggested_class": "bulk",
            "confidence": confidence,
            "reason": (
                "large inbound peer/service traffic detected "
                f"({count} records, {total_bytes} bytes, "
                f"{len(local_ports)} local ports, {len(srcs)} peers)"
            ),
            "scope": "host_remote_service_port",
            "bindable_as": "device_remote_service_port" if host_mac else "host_remote_service_port",
            "stability": "observed_service_port",
            "host_mac": host_mac,
            "hostname": hostname,
            "auto_apply": False,
            "applicable": True,
            "applicable_blocker": "",
            "target_direction": "inbound",
            "target_rule": f"dst_ip={dst_ip}, proto={proto}, sport={sport} -> bulk",
            "sample_local_dports": sorted(local_ports.keys())[:MAX_SAMPLE_SRC_IPS],
            "sample_src_ips": sorted(srcs.keys())[:MAX_SAMPLE_SRC_IPS],
        })
    return suggestions


def aggregate_unknown_flows(log_path=None, limit=20, sort_by="bytes"):
    """对 /var/log/sqm_unknown_flows.jsonl 做 Top N 聚合。
    key: proto + dst_ip + dport
    支持 sort_by="bytes"（找占带宽大的 unknown）和 sort_by="count"（找高频 unknown）。
    文件不存在、为空、单行损坏均不抛异常。
    """
    if log_path is None:
        log_path = DEFAULT_LOG_FILE
    try:
        limit = max(1, min(int(limit), 200))
    except Exception:
        limit = 20
    if sort_by not in ("bytes", "count"):
        sort_by = "bytes"

    if not os.path.exists(log_path):
        return {"success": True, "path": log_path, "entries": [], "sort_by": sort_by, "limit": limit}

    # 控制读取范围
    try:
        file_size = os.path.getsize(log_path)
    except Exception:
        file_size = 0

    try:
        with open(log_path, "r", encoding="utf-8") as fh:
            if file_size > MAX_JSONL_BYTES:
                # 超过 10MB 只读末尾
                fh.seek(max(0, file_size - MAX_JSONL_BYTES))
                fh.readline()  # 丢弃不完整的第一行
            lines = []
            for _ in range(MAX_JSONL_LINES):
                line = fh.readline()
                if not line:
                    break
                stripped = line.strip()
                if stripped:
                    lines.append(stripped)
    except Exception:
        return {"success": False, "path": log_path, "error": "failed to read log file", "entries": []}

    if not lines:
        return {"success": True, "path": log_path, "entries": [], "sort_by": sort_by, "limit": limit}

    # 逐行解析 + 聚合
    groups = {}  # 每组按目标维度累计次数、字节和来源集合
    service_groups = {}  # 服务侧分组：协议 + 目标 IP + 对端源端口
    for line in lines:
        try:
            rec = json.loads(line)
        except Exception:
            continue  # 损坏行跳过
        if not isinstance(rec, dict):
            continue
        proto = str(rec.get("proto", "")).lower()
        dst = str(rec.get("dst", "")).strip()
        try:
            dport = int(rec.get("dport", 0))
        except Exception:
            dport = 0
        try:
            sport = int(rec.get("sport", 0))
        except Exception:
            sport = 0
        if not proto or not dst:
            continue
        try:
            bts = max(0, int(rec.get("bytes", 0)))
        except Exception:
            bts = 0
        try:
            pkts = max(0, int(rec.get("packets", 0)))
        except Exception:
            pkts = 0
        src = str(rec.get("src", "")).strip()
        ts = str(rec.get("time", ""))
        guess = str(rec.get("guess", "unknown")).lower()
        try:
            conf = float(rec.get("confidence", 0))
        except Exception:
            conf = 0.0

        key = (proto, dst, dport)
        if key not in groups:
            groups[key] = {
                "proto": proto,
                "dst_ip": dst,
                "dport": dport,
                "count": 0,
                "total_bytes": 0,
                "total_packets": 0,
                "srcs": {},
                "first_seen": ts,
                "last_seen": ts,
                "guess_counts": {},
                "confidence_sum": 0.0,
            }
        g = groups[key]
        g["count"] += 1
        g["total_bytes"] += bts
        g["total_packets"] += pkts
        if src:
            g["srcs"][src] = g["srcs"].get(src, 0) + 1
        if ts:
            if ts < g["first_seen"] or not g.get("first_seen"):
                g["first_seen"] = ts
            if ts > g["last_seen"] or not g.get("last_seen"):
                g["last_seen"] = ts
        g["guess_counts"][guess] = g["guess_counts"].get(guess, 0) + 1
        g["confidence_sum"] += conf

        service_key = (proto, dst, sport)
        if sport > 0:
            if service_key not in service_groups:
                service_groups[service_key] = {
                    "proto": proto,
                    "dst_ip": dst,
                    "sport": sport,
                    "count": 0,
                    "total_bytes": 0,
                    "srcs": {},
                    "local_ports": {},
                }
            sg = service_groups[service_key]
            sg["count"] += 1
            sg["total_bytes"] += bts
            if src:
                sg["srcs"][src] = sg["srcs"].get(src, 0) + 1
            if dport:
                sg["local_ports"][dport] = sg["local_ports"].get(dport, 0) + 1

    # 组装输出
    entries = []
    for g in groups.values():
        avg_size = round(g["total_bytes"] / g["count"]) if g["count"] > 0 else 0
        src_sorted = sorted(g["srcs"].items(), key=lambda x: -x[1])
        src_count = len(src_sorted)
        sample_srcs = [s[0] for s in src_sorted[:MAX_SAMPLE_SRC_IPS]]
        guess_sorted = sorted(g["guess_counts"].items(), key=lambda x: -x[1])
        top_guess = guess_sorted[0][0] if guess_sorted else "unknown"
        avg_conf = round(g["confidence_sum"] / g["count"], 3) if g["count"] > 0 else 0.0
        entries.append({
            "proto": g["proto"],
            "dst_ip": g["dst_ip"],
            "dport": g["dport"],
            "count": g["count"],
            "total_bytes": g["total_bytes"],
            "total_packets": g["total_packets"],
            "avg_size": avg_size,
            "src_count": src_count,
            "sample_src_ips": sample_srcs,
            "first_seen": g["first_seen"],
            "last_seen": g["last_seen"],
            "top_guess": top_guess,
            "avg_confidence": avg_conf,
        })

    sort_key = "total_bytes" if sort_by == "bytes" else "count"
    entries.sort(key=lambda x: -x[sort_key])
    entries = entries[:limit]

    suggestions = _generate_suggestions(entries)
    suggestions.extend(_generate_service_port_suggestions(service_groups.values()))
    unique = {}
    for item in suggestions:
        key = (
            item.get("scope"),
            item.get("proto"),
            item.get("host_ip"),
            item.get("dport"),
            item.get("sport"),
            item.get("suggested_class"),
        )
        if key not in unique or item.get("confidence", 0) > unique[key].get("confidence", 0):
            unique[key] = item
    suggestions = sorted(
        unique.values(),
        key=lambda x: (-_to_float(x.get("confidence", 0)), str(x.get("target_rule", ""))),
    )

    return {
        "success": True,
        "path": log_path,
        "entries": entries,
        "suggestions": suggestions,
        "sort_by": sort_by,
        "limit": limit,
    }


def tail_unknown_flows(limit=10, path=DEFAULT_LOG_FILE):
    """读取最近的诊断记录；文件不存在时直接返回空结果。"""
    try:
        limit = max(1, int(limit))
    except Exception:
        limit = 10
    if not os.path.exists(path):
        return {"success": True, "path": path, "entries": []}
    try:
        with open(path, "r", encoding="utf-8") as file_handle:
            lines = [line.strip() for line in file_handle if line.strip()]
        entries = []
        for line in lines[-limit:]:
            try:
                entries.append(json.loads(line))
            except Exception:
                entries.append({"raw": line, "parse_error": True})
        return {"success": True, "path": path, "entries": entries}
    except Exception as exc:
        return {"success": False, "path": path, "error": str(exc), "entries": []}


def self_test():
    return {
        "ok": True,
        "module": MODULE,
        "version": VERSION,
        "active": ACTIVE,
        "time": int(time.time()),
        "log_file": DEFAULT_LOG_FILE,
        "sample": normalize_flow({"proto": "udp", "dport": 443, "guess": "streaming", "confidence": 0.5}),
    }


def main():
    print(json.dumps(self_test(), ensure_ascii=False))


if __name__ == "__main__":
    main()
