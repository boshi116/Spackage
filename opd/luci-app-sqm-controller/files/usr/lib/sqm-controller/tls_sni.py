#!/usr/bin/env python3
"""SQM Controller TLS SNI 分类模块。

通过 tcpdump 抓取 TLS ClientHello 包，解析 SNI 域名，
匹配 dns_mapper 的域名规则后注入 DNS 缓存。
不修改 nftables/tc 规则。
"""
import json
import os
import struct
import subprocess
import time

MODULE = "tls_sni"
VERSION = "4.0"
ACTIVE = True
CACHE_FILE = "/tmp/sqm_tls_sni_cache.json"
SNI_TTL = 600  # SNI 缓存保留 10 分钟


def parse_pcap_sni(pcap_path, max_packets=50):
    """解析 pcap 文件，提取 TLS ClientHello SNI 域名。

    返回 [{"src_ip": str, "dst_ip": str, "dst_port": int, "sni": str}, ...]
    """
    if not os.path.exists(pcap_path):
        return []

    try:
        with open(pcap_path, "rb") as f:
            data = f.read()
    except Exception:
        return []

    results = []
    pos = 24  # 跳过 pcap 全局头（24 字节）

    for _ in range(max_packets):
        if pos + 16 > len(data):
            break

        # 读取单个数据包头（16 字节）
        incl_len = struct.unpack_from("<I", data, pos + 8)[0]
        pos += 16

        if incl_len == 0 or pos + incl_len > len(data):
            pos += incl_len
            continue

        packet = data[pos:pos + incl_len]
        pos += incl_len

        # 跳过 Linux cooked capture 头（SLL2 固定 20 字节）
        sll_offset = 20
        if len(packet) < sll_offset + 20:
            continue

        ip_start = sll_offset
        ip_byte = packet[ip_start]
        ip_version = ip_byte >> 4

        if ip_version == 4:
            ip_header_len = (ip_byte & 0x0F) * 4
            if packet[ip_start + 9] != 6:  # 这里只处理 TCP
                continue
            dst_ip = ".".join(str(b) for b in packet[ip_start + 16:ip_start + 20])
            tcp_start = ip_start + ip_header_len
        elif ip_version == 6:
            if packet[ip_start + 6] != 6:
                continue
            dst_ip = ":".join(
                f"{packet[ip_start + 24 + i * 2]:02x}{packet[ip_start + 25 + i * 2]:02x}"
                for i in range(8)
            )
            tcp_start = ip_start + 40
        else:
            continue

        if tcp_start + 20 > len(packet):
            continue

        data_offset = (packet[tcp_start + 12] >> 4) * 4
        dst_port = struct.unpack_from("!H", packet, tcp_start + 2)[0]

        payload_start = tcp_start + data_offset
        payload = packet[payload_start:]

        # 这里只解析 TLS ClientHello：record_type=0x16，version=0x03xx
        if len(payload) < 6 or payload[0] != 0x16 or payload[1] != 0x03:
            continue

        sni = _extract_sni_from_handshake(payload)
        if sni:
            results.append({
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "sni": sni,
            })

    return results


def _extract_sni_from_handshake(payload):
    """从 TLS 记录的 Handshake 中提取 SNI。"""
    try:
        record_len = (payload[3] << 8) | payload[4]
        handshake = payload[5:5 + record_len]
        if len(handshake) < 40 or handshake[0] != 0x01:  # 只处理 ClientHello
            return ""

        hs_len = (handshake[1] << 16) | (handshake[2] << 8) | handshake[3]
        ch = handshake[4:4 + hs_len]

        # 跳过版本号和随机数
        offset = 2 + 32
        if offset + 1 > len(ch):
            return ""
        session_id_len = ch[offset]
        offset += 1 + session_id_len

        # 跳过密码套件列表
        if offset + 2 > len(ch):
            return ""
        cs_len = (ch[offset] << 8) | ch[offset + 1]
        offset += 2 + cs_len

        # 跳过压缩方法列表
        if offset + 1 > len(ch):
            return ""
        comp_len = ch[offset]
        offset += 1 + comp_len

        # 进入扩展区
        if offset + 2 > len(ch):
            return ""
        ext_len = (ch[offset] << 8) | ch[offset + 1]
        offset += 2
        ext_end = offset + ext_len

        while offset + 4 <= ext_end:
            ext_type = (ch[offset] << 8) | ch[offset + 1]
            ext_data_len = (ch[offset + 2] << 8) | ch[offset + 3]
            offset += 4

            if ext_type == 0x0000:  # Server Name 扩展
                sni_data = ch[offset:offset + ext_data_len]
                if len(sni_data) > 5:
                    list_len = (sni_data[0] << 8) | sni_data[1]
                    sn = sni_data[2:2 + list_len]
                    if len(sn) > 3 and sn[0] == 0x00:  # host_name 类型
                        name_len = (sn[1] << 8) | sn[2]
                        return sn[3:3 + name_len].decode("ascii", errors="ignore")
                break

            offset += ext_data_len

    except Exception:
        pass

    return ""


def sniff(interface="any", timeout_sec=8, max_packets=80):
    """抓取当前链路上的 TLS ClientHello，提取 SNI 域名。

    timeout_sec 不宜太大，避免阻塞 cron 策略调度。
    """
    pcap_path = "/tmp/sqm_tls_sni_tmp.pcap"
    try:
        subprocess.run(
            ["rm", "-f", pcap_path],
            capture_output=True, timeout=2,
        )
    except Exception:
        pass

    try:
        subprocess.run(
            [
                "tcpdump",
                "-i", str(interface or "any"),
                "-c", str(max(1, int(max_packets))),
                "-w", pcap_path,
                "tcp dst port 443",
            ],
            capture_output=True,
            timeout=max(2, int(timeout_sec or 3)) + 2,
        )
    except subprocess.TimeoutExpired:
        pass
    except Exception:
        return {"success": False, "error": "tcpdump failed", "sni_results": []}

    try:
        results = parse_pcap_sni(pcap_path, max_packets=max_packets)
    except Exception as exc:
        results = []
        return {"success": False, "error": str(exc), "sni_results": []}
    finally:
        try:
            os.remove(pcap_path)
        except Exception:
            pass

    return {
        "success": True,
        "time": int(time.time()),
        "sni_count": len(results),
        "sni_results": results,
    }


def classify_and_cache(sni_results, dns_mapper_module=None):
    """将 SNI 域名匹配到域名规则，再写入 dns_mapper 缓存。

    不修改 dns_mapper 的 lookup_hits/cache_entries 主统计，
    只写入 IP→domain→class 缓存条目（标记 source="tls_sni"）。
    """
    if not sni_results:
        return {"imported": 0}

    imported = 0
    for item in sni_results:
        ip = item.get("dst_ip", "")
        sni = item.get("sni", "")
        if not ip or not sni:
            continue

        # 先复用 dns_mapper 的域名匹配逻辑
        if dns_mapper_module:
            pattern, cls, confidence = dns_mapper_module._match_domain_rules(sni)
            if cls and confidence > 0:
        # 命中后直接写入 dns_mapper 缓存
                cache = getattr(dns_mapper_module, "_cache", {})
                now = time.time()
                cache[ip] = {
                    "domain": sni,
                    "pattern": pattern or sni,
                    "class": cls,
                    "confidence": confidence,
                    "expires": now + SNI_TTL,
                }
                imported += 1

    return {"imported": imported}


def sniff_and_import(interface="any", timeout_sec=8, max_packets=80):
    """抓取 TLS SNI → 匹配域名规则 → 注入 dns_mapper 缓存。

    轻量级快速操作，失败不抛出异常。
    """
    import dns_mapper

    try:
        result = sniff(
            interface=interface,
            timeout_sec=timeout_sec,
            max_packets=max_packets,
        )
    except Exception as exc:
        return {"success": False, "error": str(exc), "imported": 0}

    if not result.get("success"):
        return {"success": False, "error": result.get("error", "sniff failed"), "imported": 0}

    import_result = classify_and_cache(
        result.get("sni_results", []),
        dns_mapper_module=dns_mapper,
    )

    return {
        "success": True,
        "sni_count": result.get("sni_count", 0),
        "imported": import_result.get("imported", 0),
        "time": int(time.time()),
    }


def self_test():
    return {
        "ok": True,
        "module": MODULE,
        "version": VERSION,
        "active": ACTIVE,
        "time": int(time.time()),
    }


def main():
    import argparse
    parser = argparse.ArgumentParser(description="SQM TLS SNI 分类")
    parser.add_argument("--sniff", action="store_true", help="抓取 TLS SNI")
    parser.add_argument("--sniff-and-import", action="store_true", help="抓取并注入 dns_mapper")
    parser.add_argument("--interface", default="any", help="抓包接口")
    parser.add_argument("--timeout", type=int, default=3, help="抓包超时秒数")
    parser.add_argument("--max-packets", type=int, default=30)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        print(json.dumps(self_test(), ensure_ascii=False, indent=2))
    elif args.sniff_and_import:
        result = sniff_and_import(
            interface=args.interface,
            timeout_sec=args.timeout,
            max_packets=args.max_packets,
        )
        print(json.dumps(result, ensure_ascii=False, indent=2))
    elif args.sniff:
        result = sniff(
            interface=args.interface,
            timeout_sec=args.timeout,
            max_packets=args.max_packets,
        )
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(json.dumps(self_test(), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
