#!/usr/bin/env python3
"""SQM Controller DNS 关联流量分类模块。

解析 dnsmasq 查询日志，建立 IP → 域名映射缓存。
通过域名模式匹配（*.bilivideo.com → streaming）对流量实现高置信度分类。
不修改任何 nftables/tc 规则。
"""
import fnmatch
import json
import os
import re
import subprocess
import time

MODULE = "dns_mapper"
VERSION = "4.0"
DEFAULT_TTL = 300
DEFAULT_MAX_ENTRIES = 5000
CACHE_FILE = "/tmp/sqm_dns_cache.json"

# 域名模式 → (类别, 置信度)
# 数据来源: dscpclassify, QoSmate, Netify.ai, ChinaMedia/Clash 规则集, 社区 PCDN 列表
DOMAIN_RULES = [
    # ═══ 流媒体（国内）═══
    # B站 (bilibili)
    ("*.bilibili.com", "streaming", 0.90),
    ("*.bilivideo.com", "streaming", 0.92),
    ("*.bilivideo.cn", "streaming", 0.92),
    ("*.mcdn.bilivideo.cn", "streaming", 0.90),
    ("*.biliapi.net", "streaming", 0.88),
    ("*.biliapi.com", "streaming", 0.88),
    ("*.bilicdn1.com", "streaming", 0.85),
    ("*.hdslb.com", "streaming", 0.85),
    # 爱奇艺 (iQiyi)
    ("*.iqiyi.com", "streaming", 0.90),
    ("*.iqiyipic.com", "streaming", 0.85),
    # 优酷 (Youku)
    ("*.youku.com", "streaming", 0.90),
    # 腾讯视频 (Tencent Video)
    ("v.qq.com", "streaming", 0.90),
    ("*.video.qq.com", "streaming", 0.88),
    # tc.qq.com 是腾讯通用 CDN 调度域名（含小程序/图片/头像），
    # 不限于视频流，放在 other 区域低置信度匹配
    # 微信视频号 channels.weixin.qq.com 已通过 weixin.qq.com 覆盖
    # 芒果TV (MGTV)
    ("*.mgtv.com", "streaming", 0.88),
    ("*.hitv.com", "streaming", 0.85),
    # 抖音 (Douyin)
    ("*.douyinvod.com", "streaming", 0.90),
    ("*.douyin.com", "streaming", 0.85),
    ("*.douyinpic.com", "streaming", 0.85),
    ("*.pstatp.com", "streaming", 0.85),
    # 西瓜视频 (Xigua)
    ("*.ixigua.com", "streaming", 0.88),
    # 快手 (Kuaishou)
    ("*.kuaishou.com", "streaming", 0.85),
    ("*.yximgs.com", "streaming", 0.85),
    # 虎牙 (Huya)
    ("*.huya.com", "streaming", 0.88),
    # 斗鱼 (Douyu)
    ("*.douyu.com", "streaming", 0.88),
    ("*.douyucdn.cn", "streaming", 0.88),
    # 其他国内流媒体
    ("*.cntv.cn", "streaming", 0.85),
    ("*.cctv.cn", "streaming", 0.85),
    ("*.migu.cn", "streaming", 0.85),
    ("*.miguvideo.com", "streaming", 0.88),
    ("*.pptv.com", "streaming", 0.85),
    ("*.pplive.cn", "streaming", 0.85),
    ("*.le.com", "streaming", 0.85),
    ("*.letv.com", "streaming", 0.85),
    ("*.sohu.com", "streaming", 0.75),
    ("*.fun.tv", "streaming", 0.85),

    # ═══ 流媒体（国外）═══
    ("*.googlevideo.com", "streaming", 0.92),
    ("*.youtube.com", "streaming", 0.85),
    ("*.youtu.be", "streaming", 0.85),
    ("*.ytimg.com", "streaming", 0.85),
    ("*.ggpht.com", "streaming", 0.75),
    ("*.netflix.com", "streaming", 0.88),
    ("*.nflxvideo.net", "streaming", 0.90),
    ("*.nflximg.net", "streaming", 0.85),
    ("*.nflxext.com", "streaming", 0.85),
    ("*.twitch.tv", "streaming", 0.88),
    ("*.ttvnw.net", "streaming", 0.88),
    ("*.jtvnw.net", "streaming", 0.88),
    ("*.disneyplus.com", "streaming", 0.85),
    ("*.bamgrid.com", "streaming", 0.85),
    ("*.hbo.com", "streaming", 0.85),
    ("*.hbomax.com", "streaming", 0.85),
    ("*.primevideo.com", "streaming", 0.85),
    ("*.aiv-cdn.net", "streaming", 0.85),

    # ═══ 音乐 ═══
    ("*.y.qq.com", "streaming", 0.80),
    ("*.qqmusic.qq.com", "streaming", 0.80),
    ("*.music.163.com", "streaming", 0.80),
    # 网易云音乐核心音频CDN（DNS日志已验证：p5.music.126.net）
    ("*.music.126.net", "streaming", 0.85),
    ("*.kugou.com", "streaming", 0.80),
    ("*.kuwo.cn", "streaming", 0.80),

    # ═══ 游戏 ═══
    # Steam / Valve
    ("*.steamserver.net", "gaming", 0.85),
    ("*.steamcommunity.com", "gaming", 0.80),
    ("*.valve.net", "gaming", 0.85),
    # Riot
    ("*.riotgames.com", "gaming", 0.85),
    # 暴雪
    ("*.blizzard.com", "gaming", 0.85),
    ("*.battle.net", "gaming", 0.85),
    # Epic Games
    ("*.epicgames.com", "gaming", 0.85),
    ("*.epicgames-download.*.akamaized.net", "gaming", 0.85),
    # Ubisoft
    ("*.ubisoft.com", "gaming", 0.85),
    ("*.ubi.com", "gaming", 0.85),
    # EA / Origin
    ("*.origin.com", "gaming", 0.85),
    ("*.ea.com", "gaming", 0.75),
    # Rockstar
    ("*.rockstargames.com", "gaming", 0.85),
    # Nintendo
    ("*.nintendo.com", "gaming", 0.85),
    ("*.nintendo.net", "gaming", 0.85),
    # PlayStation
    ("*.playstation.com", "gaming", 0.85),
    ("*.playstation.net", "gaming", 0.85),
    ("*.sonyentertainmentnetwork.com", "gaming", 0.85),
    # Xbox
    ("*.xboxlive.com", "gaming", 0.85),
    ("*.xbox.com", "gaming", 0.80),
    # GOG
    ("*.gog.com", "gaming", 0.85),
    ("*.gog-statics.com", "gaming", 0.85),
    # 国内游戏
    ("*.tencent-cloud.net", "gaming", 0.80),
    ("*.qcgamedns.com", "gaming", 0.82),
    ("*.netease.com", "gaming", 0.75),
    ("*.163.com", "gaming", 0.65),
    ("*.garena.com", "gaming", 0.85),

    # ═══ 批量下载 ═══
    # Steam 下载
    ("*.steamcontent.com", "bulk", 0.92),
    ("*.steampowered.com", "bulk", 0.85),
    ("*.steamstatic.com", "bulk", 0.80),
    ("*.steamcdn-a.akamaihd.net", "bulk", 0.90),
    # 腾讯下载
    ("*.dlied1.cdntips.net", "bulk", 0.88),
    # 阿里 CDN（以电商商品图片为主，偶有大文件下载，保守归 other）
    ("*.alicdn.com", "other", 0.60),
    # 腾讯云 CDN
    ("*.qcloud.com", "bulk", 0.75),
    ("*.myqcloud.com", "bulk", 0.75),
    # Windows / Microsoft 更新
    ("*.windowsupdate.com", "bulk", 0.90),
    ("*.update.microsoft.com", "bulk", 0.88),
    ("dl.delivery.mp.microsoft.com", "bulk", 0.90),
    # Apple 下载
    ("*.appldnld.apple.com", "bulk", 0.85),
    ("*.cdn-apple.com", "bulk", 0.80),
    # Google Play 下载
    ("dl.google.com", "bulk", 0.80),
    # 通用 CDN
    ("*.akamaiedge.net", "bulk", 0.70),
    ("*.akamai.net", "bulk", 0.65),
    ("*.cloudfront.net", "bulk", 0.65),
    ("*.fastly.net", "bulk", 0.60),
    ("*.akamaitechnologies.com", "bulk", 0.65),
    ("*.edgesuite.net", "bulk", 0.65),

    # ═══ 视频会议 / 语音 ═══
    ("*.zoom.us", "streaming", 0.85),
    ("*.discord.com", "streaming", 0.80),
    ("*.discord.gg", "streaming", 0.80),
    ("*.discordapp.com", "streaming", 0.80),
    ("*.teams.microsoft.com", "streaming", 0.80),
    ("*.skype.com", "streaming", 0.80),
    ("*.skypeforbusiness.com", "streaming", 0.80),

    # ═══ 通用 CDN（低置信度）═══
    ("*.cdn20.com", "streaming", 0.60),
    ("*.jomodns.com", "streaming", 0.65),

    # ═══ dlc.dat 补充：流媒体国际域名 ═══
    ("*.amazonprimevideo.com.cn", "streaming", 0.90),
    ("*.disney.co.il", "streaming", 0.90),
    ("*.disney.co.jp", "streaming", 0.90),
    ("*.disney.co.kr", "streaming", 0.90),
    ("*.disney.co.th", "streaming", 0.90),
    ("*.disney.co.uk", "streaming", 0.90),
    ("*.disney.co.za", "streaming", 0.90),
    ("*.disney.com.au", "streaming", 0.90),
    ("*.disney.com.br", "streaming", 0.90),
    ("*.disney.com.hk", "streaming", 0.90),
    ("*.disney.com.tw", "streaming", 0.90),
    ("*.disneymagicmoments.co.il", "streaming", 0.90),
    ("*.disneymagicmoments.co.uk", "streaming", 0.90),
    ("*.disneymagicmoments.co.za", "streaming", 0.90),
    ("*.espn.co.uk", "streaming", 0.90),
    ("*.hbogo.co.th", "streaming", 0.90),
    ("*.youtube.co.il", "streaming", 0.90),
    ("*.youtube.co.in", "streaming", 0.90),
    ("*.youtube.co.jp", "streaming", 0.90),
    ("*.youtube.co.kr", "streaming", 0.90),
    ("*.youtube.co.nz", "streaming", 0.90),
    ("*.youtube.co.th", "streaming", 0.90),
    ("*.youtube.co.uk", "streaming", 0.90),
    ("*.youtube.co.za", "streaming", 0.90),
    ("*.youtube.com.au", "streaming", 0.90),
    ("*.youtube.com.br", "streaming", 0.90),
    ("*.youtube.com.hk", "streaming", 0.90),
    ("*.youtube.com.mx", "streaming", 0.90),
    ("*.youtube.com.sg", "streaming", 0.90),
    ("*.youtube.com.tw", "streaming", 0.90),
    ("*.youtubego.co.in", "streaming", 0.90),
    ("*.youtubego.com.br", "streaming", 0.90),
    ("*.cctvlib.com.cn", "streaming", 0.85),
    ("*.cctvlibrary.com.cn", "streaming", 0.85),
    ("*.cctvpro.com.cn", "streaming", 0.85),
    ("*.cntv.com.cn", "streaming", 0.85),
    ("*.kktv.com.tw", "streaming", 0.85),

    # ═══ dlc.dat 补充：游戏平台国际域名 ═══
    ("*.leagueoflegends.co.kr", "gaming", 0.90),
    ("*.lolshop.co.kr", "gaming", 0.90),
    ("*.nintendo.co.jp", "gaming", 0.90),
    ("*.nintendo.co.kr", "gaming", 0.90),
    ("*.nintendo.co.uk", "gaming", 0.90),
    ("*.nintendo.co.za", "gaming", 0.90),
    ("*.nintendo.com.hk", "gaming", 0.90),
    ("*.nintendoswitch.com.cn", "gaming", 0.90),
    ("*.riotgames.co.kr", "gaming", 0.90),
    ("*.bushiroad.co.jp", "gaming", 0.85),
    ("*.cygames.co.jp", "gaming", 0.85),
    ("*.dlsite.com.tw", "gaming", 0.85),
    ("*.garena.co.th", "gaming", 0.85),
    ("*.roblox.co.jp", "gaming", 0.85),
    ("*.roblox.co.uk", "gaming", 0.85),
    ("*.snk-corp.co.jp", "gaming", 0.85),
    ("*.yostar-pictures.co.jp", "gaming", 0.85),
    ("*.yostar.co.jp", "gaming", 0.85),

    # ═══ dlc.dat 补充：驱动/系统更新国际域名 ═══
    ("*.microsoftonline-p-i.net.cn", "bulk", 0.88),
    ("*.microsoftonline-p.net.cn", "bulk", 0.88),
    ("*.amd.com.cn", "bulk", 0.75),
    ("*.geforce.co.kr", "bulk", 0.75),
    ("*.geforce.co.uk", "bulk", 0.75),
    ("*.geforce.com.tw", "bulk", 0.75),
    ("*.intel.co.il", "bulk", 0.75),
    ("*.intel.co.jp", "bulk", 0.75),
    ("*.intel.co.kr", "bulk", 0.75),
    ("*.intel.co.uk", "bulk", 0.75),
    ("*.intel.co.za", "bulk", 0.75),
    ("*.intel.com.au", "bulk", 0.75),
    ("*.intel.com.br", "bulk", 0.75),
    ("*.intel.com.cn", "bulk", 0.75),
    ("*.intel.com.hk", "bulk", 0.75),
    ("*.intel.com.mx", "bulk", 0.75),
    ("*.intel.com.tw", "bulk", 0.75),
    ("*.nvidia.co.in", "bulk", 0.75),
    ("*.nvidia.co.jp", "bulk", 0.75),
    ("*.nvidia.co.kr", "bulk", 0.75),
    ("*.nvidia.co.uk", "bulk", 0.75),
    ("*.nvidia.com.au", "bulk", 0.75),
    ("*.nvidia.com.br", "bulk", 0.75),
    ("*.nvidia.com.mx", "bulk", 0.75),
    ("*.nvidia.com.tw", "bulk", 0.75),

    # ═══ 腾讯系：微信 / QQ ═══
    # 微信视频号（DNS 日志已验证：channels.weixin.qq.com → aewebproxy.weixin.qq.com）
    ("channels.weixin.qq.com", "streaming", 0.82),
    ("*.weixin.qq.com", "other", 0.70),
    ("*.wx.qq.com", "other", 0.70),
    ("*.mp.weixin.qq.com", "other", 0.70),
    ("*.mmbiz.qpic.cn", "other", 0.65),
    # 微信头像 CDN（DNS 日志已验证：wx.qlogo.cn → mmsns.qpic.cn）
    ("*.qlogo.cn", "other", 0.65),
    # QQ 文件传输 / 邮箱
    ("*.qqmail.com", "bulk", 0.75),
    ("mail.qq.com", "bulk", 0.70),
    # QQ 空间 / 相册 / CDN（gtimg.cn 已通过 DNS 日志验证）
    ("*.qzone.qq.com", "other", 0.65),
    ("*.qpic.cn", "other", 0.65),
    ("*.gtimg.cn", "other", 0.60),
    ("*.tc.qq.com", "other", 0.60),
    ("galileotelemetry.tencent.com", "other", 0.82),
    # 企业微信 / 腾讯会议
    ("*.work.weixin.qq.com", "streaming", 0.78),
    ("*.meeting.tencent.com", "streaming", 0.82),

    # ═══ 办公协作 ═══
    ("*.dingtalk.com", "streaming", 0.82),
    ("*.feishu.cn", "streaming", 0.82),

    # ═══ 社交 / 内容 ═══
    ("*.weibo.com", "other", 0.70),
    ("*.sinaimg.cn", "other", 0.65),
    ("*.zhihu.com", "other", 0.70),
    ("*.zhimg.com", "other", 0.65),
    ("*.xiaohongshu.com", "other", 0.70),
    ("*.douban.com", "other", 0.70),
    ("*.tieba.baidu.com", "other", 0.65),

    # ═══ 电商 ═══
    ("*.jd.com", "other", 0.70),
    # 京东云图片 CDN（DNS 日志已验证：img20.jcloudimg.com）
    ("*.jcloudimg.com", "other", 0.65),
    ("*.pinduoduo.com", "other", 0.70),
    ("*.taobao.com", "other", 0.70),
    ("*.tmall.com", "other", 0.70),
    ("*.suning.com", "other", 0.70),
    ("*.vip.com", "other", 0.70),
    ("*.meituan.com", "other", 0.70),
    ("*.dianping.com", "other", 0.65),
    ("*.ele.me", "other", 0.70),
    ("*.alipay.com", "other", 0.70),
    # AI / 开发工具
    ("api.anthropic.com", "other", 0.85),
    ("persistent.oaistatic.com", "other", 0.85),

    # ═══ 网盘 / 下载（必须在 *.baidu.com 之前，确保下载子域名优先匹配）═══
    # 百度网盘（DNS 日志已验证下载：d.pcs.baidu.com, bjdd-ct10.baidupcs.com,
    #   wppkg.baidupcs.com → CNAME → netdisk-pan.n.shifen.com）
    ("d.pcs.baidu.com", "bulk", 0.92),
    ("*.pcs.baidu.com", "bulk", 0.90),
    ("*.baidupcs.com", "bulk", 0.90),
    ("*.pan.baidu.com", "bulk", 0.85),
    ("gamedelivery.baidu.com", "bulk", 0.85),
    # 蓝奏云（DNS 日志已验证：pc.woozooo.com，非 lanzou.com）
    ("pc.woozooo.com", "bulk", 0.85),
    ("*.woozooo.com", "bulk", 0.85),
    # 阿里云盘 — 后端是 PDS (Personal Drive Service)
    # DNS 日志已验证：pds-app-cn-beijing.*.aliyuncs.com
    ("pds-*.aliyuncs.com", "bulk", 0.85),
    ("*.aliyundrive.com", "bulk", 0.85),
    # 夸克网盘（DNS 日志已验证：download.quark.cn, image.quark.cn）
    ("download.quark.cn", "bulk", 0.85),
    ("*.quark.cn", "bulk", 0.80),

    # ═══ 地图 / 出行 ═══
    # 高德地图（DNS 日志已验证：mapplugin.amap.com）
    ("*.amap.com", "other", 0.70),

    # ═══ 搜索 / 门户 ═══
    ("*.baidu.com", "other", 0.70),
    ("*.bdstatic.com", "other", 0.65),
    ("*.sogou.com", "other", 0.70),
    ("*.360.cn", "other", 0.70),
    ("*.so.com", "other", 0.65),
    ("*.xunlei.com", "bulk", 0.90),
    ("*.sandai.net", "bulk", 0.85),
    ("*.weiyun.com", "bulk", 0.85),
    ("dldir1v6.qq.com", "bulk", 0.82),
    # 腾讯文件下载 CDN（DNS 日志已验证：dldir1v6.qq.com.s7.ctlcdn.cn）
    ("*.ctlcdn.cn", "bulk", 0.82),

    # ═══ 国内游戏 ═══
    ("*.mihoyo.com", "gaming", 0.85),
    ("*.hoyoverse.com", "gaming", 0.85),
    ("*.yuanshen.com", "gaming", 0.85),
    ("*.pvp.qq.com", "gaming", 0.85),
    ("*.game.qq.com", "gaming", 0.80),
    ("*.game.163.com", "gaming", 0.80),
    ("*.perfectworld.com", "gaming", 0.82),
    ("*.taptap.com", "gaming", 0.80),

    # ═══ 直播 ═══
    ("*.huajiao.com", "streaming", 0.85),
    ("*.yy.com", "streaming", 0.85),
]

# dnsmasq 日志解析正则
_RE_LOG_LINE = re.compile(
    r"reply\s+(\S+)\s+is\s+"
    r"(?:(<CNAME>)|"
    r"(?:NODATA(?:-IPv[46])?|NXDOMAIN)|"
    r"(\d+\.\d+\.\d+\.\d+))"
)
_RE_CACHED = re.compile(r"\bcached\b")
_RE_FORWARDED = re.compile(r"\bforwarded\b")

_cache = {}  # ip → {"domain": str, "class": str, "confidence": float, "expires": float, "pattern": str}
_stats = {
    "total_mapped": 0,
    "lookup_hits": 0,        # lookup() 实际命中
    "lookup_misses": 0,      # lookup() 实际未命中
    "cache_entries": 0,      # 当前活跃缓存 IP 数
    "hits": 0,               # 兼容旧版 = lookup_hits
    "misses": 0,             # 兼容旧版 = lookup_misses
    "entries": 0,            # 兼容旧版 = cache_entries
    "last_refresh": 0,
}
_pattern_hit_counters = {}        # 兼容旧版 = _pattern_lookup_counters（仅 lookup 写入）
_pattern_lookup_counters = {}     # pattern → int（lookup 命中时递增）
_pattern_cache_counts = {}         # pattern → int（缓存覆盖 IP 数）

# 未匹配域名统计（用于 AI 规则扩充导出）
_unmatched = {}  # domain → {count, first_seen, last_seen, sample_ips, subdomain_samples}
MAX_UNMATCHED = 2000       # 最多保留条数
UNMATCHED_TTL = 86400      # 过期秒数（24h）
UNMATCHED_MAX_SAMPLES = 5  # 样本数上限
LOGREAD_CANDIDATES = ("/sbin/logread", "/usr/sbin/logread", "/bin/logread", "logread")
DNS_LOG_FILES = ("/tmp/dnsmasq.log", "/var/log/dnsmasq.log")
DNS_LOG_MAX_BYTES = 2 * 1024 * 1024


def _clear_runtime_cache():
    """重置内存中的 DNS 缓存与 pattern 级缓存覆盖计数。"""
    _cache.clear()
    _pattern_cache_counts.clear()
    _pattern_hit_counters.clear()
    _pattern_lookup_counters.clear()
    _stats["cache_entries"] = 0
    _stats["entries"] = 0


def _load_cache():
    """从磁盘恢复 DNS 缓存和统计（用于跨进程持久化）。"""
    global _cache, _stats, _pattern_hit_counters, _pattern_lookup_counters, _pattern_cache_counts, _unmatched
    if not os.path.exists(CACHE_FILE):
        return
    try:
        with open(CACHE_FILE, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if not isinstance(data, dict):
            return
        raw = data.get("entries", {})
        now = time.time()
        loaded = 0
        for ip, v in raw.items():
            if not isinstance(v, dict):
                continue
            expires = v.get("expires", 0)
            if expires < now:
                continue
            _cache[ip] = {
                "domain": v.get("domain", ""),
                "pattern": v.get("pattern", ""),
                "class": v.get("class", "other"),
                "confidence": v.get("confidence", 0.0),
                "expires": expires,
            }
            loaded += 1
        saved_stats = data.get("stats", {}) if isinstance(data, dict) else {}
        if isinstance(saved_stats, dict):
            # 新字段优先，fallback 旧字段
            if "lookup_hits" not in saved_stats:
                saved_stats["lookup_hits"] = saved_stats.get("hits", 0)
            if "lookup_misses" not in saved_stats:
                saved_stats["lookup_misses"] = saved_stats.get("misses", 0)
            if "cache_entries" not in saved_stats:
                saved_stats["cache_entries"] = saved_stats.get("entries", loaded)
            _stats.update(saved_stats)
        # 新计数器优先
        saved_lookup = data.get("pattern_lookup_counters", {})
        if isinstance(saved_lookup, dict):
            _pattern_lookup_counters.update(saved_lookup)
        saved_cache = data.get("pattern_cache_counts", {})
        if isinstance(saved_cache, dict):
            _pattern_cache_counts.update(saved_cache)
        # 兼容旧版 pattern_hit_counters：仅当新字段不存在时使用
        saved_old = data.get("pattern_hit_counters", {})
        if isinstance(saved_old, dict) and not saved_lookup:
            _pattern_lookup_counters.update(saved_old)
        _pattern_hit_counters.update(_pattern_lookup_counters)
        saved_unmatched = data.get("unmatched", {})
        if isinstance(saved_unmatched, dict):
            for domain, entry in saved_unmatched.items():
                if not isinstance(entry, dict):
                    continue
                last_seen = float(entry.get("last_seen", 0) or 0)
                if last_seen and last_seen < now - UNMATCHED_TTL:
                    continue
                samples = list(entry.get("subdomain_samples", []) or [])[:UNMATCHED_MAX_SAMPLES]
                _unmatched[str(domain)] = {
                    "count": int(entry.get("count", 0) or 0),
                    "first_seen": float(entry.get("first_seen", last_seen or now) or now),
                    "last_seen": last_seen or now,
                    "sample_ips": list(entry.get("sample_ips", []) or [])[:UNMATCHED_MAX_SAMPLES],
                    "subdomain_samples": samples,
                    "_subdomain_set": set(samples),
                }
        _stats["entries"] = loaded
    except Exception as exc:
        _stats["cache_load_error"] = str(exc)
        _stats["last_error"] = str(exc)
        # 缓存损坏时清空运行态，并删除损坏文件，避免每次新进程都重复带着旧错误启动
        _clear_runtime_cache()
        try:
            os.remove(CACHE_FILE)
        except OSError:
            pass


def _save_cache():
    """将 DNS 缓存写入磁盘。"""
    try:
        # 写盘前先清理已恢复的历史错误标记，避免把旧错误重新固化到缓存文件里
        _stats.pop("cache_save_error", None)
        _stats.pop("cache_load_error", None)
        _stats.pop("last_error", None)
        unmatched_dump = {}
        for domain, entry in _unmatched.items():
            if not isinstance(entry, dict):
                continue
            samples = entry.get("subdomain_samples", [])
            if not samples and isinstance(entry.get("_subdomain_set"), set):
                samples = list(entry.get("_subdomain_set"))
            unmatched_dump[domain] = {
                "count": int(entry.get("count", 0) or 0),
                "first_seen": entry.get("first_seen", 0),
                "last_seen": entry.get("last_seen", 0),
                "sample_ips": list(entry.get("sample_ips", []) or [])[:UNMATCHED_MAX_SAMPLES],
                "subdomain_samples": list(samples or [])[:UNMATCHED_MAX_SAMPLES],
            }
        data = {
            "entries": _cache,
            "stats": dict(_stats),
            "pattern_hit_counters": dict(_pattern_hit_counters),        # 兼容旧版
            "pattern_lookup_counters": dict(_pattern_lookup_counters),  # 新版
            "pattern_cache_counts": dict(_pattern_cache_counts),        # 新版
            "unmatched": unmatched_dump,
            "time": int(time.time()),
        }
        tmp_path = CACHE_FILE + ".tmp"
        with open(tmp_path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, ensure_ascii=False)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp_path, CACHE_FILE)
    except Exception as exc:
        _stats["cache_save_error"] = str(exc)
        _stats["last_error"] = str(exc)


def save():
    """持久化 DNS 缓存与统计（供策略链路在 scan_conntrack 后调用）。"""
    _save_cache()


# 模块加载时恢复缓存
_load_cache()


def _match_domain_rules(domain, extra_rules=None):
    rules = list(DOMAIN_RULES)
    if extra_rules:
        rules.extend(extra_rules)
    for pattern, cls, confidence in rules:
        if fnmatch.fnmatch(domain, pattern):
            return pattern, cls, confidence
    return None, None, 0.0


def _read_logread_lines():
    last_error = ""
    for cmd in LOGREAD_CANDIDATES:
        try:
            proc = subprocess.run(
                [cmd],
                capture_output=True, text=True, timeout=10,
            )
            if proc.returncode == 0:
                return proc.stdout.strip().split("\n") if proc.stdout.strip() else []
            last_error = (proc.stderr or "").strip() or f"{cmd} exited {proc.returncode}"
        except Exception as exc:
            last_error = str(exc)
    raise RuntimeError(last_error or "logread failed")


def _read_log_file_lines(path, max_bytes=DNS_LOG_MAX_BYTES):
    """读取日志文件尾部，避免大文件一次性读入内存。"""
    size = os.path.getsize(path)
    with open(path, "rb") as fh:
        if size > max_bytes:
            fh.seek(size - max_bytes)
            data = fh.read()
            nl = data.find(b"\n")
            if nl >= 0:
                data = data[nl + 1 :]
        else:
            data = fh.read()
    return data.decode("utf-8", "ignore").splitlines()


def _read_dns_reply_lines():
    """优先从 logread 读取 reply 行；没有时回退到 dnsmasq 日志文件。"""
    reply_lines = []
    last_error = ""

    try:
        logread_lines = _read_logread_lines()
        reply_lines = [line for line in logread_lines if "dnsmasq" in line and "reply" in line]
        if reply_lines:
            return reply_lines, "logread"
    except Exception as exc:
        last_error = str(exc)

    for path in DNS_LOG_FILES:
        if not os.path.exists(path):
            continue
        try:
            file_lines = _read_log_file_lines(path)
            reply_lines = [line for line in file_lines if "dnsmasq" in line and "reply" in line]
            if reply_lines:
                return reply_lines, path
        except Exception as exc:
            last_error = str(exc)

    return [], last_error or "no dns reply lines found"


def _load_user_rules(path="/etc/sqm_controller/dns_rules.json"):
    """加载用户自定义域名规则（JSON 文件）。

    兼容两种格式：
      - 旧格式：[(pattern, class, confidence), ...]
      - 新格式：[{pattern, class, confidence, source, enabled, reason, created_at}, ...]
    enabled=false 的条目会被跳过。
    """
    rules = []
    if not os.path.exists(path):
        return rules
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        for item in data if isinstance(data, list) else data.get("rules", []):
            if isinstance(item, (list, tuple)) and len(item) >= 3:
                # 旧格式兼容
                pattern, cls, conf = item[0], item[1], item[2]
                if str(pattern) and str(cls) in ("gaming", "streaming", "bulk", "other"):
                    rules.append((str(pattern), str(cls), min(max(float(conf or 0.8), 0.0), 1.0)))
            elif isinstance(item, dict):
                if item.get("enabled") is False:
                    continue
                pattern = str(item.get("pattern", "")).strip()
                cls = str(item.get("class", "")).strip().lower()
                conf = float(item.get("confidence", 0.80) or 0.80)
                if pattern and cls in ("gaming", "streaming", "bulk", "other"):
                    rules.append((pattern, cls, min(max(conf, 0.0), 1.0)))
    except Exception:
        pass
    return rules


def refresh(ttl=None, max_entries=None):
    """增量解析 dnsmasq 日志，更新 IP→域名映射缓存。

    读取 logread 中 dnsmasq 的 reply 行，提取「域名→IP」记录。
    支持 CNAME 链追踪：同一个 batch 中先看到 CNAME 再看到最终 IP。
    """
    global _cache, _stats
    if ttl is None:
        ttl = DEFAULT_TTL
    if max_entries is None:
        max_entries = DEFAULT_MAX_ENTRIES

    now = time.time()
    cname_stack = []  # CNAME 链追踪：[根域名, 中间域名, ...]
    new_count = 0

    lines, source = _read_dns_reply_lines()
    _stats["log_source"] = source
    if not lines:
        _stats["last_error"] = "dns reply log unavailable: %s" % source
        return {"success": False, "error": _stats["last_error"], "entries": len(_cache)}

    # 合并用户规则
    all_rules = list(DOMAIN_RULES) + _load_user_rules()

    for line in lines:
        match = _RE_LOG_LINE.search(line)
        if not match:
            continue

        domain = match.group(1)
        is_cname = match.group(2) == "<CNAME>"
        ip_addr = match.group(3)

        if is_cname:
            # 记录 CNAME 链：此域名是别名
            cname_stack.append(domain)
            continue

        if not ip_addr:
            # NODATA / NXDOMAIN — 重置 CNAME 链，无 IP 可映射
            cname_stack.clear()
            continue

        # 有 IP 地址：CNAME 栈底即为原始域名，栈顶为最接近 IP 的中间域名
        saved_stack = list(cname_stack)
        original_domain = saved_stack[0] if saved_stack else domain
        cname_stack.clear()

        pattern, cls, confidence = _match_domain_rules(original_domain, all_rules)
        # 根域名未命中时，尝试匹配 CNAME 中间域名
        if cls is None:
            for mid_domain in reversed(saved_stack):
                c_pattern, c, conf = _match_domain_rules(mid_domain, all_rules)
                if c and conf > (confidence or 0):
                    pattern, cls, confidence = c_pattern, c, conf

        if cls is None:
            # 收集未匹配域名（用于 AI 规则扩充导出）
            _collect_unmatched(original_domain, ip_addr, saved_stack, now)
            continue

        if len(_cache) >= max_entries and ip_addr not in _cache:
            # 清理过期条目腾空间
            expired = [ip for ip, v in _cache.items() if v["expires"] < now]
            for ip in expired[:max(100, len(expired) // 2)]:
                del _cache[ip]
            if len(_cache) >= max_entries:
                continue

        _cache[ip_addr] = {
            "domain": original_domain,
            "pattern": pattern,
            "class": cls,
            "confidence": confidence,
            "expires": now + ttl,
        }
        new_count += 1

    # 清理过期条目
    expired = [ip for ip, v in _cache.items() if v["expires"] < now]
    for ip in expired:
        del _cache[ip]

    # 清理未匹配域名统计（过期 + 容量上限）
    _prune_unmatched(now)

    _stats["total_mapped"] += new_count
    _stats["last_refresh"] = int(now)
    _stats["cache_entries"] = len(_cache)
    _stats["entries"] = len(_cache)  # 兼容旧版
    _stats.pop("last_error", None)
    # 更新 pattern 级别的缓存覆盖数
    _pattern_cache_counts.clear()
    for ip, v in _cache.items():
        if v.get("expires", 0) >= now:
            p = v.get("pattern", "")
            if p:
                _pattern_cache_counts[p] = _pattern_cache_counts.get(p, 0) + 1

    _save_cache()

    return {
        "success": True,
        "new": new_count,
        "entries": len(_cache),
        "expired_removed": len(expired),
        "time": int(now),
    }


def lookup(ip):
    """按 IP 查询 DNS 映射缓存。返回 dict 或 None。"""
    global _stats, _pattern_hit_counters, _pattern_lookup_counters
    if not ip or not isinstance(ip, str):
        _stats["lookup_misses"] += 1
        _stats["misses"] += 1  # 兼容旧版
        return None

    now = time.time()
    entry = _cache.get(ip)
    if entry is None:
        _stats["lookup_misses"] += 1
        _stats["misses"] += 1
        return None
    if entry["expires"] < now:
        del _cache[ip]
        _stats["lookup_misses"] += 1
        _stats["misses"] += 1
        return None

    _stats["lookup_hits"] += 1
    _stats["hits"] += 1  # 兼容旧版

    # 递增真实分类命中计数器
    pattern = entry.get("pattern")
    if pattern:
        _pattern_lookup_counters[pattern] = _pattern_lookup_counters.get(pattern, 0) + 1
        _pattern_hit_counters[pattern] = _pattern_lookup_counters[pattern]  # 兼容旧版

    return {
        "domain": entry["domain"],
        "pattern": pattern,
        "class": entry["class"],
        "confidence": entry["confidence"],
    }


def lookup_class(ip):
    """快捷方法：按 IP 查询，直接返回 (class, confidence, reason) 或 (None, 0, '')。"""
    result = lookup(ip)
    if result:
        return result["class"], result["confidence"], f"dns:{result['domain']}"
    return None, 0.0, ""


def get_stats():
    """返回缓存统计信息。"""
    return dict(_stats)


def get_rule_hit_stats():
    """返回每条域名规则的命中统计。

    返回字段：
      - lookup_hits:      该 pattern 实际参与流分类的次数
      - cache_entries:    该 pattern 当前覆盖的活跃 IP 数
      - hits:             兼容旧版 = lookup_hits
    按 cache_entries 降序排列（反映当前规则覆盖能力）。
    """
    result = {}
    for pattern, cls, confidence in DOMAIN_RULES:
        result[pattern] = {
            "pattern": pattern,
            "class": cls,
            "confidence": confidence,
            "lookup_hits": _pattern_lookup_counters.get(pattern, 0),
            "cache_entries": _pattern_cache_counts.get(pattern, 0),
            "hits": _pattern_lookup_counters.get(pattern, 0),  # 兼容旧版 = lookup_hits
            "is_user": False,
        }
    user_rules = _load_user_rules()
    for pattern, cls, confidence in user_rules:
        ce = _pattern_cache_counts.get(pattern, 0)
        lh = _pattern_lookup_counters.get(pattern, 0)
        if pattern in result:
            entry = result[pattern]
            entry["cache_entries"] = max(entry["cache_entries"], ce)
            entry["lookup_hits"] = max(entry["lookup_hits"], lh)
            entry["hits"] = entry["lookup_hits"]
            entry["is_user"] = True
        else:
            result[pattern] = {
                "pattern": pattern,
                "class": cls,
                "confidence": confidence,
                "lookup_hits": lh,
                "cache_entries": ce,
                "hits": lh,
                "is_user": True,
            }
    return sorted(result.values(), key=lambda x: (-x["cache_entries"], x["pattern"]))


def get_cache_entry_counts():
    """返回每个域名模式当前的活跃缓存条目数（即有多少个 IP 被该模式匹配）。"""
    now = time.time()
    counts = {}
    for ip, entry in _cache.items():
        if entry.get("expires", 0) >= now:
            pattern = entry.get("pattern", "")
            if pattern:
                counts[pattern] = counts.get(pattern, 0) + 1
    return counts


def sync_hit_stats_from_cache():
    """用当前缓存条目数更新 DNS 缓存覆盖统计。

    只写 _pattern_cache_counts 和 _stats["cache_entries"]，
    不触及 lookup_hits / lookup_misses / _pattern_lookup_counters。
    兼容旧字段（_pattern_hit_counters / _stats["hits"]）同步更新。
    """
    now = time.time()
    entry_count = 0
    _pattern_cache_counts.clear()
    for ip, entry in _cache.items():
        if entry.get("expires", 0) >= now:
            entry_count += 1
            pattern = entry.get("pattern", "")
            if pattern:
                _pattern_cache_counts[pattern] = _pattern_cache_counts.get(pattern, 0) + 1
    _stats["cache_entries"] = entry_count
    _stats["entries"] = entry_count  # 兼容旧版
    # 兼容旧版：_pattern_hit_counters 同步为 lookup_counters（不改 cache 语义）
    # hits 字段保持为 lookup_hits，不修改
    return {"cache_entries": entry_count, "matched_patterns": len(_pattern_cache_counts)}


def get_cache_snapshot(limit=50):
    """返回缓存快照（用于调试）。返回最近更新的 N 条。"""
    now = time.time()
    items = sorted(
        [(ip, v) for ip, v in _cache.items() if v["expires"] >= now],
        key=lambda x: x[1]["expires"], reverse=True,
    )[:limit]
    return [
        {"ip": ip, "domain": v["domain"], "pattern": v.get("pattern", ""),
         "class": v["class"], "confidence": v["confidence"],
         "expires_in": int(v["expires"] - now)}
        for ip, v in items
    ]


def get_active_mappings(min_confidence=0.0, limit=1000):
    """返回当前可用于动态打标的 DNS IP 映射。"""
    now = time.time()
    try:
        min_confidence = float(min_confidence)
    except (ValueError, TypeError):
        min_confidence = 0.0
    items = sorted(
        [(ip, v) for ip, v in _cache.items() if v.get("expires", 0) >= now],
        key=lambda x: x[1].get("expires", 0), reverse=True,
    )
    result = []
    for ip, v in items[:max(0, int(limit or 0))]:
        cls = str(v.get("class", "other")).strip().lower()
        confidence = float(v.get("confidence", 0.0) or 0.0)
        if cls not in ("gaming", "streaming", "bulk"):
            continue
        if confidence < min_confidence:
            continue
        result.append({
            "ip": ip,
            "domain": v.get("domain", ""),
            "pattern": v.get("pattern", ""),
            "class": cls,
            "confidence": confidence,
            "expires_in": int(v.get("expires", now) - now),
        })
    return result


# ═══ 未匹配域名收集（用于 AI 规则扩充导出）═══

def _collect_unmatched(domain, ip_addr, cname_stack, now):
    """将未匹配任何规则的域名记录到 _unmatched。"""
    global _unmatched
    if not domain or not isinstance(domain, str):
        return
    domain = domain.strip().lower()
    if not domain or len(domain) > 255:
        return

    entry = _unmatched.get(domain)
    if entry is None:
        entry = {
            "count": 0,
            "first_seen": now,
            "last_seen": now,
            "sample_ips": [],
            "_subdomain_set": set(),
        }
        _unmatched[domain] = entry

    entry["count"] += 1
    entry["last_seen"] = now
    if len(entry["sample_ips"]) < UNMATCHED_MAX_SAMPLES and ip_addr not in entry["sample_ips"]:
        entry["sample_ips"].append(ip_addr)
    # 用内部 set 去重收集子域名样本
    sub_set = entry.setdefault("_subdomain_set", set())
    for mid_domain in cname_stack:
        mid = str(mid_domain or "").strip().lower()
        if mid and mid != domain and len(sub_set) < UNMATCHED_MAX_SAMPLES:
            sub_set.add(mid)
    entry["subdomain_samples"] = list(sub_set)


def _prune_unmatched(now):
    """清理过期的未匹配域名统计，超出容量上限时删除低频条目。"""
    global _unmatched
    cutoff = now - UNMATCHED_TTL
    expired = [d for d, v in _unmatched.items() if v["last_seen"] < cutoff]
    for d in expired:
        del _unmatched[d]
    if len(_unmatched) > MAX_UNMATCHED:
        sorted_by_count = sorted(_unmatched.items(), key=lambda x: x[1]["count"])
        to_remove = len(_unmatched) - MAX_UNMATCHED
        for d, _ in sorted_by_count[:to_remove]:
            del _unmatched[d]


def _suggest_pattern(domain, subdomain_samples):
    """根据原始域名和子域名样本，智能推测通配规则模式。"""
    def _norm(name):
        text = str(name or "").strip().lower().strip(".")
        return text

    def _labels(name):
        return [part for part in _norm(name).split(".") if part]

    domain = _norm(domain)
    subdomains = []
    for item in list(subdomain_samples or []):
        item = _norm(item)
        if item and item not in subdomains and item != domain:
            subdomains.append(item)

    if not domain:
        return ""
    if not subdomains:
        return domain

    # 对于 CNAME 最终域名，把更接近业务原始域名的“前缀样本”提出来。
    prefix_candidates = [
        item for item in subdomains
        if domain.startswith(item + ".")
    ]
    if prefix_candidates:
        domain = sorted(prefix_candidates, key=lambda x: (-len(_labels(x)), len(x)))[0]

    related = [domain]
    for item in subdomains:
        if item not in related:
            related.append(item)

    labels = _labels(domain)
    if len(labels) < 2:
        return domain

    # 从“尽量具体”的后缀往“更泛”的后缀试，只要能得到合法通配规则才返回。
    for start in range(0, len(labels) - 1):
        suffix = ".".join(labels[start:])
        support = sum(
            1 for item in related
            if item == suffix or item.endswith("." + suffix)
        )
        if support < 2:
            continue

        wildcard = "*." + suffix
        valid, _ = _validate_pattern(wildcard)
        if valid:
            return wildcard

    return domain


def get_unmatched_stats(min_count=3, limit=150):
    """导出未匹配域名 Top N 统计（用于 AI 分析和前端导出）。"""
    now = time.time()
    items = []
    for domain, entry in _unmatched.items():
        if entry["count"] < min_count:
            continue
        subdomain_samples = list(entry.get("subdomain_samples", []) or [])[:UNMATCHED_MAX_SAMPLES]
        items.append({
            "domain": domain,
            "count": entry["count"],
            "first_seen": entry["first_seen"],
            "last_seen": entry["last_seen"],
            "sample_ips": list(entry.get("sample_ips", []) or [])[:UNMATCHED_MAX_SAMPLES],
            "subdomain_samples": subdomain_samples,
            "suggested_pattern": _suggest_pattern(domain, subdomain_samples),
        })
    items.sort(key=lambda x: -x["count"])
    items = items[:max(1, min(int(limit), 500))]
    for i, item in enumerate(items):
        item["rank"] = i + 1
    return {
        "total_unmatched": len(_unmatched),
        "exported_top": len(items),
        "min_count": min_count,
        "time": int(now),
        "entries": items,
    }


# ═══ AI 规则导入 ═══

# 过宽 pattern 黑名单（拒绝导入）
TOO_BROAD_PATTERNS = {
    "*.com", "*.cn", "*.net", "*.org", "*.io", "*.co", "*.cc",
    "*.com.cn", "*.net.cn", "*.org.cn",
}

# 过宽二级泛域名（拒绝导入）
TOO_BROAD_PREFIXES = (
    "*.qq.com", "*.baidu.com", "*.taobao.com", "*.163.com",
    "*.alicdn.com", "*.qcloud.com", "*.aliyuncs.com", "*.cloudfront.net",
    "*.akamai.net", "*.fastly.net", "*.edgesuite.net",
)

import re as _re

_PATTERN_SAFE_RE = _re.compile(r"^[a-zA-Z0-9.\-_\*]+$")


def _validate_pattern(pattern):
    """校验 pattern 合法性。返回 (valid, error_reason)。"""
    if not pattern or not isinstance(pattern, str):
        return False, "pattern is empty"
    pattern = pattern.strip()
    if len(pattern) > 255:
        return False, "pattern too long (>255)"
    if not _PATTERN_SAFE_RE.match(pattern):
        return False, "pattern contains invalid characters"
    if pattern in ("*", "*.*"):
        return False, "pattern is too broad (* or *.*)"
    if pattern in TOO_BROAD_PATTERNS:
        return False, "pattern is too broad (TLD wildcard)"
    for prefix in TOO_BROAD_PREFIXES:
        if pattern == prefix or pattern.startswith(prefix):
            return False, f"pattern is too broad (matches {prefix})"
    # 检查合法 fnmatch 格式：至少包含一个点，或以星号开头
    if "*" not in pattern and "." not in pattern:
        return False, "pattern must contain a dot or wildcard"
    return True, ""


def import_ai_rules(rules_list, user_rules_path="/etc/sqm_controller/dns_rules.json"):
    """导入 AI 生成的规则到用户规则文件。

    校验 pattern 合法性、class、confidence，去重后写入 JSON 文件。
    返回详细导入结果。
    """
    valid_classes = {"streaming", "gaming", "bulk", "other"}
    result = {
        "success": True,
        "added": 0,
        "skipped_duplicate": 0,
        "skipped_invalid": 0,
        "skipped_too_broad": 0,
        "total_user_rules": 0,
        "warnings": [],
        "added_rules": [],
    }

    if not isinstance(rules_list, list):
        return {"success": False, "error": "rules must be a JSON array", "added": 0}

    # 加载已有用户规则（去重用）
    existing_rules = _load_user_rules(user_rules_path)
    existing_patterns = set(r[0] for r in existing_rules)
    # 内置规则 pattern（也去重）
    builtin_patterns = set(r[0] for r in DOMAIN_RULES)

    new_rules = []
    for item in rules_list:
        if not isinstance(item, dict):
            result["skipped_invalid"] += 1
            continue

        pattern = str(item.get("pattern", "")).strip()
        cls = str(item.get("class", "")).strip().lower()
        try:
            confidence = float(item.get("confidence", 0))
        except (ValueError, TypeError):
            result["skipped_invalid"] += 1
            continue
        reason = str(item.get("reason", "")).strip()

        # pattern 安全校验
        valid, err = _validate_pattern(pattern)
        if not valid:
            if "too broad" in err:
                result["skipped_too_broad"] += 1
                result["warnings"].append({"pattern": pattern, "reason": err})
            else:
                result["skipped_invalid"] += 1
            continue

        # class 校验
        if cls not in valid_classes:
            result["skipped_invalid"] += 1
            continue

        # confidence 范围校验
        confidence = max(0.0, min(1.0, confidence))

        # 去重
        if pattern in existing_patterns or pattern in builtin_patterns:
            result["skipped_duplicate"] += 1
            continue

        # 添加元数据
        new_rules.append({
            "pattern": pattern,
            "class": cls,
            "confidence": confidence,
            "source": "ai_import",
            "reason": reason,
            "created_at": int(time.time()),
            "enabled": True,
        })
        existing_patterns.add(pattern)
        result["added"] += 1
        result["added_rules"].append({"pattern": pattern, "class": cls, "confidence": confidence})

    if new_rules:
        # 合并已有规则
        all_rules = []
        try:
            if os.path.exists(user_rules_path):
                with open(user_rules_path, "r", encoding="utf-8") as fh:
                    existing_data = json.load(fh)
                    all_rules = existing_data if isinstance(existing_data, list) else existing_data.get("rules", [])
        except Exception:
            all_rules = []
        all_rules.extend(new_rules)
        try:
            directory = os.path.dirname(user_rules_path)
            if directory:
                os.makedirs(directory, exist_ok=True)
            with open(user_rules_path, "w", encoding="utf-8") as fh:
                json.dump(all_rules, fh, ensure_ascii=False, indent=2)
        except Exception as exc:
            return {"success": False, "error": f"failed to write rules: {exc}", "added": 0}

    result["total_user_rules"] = len(existing_patterns)
    return result


def self_test():
    test_domain = "cn-zjjh-ct-04-05.bilivideo.com"
    pattern, cls, conf = _match_domain_rules(test_domain)
    return {
        "ok": cls == "streaming" and conf > 0.8,
        "module": MODULE,
        "version": VERSION,
        "time": int(time.time()),
        "rules_count": len(DOMAIN_RULES),
        "cache_entries": len(_cache),
        "stats": dict(_stats),
        "sample_match": {"domain": test_domain, "pattern": pattern, "class": cls, "confidence": conf},
    }


def main():
    import argparse
    parser = argparse.ArgumentParser(description="SQM DNS 关联分类")
    parser.add_argument("--refresh", action="store_true", help="更新 DNS 缓存")
    parser.add_argument("--lookup", type=str, default="", help="查询指定 IP")
    parser.add_argument("--snapshot", type=int, default=0, help="输出缓存快照（N 条）")
    parser.add_argument("--stats", action="store_true", help="输出缓存统计")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--ttl", type=int, default=DEFAULT_TTL)
    args = parser.parse_args()

    if args.refresh:
        print(json.dumps(refresh(ttl=args.ttl), ensure_ascii=False))
    elif args.lookup:
        result = lookup(args.lookup)
        print(json.dumps({"ip": args.lookup, "result": result, "stats": dict(_stats)}, ensure_ascii=False))
    elif args.snapshot > 0:
        print(json.dumps({"snapshot": get_cache_snapshot(args.snapshot), "stats": dict(_stats)}, ensure_ascii=False))
    elif args.stats:
        print(json.dumps(dict(_stats), ensure_ascii=False))
    elif args.self_test:
        print(json.dumps(self_test(), ensure_ascii=False))
    else:
        print(json.dumps(self_test(), ensure_ascii=False))


if __name__ == "__main__":
    main()
