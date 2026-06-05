#!/bin/sh
# shellcheck shell=dash
# Per-device byte counters from conntrack (for speed calculation).
# Output: JSON array [{"ip":"...","bytes_in":N,"bytes_out":N}]

. /usr/local/bin/trafficctl-fw.sh

# Any offload mode (software, hardware, hardware-counter) bypasses conntrack counters
# for fast-path packets. Use nftables counters at forward priority -200 (before the
# flowtable at -150) which capture every packet regardless of offload state.
# Only pure "none" mode has accurate conntrack counters.
_offload=$(tctl_get_offload_mode)
[ "$_offload" != "none" ] && [ "$TCTL_FW" = "nft" ] && exec /usr/local/bin/trafficctl-bytes-nft.sh

LAN_DEV=$(tctl_get_lan_device)
LAN_SUBNET=$(ip -4 addr show dev "$LAN_DEV" 2>/dev/null | grep -oE 'inet [0-9.]+' | head -1 | awk '{print $2}')
LAN_PREFIX=$(echo "$LAN_SUBNET" | cut -d. -f1-3)

[ -z "$LAN_PREFIX" ] && { echo '[]'; exit 0; }

cat /proc/net/nf_conntrack 2>/dev/null | awk -v prefix="$LAN_PREFIX" '
BEGIN { printf "[" }
{
    src=""; bytes_orig=0; bytes_reply=0; bc=0
    for (i=1; i<=NF; i++) {
        if ($i ~ /^src=/) {
            v = substr($i, 5)
            if (v ~ "^"prefix"\\." && src == "") src = v
        }
        if ($i ~ /^bytes=/) {
            v = substr($i, 7) + 0
            bc++
            if (src != "" && bc == 1) bytes_orig = v
            else if (src != "" && bc == 2) bytes_reply = v
        }
    }
    if (src != "" && src ~ "^"prefix"\\.") {
        key = src
        in_total[key] += bytes_reply
        out_total[key] += bytes_orig
    }
}
END {
    n = 0
    for (ip in in_total) {
        if (n > 0) printf ","
        printf "{\"ip\":\"%s\",\"bytes_in\":%d,\"bytes_out\":%d}", ip, in_total[ip], out_total[ip]
        n++
    }
    printf "]\n"
}
'
