#!/bin/sh
# shellcheck shell=dash
# Summary of all active LAN devices with traffic control status.
# Output: JSON array with per-device info.
#
# Performance: all firewall/tc/conntrack state is fetched ONCE up front and
# reused per device, instead of re-dumping nft chains / re-reading conntrack
# inside the per-IP loop. On a router with many devices this turns O(N) heavy
# forks (one full conntrack read + two nft chain dumps + a tc call PER device)
# into a constant handful of calls.

. /usr/local/bin/trafficctl-fw.sh

CONN_CACHE="/tmp/trafficctl_conn_cache"
[ -f "$CONN_CACHE" ] || : > "$CONN_CACHE"

PORT_MAP_FILE="/tmp/.trafficctl_portmap.$$"
# shellcheck disable=SC2064
trap "rm -f '$PORT_MAP_FILE'" EXIT INT TERM

# Enumerate every LAN subnet (multi-bridge / multi-VLAN aware), once.
LAN_SUBNETS=$(tctl_lan_subnets)
[ -z "$LAN_SUBNETS" ] && { echo '[]'; exit 0; }
LAN_DEVS=$(echo "$LAN_SUBNETS" | awk '{print $1}' | sort -u)
# Membership spec for awk: "netbase:block:routerint ..." (no awk bit-ops needed)
MATCH_SPEC=$(echo "$LAN_SUBNETS" | awk '{printf "%s%s:%s:%s",(NR>1?" ":""),$2,$3,$4}')
# Device that carries the tc/HTB shaper (shaping is single-bridge by design).
PRIMARY_LAN_DEV=$(tctl_get_lan_device)

# Get WiFi station→interface mapping: "mac iface_name band"
get_wifi_stations() {
    iw dev 2>/dev/null | awk '/Interface/{print $2}' | while read -r iface; do
        local band=""
        local ch
        ch=$(iw dev "$iface" info 2>/dev/null | awk '/channel/{print $2}')
        if [ -n "$ch" ]; then
            if [ "$ch" -le 14 ] 2>/dev/null; then
                band="2.4G"
            elif [ "$ch" -le 177 ] 2>/dev/null; then
                band="5G"
            else
                band="6G"
            fi
        fi
        iw dev "$iface" station dump 2>/dev/null | awk -v iface="$iface" -v band="$band" \
            '/Station/{print tolower($2), iface, band}'
    done
}

# Get bridge MAC→port interface mapping across all LAN bridges: "mac port_iface"
get_bridge_macs() {
    local dev
    for dev in $LAN_DEVS; do
        [ -d "/sys/class/net/$dev/brif" ] || continue
        for pdir in /sys/class/net/"$dev"/brif/*/; do
            [ -d "$pdir" ] || continue
            local iface pno
            iface=$(basename "$pdir")
            pno=$(cat "${pdir}port_no" 2>/dev/null)
            [ -z "$pno" ] && continue
            printf "%d %s\n" "$(( pno ))" "$iface"
        done > "$PORT_MAP_FILE"
        brctl showmacs "$dev" 2>/dev/null | awk -v pmf="$PORT_MAP_FILE" '
        BEGIN { while ((getline line < pmf) > 0) { split(line, p, " "); portname[p[1]] = p[2] } }
        NR > 1 && $3 == "no" {
            mac = tolower($2)
            port = $1 + 0
            if (port in portname) print mac, portname[port]
        }'
    done
    rm -f "$PORT_MAP_FILE"
}

# ── Single conntrack pass ──────────────────────────────────────────────────
# Emit "ip total tcp udp conns" for every active LAN source in one read,
# replicating the previous per-IP accounting (original-direction bytes of the
# first tuple that belongs to a LAN device). Replaces N full conntrack reads.
CT_SUMMARY=$(awk -v spec="$MATCH_SPEC" '
function ip2int(ip,   a) {
    split(ip, a, ".")
    return a[1]*16777216 + a[2]*65536 + a[3]*256 + a[4]
}
# Return the index of the LAN subnet that contains ip, or 0.
function lan_idx(ip,   si, k) {
    si = ip2int(ip)
    for (k = 1; k <= ns; k++)
        if (si - (si % blk[k]) == base[k]) return k
    return 0
}
BEGIN {
    ns = split(spec, parts, " ")
    for (k = 1; k <= ns; k++) {
        split(parts[k], kv, ":")
        base[k] = kv[1] + 0; blk[k] = kv[2] + 0; rtr[k] = kv[3] + 0
    }
}
{
    proto=""
    for (i=1; i<=NF; i++) {
        if ($i == "tcp") proto="tcp"
        else if ($i == "udp") proto="udp"
    }
    # first src= field that belongs to one of our LAN subnets
    srcidx=0; src=""; sk=0
    for (i=1; i<=NF; i++) {
        if (index($i, "src=") == 1) {
            v=substr($i, 5)
            k=lan_idx(v)
            if (k > 0) { src=v; srcidx=i; sk=k; break }
        }
    }
    if (src == "") next
    si=ip2int(src)
    # skip the router itself, the network address and the broadcast address
    if (si == rtr[sk] || si == base[sk] || si == base[sk] + blk[sk] - 1) next
    seen=0; got_dst=0; found=0; b=0
    for (i=srcidx; i<=NF; i++) {
        if (i == srcidx) { seen=1; continue }
        if (seen && !got_dst && index($i, "dst=") == 1) {
            dst=substr($i, 5)
            if (dst != src) { got_dst=1 } else next
        }
        if (seen && got_dst && index($i, "bytes=") == 1) {
            b=substr($i, 7) + 0; found=1; break
        }
    }
    if (got_dst) {
        conns[src]++
        if (found) {
            total[src]+=b
            if (proto == "tcp") tcp[src]+=b
            else if (proto == "udp") udp[src]+=b
        }
    }
}
END {
    for (ip in conns)
        printf "%s %d %d %d %d\n", ip, total[ip]+0, tcp[ip]+0, udp[ip]+0, conns[ip]
}' /proc/net/nf_conntrack 2>/dev/null)

ACTIVE_IPS=$(echo "$CT_SUMMARY" | awk 'NF{print $1}' | sort -t. -k1,1n -k2,2n -k3,3n -k4,4n)
[ -z "$ACTIVE_IPS" ] && { echo '[]'; exit 0; }

# ── Prefetch all shared state once ─────────────────────────────────────────
NOW=$(date +%s)
LEASES=$(cat /tmp/dhcp.leases 2>/dev/null)
NEIGH=$(ip neigh show 2>/dev/null)

# Firewall dumps (IP-independent — fetched once, grepped per device below)
if [ "$TCTL_FW" = "nft" ]; then
    FWD_DUMP=$(nft list chain inet fw4 forward 2>/dev/null)
    RL_DUMP=$(nft list table netdev tm_ratelimit 2>/dev/null)
else
    FWD_DUMP=$(iptables -L FORWARD -nvx 2>/dev/null)
    RL_DUMP=$(iptables -t mangle -L FORWARD -nv 2>/dev/null)
fi

# tc HTB classes → "classid rate_kbit" map (one tc call, parsed once)
TC_MAP=""
if command -v tc >/dev/null 2>&1; then
    TC_MAP=$(tc class show dev "$PRIMARY_LAN_DEV" 2>/dev/null | awk '
    /^class htb 1:/ {
        classid=$3
        minor=classid; sub(/^1:/,"",minor)
        if (minor=="1" || minor=="fffe") next
        rate=0
        for (i=1;i<=NF;i++) {
            if ($i=="rate") {
                v=$(i+1)
                if (v ~ /Gbit/)       { sub(/Gbit/,"",v);   rate=(v+0)*1000000 }
                else if (v ~ /Mbit/)  { sub(/Mbit/,"",v);   rate=(v+0)*1000 }
                else if (v ~ /[Kk]bit/){ sub(/[Kk]bit/,"",v); rate=v+0 }
                break
            }
        }
        print classid, rate
    }')
fi

# All wifi maclists concatenated (a device is wifi-blocked if its MAC is in any)
WIFI_MACLISTS=$(uci -q show wireless 2>/dev/null | grep '\.maclist=')

WIFI_STATIONS=$(get_wifi_stations)
BRIDGE_MACS=$(get_bridge_macs)

# ── Per-device helpers (operate on prefetched blobs, no new forks of nft/tc) ─
lookup_name() {
    echo "$LEASES" | awk -v ip="$1" '$3 == ip {print $4; exit}'
}

lookup_mac() {
    local ip="$1" mac
    mac=$(echo "$LEASES" | awk -v ip="$ip" '$3 == ip {print $2; exit}')
    [ -z "$mac" ] && mac=$(echo "$NEIGH" | awk -v ip="$ip" '$1 == ip {for(i=1;i<=NF;i++)if($i=="lladdr"){print $(i+1);exit}}')
    echo "$mac" | tr 'A-F' 'a-f'
}

lookup_blocked() {
    local ip="$1"
    if [ "$TCTL_FW" = "nft" ]; then
        echo "$FWD_DUMP" | grep -q "ip saddr $ip .*drop" && echo 1 || echo 0
    else
        echo "$FWD_DUMP" | grep "$ip" | grep -q "DROP" && echo 1 || echo 0
    fi
}

lookup_block_bytes() {
    local ip="$1" b
    if [ "$TCTL_FW" = "nft" ]; then
        b=$(echo "$FWD_DUMP" | grep "ip saddr $ip" | grep -oE 'bytes [0-9]+' | awk '{print $2}' | head -1)
    else
        b=$(echo "$FWD_DUMP" | grep "DROP" | grep "$ip" | awk '{print $2}' | head -1)
    fi
    echo "${b:-0}"
}

lookup_rate_limit() {
    local ip="$1" r
    if [ "$TCTL_FW" = "nft" ]; then
        r=$(echo "$RL_DUMP" | grep "daddr $ip" | grep -oE '[0-9]+ kbytes' | awk '{print $1 * 8}')
    else
        r=$(echo "$RL_DUMP" | grep "rl_ratelimit" | grep "$ip" | grep -oE '[0-9]+kbit' | head -1 | sed 's/kbit//')
    fi
    echo "${r:-0}"
}

lookup_shape_kbit() {
    local ip="$1" o3 o4 dec hex classid r
    o3=$(echo "$ip" | cut -d. -f3)
    o4=$(echo "$ip" | cut -d. -f4)
    dec=$((o3 * 256 + o4))
    hex=$(printf "%x" "$dec")
    case "$hex" in 1|fffe) echo 0; return ;; esac
    classid="1:$hex"
    r=$(echo "$TC_MAP" | awk -v c="$classid" '$1==c{print $2; exit}')
    echo "${r:-0}"
}

lookup_wifi_blocked() {
    local mac="$1"
    [ -z "$mac" ] && { echo 0; return; }
    echo "$WIFI_MACLISTS" | grep -qi "$mac" && echo 1 || echo 0
}

# ── Emit JSON ──────────────────────────────────────────────────────────────
printf "["
FIRST=1
for ip in $ACTIVE_IPS; do
    # shellcheck disable=SC2046 # deliberate split into 4 positional fields
    set -- $(echo "$CT_SUMMARY" | awk -v ip="$ip" '$1==ip{print $2,$3,$4,$5; exit}')
    TOTAL="${1:-0}"; TCP="${2:-0}"; UDP="${3:-0}"; CONNS="${4:-0}"

    NAME=$(lookup_name "$ip")
    MAC=$(lookup_mac "$ip")
    BLOCKED=$(lookup_blocked "$ip")
    BLOCK_BYTES=$(lookup_block_bytes "$ip")
    WIFI_BLK=$(lookup_wifi_blocked "$MAC")
    RATE_LIM=$(lookup_rate_limit "$ip")
    SHAPE=$(lookup_shape_kbit "$ip")
    [ -z "$NAME" ] && NAME="*"

    CONN_TYPE=""
    CONN_LAST=""
    if [ -n "$MAC" ]; then
        _wl=$(echo "$WIFI_STATIONS" | grep -i "$MAC")
        if [ -n "$_wl" ]; then
            _band=$(echo "$_wl" | awk '{print $3}')
            CONN_TYPE="${_band:-wifi}"
        else
            _bl=$(echo "$BRIDGE_MACS" | grep -i "$MAC")
            if [ -n "$_bl" ]; then
                _piface=$(echo "$_bl" | awk '{print $2}')
                case "$_piface" in
                    phy*|wlan*) CONN_TYPE="wifi" ;;
                    *) CONN_TYPE="$_piface" ;;
                esac
            fi
        fi
    fi
    if [ -n "$CONN_TYPE" ]; then
        sed -i "/^$ip /d" "$CONN_CACHE" 2>/dev/null
        echo "$ip $CONN_TYPE $NOW" >> "$CONN_CACHE"
    else
        _arp_state=$(echo "$NEIGH" | awk -v ip="$ip" '$1==ip{print $NF; exit}')
        case "$_arp_state" in
            REACHABLE|STALE|DELAY|PROBE) CONN_TYPE="ethernet" ;;
            *)
                CONN_TYPE="?"
                _cached=$(grep "^$ip " "$CONN_CACHE" 2>/dev/null | tail -1)
                if [ -n "$_cached" ]; then
                    CONN_LAST=$(echo "$_cached" | awk '{print $2 "@" $3}')
                fi
                ;;
        esac
    fi

    if [ "$FIRST" = "1" ]; then
        FIRST=0
    else
        printf ","
    fi
    printf '{"ip":"%s","name":"%s","mac":"%s","conn_type":"%s","conn_last":"%s","conns":%d,"total":%d,"tcp":%d,"udp":%d,"blocked":%s,"block_bytes":%d,"wifi_blocked":%s,"rate_limit_kbit":%d,"shape_kbit":%d}' \
        "$ip" "$NAME" "$MAC" "$CONN_TYPE" "$CONN_LAST" "$CONNS" "$TOTAL" "$TCP" "$UDP" \
        "$([ "$BLOCKED" = "1" ] && echo true || echo false)" \
        "$BLOCK_BYTES" \
        "$([ "$WIFI_BLK" = "1" ] && echo true || echo false)" \
        "$RATE_LIM" "$SHAPE"
done
printf "]\n"
