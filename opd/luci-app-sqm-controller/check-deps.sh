#!/bin/sh

CONFIG_FILE="/etc/config/sqm_controller"

check_package() {
    if ! opkg list-installed | grep -q "^$1 "; then
        echo "Missing package: $1"
        return 1
    fi
    return 0
}

check_command() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "Missing command: $1"
        return 1
    fi
    return 0
}

read_backend() {
    if [ -f "$CONFIG_FILE" ]; then
        uci -q get sqm_controller.classification.backend 2>/dev/null
    fi
}

read_queue_backend() {
    if [ -f "$CONFIG_FILE" ]; then
        uci -q get sqm_controller.basic_config.queue_backend 2>/dev/null
    fi
}

REQUIRED_PKGS="
python3
python3-light
curl
ca-bundle
kmod-ifb
kmod-sched-core
kmod-sched-cake
kmod-sched-connmark
kmod-sched-ctinfo
luci-base
luci-compat
luci-lib-ip
luci-lib-nixio
"

REQUIRED_CMDS="
python3
tc
ip
uci
"

MISSING=""
for pkg in $REQUIRED_PKGS; do
    if ! check_package "$pkg"; then
        MISSING="$MISSING $pkg"
    fi
done

for cmd in $REQUIRED_CMDS; do
    if ! check_command "$cmd"; then
        MISSING="$MISSING [cmd:$cmd]"
    fi
done

backend="$(read_backend | tr -d '\r\n' | tr 'A-Z' 'a-z')"
queue_backend="$(read_queue_backend | tr -d '\r\n' | tr 'A-Z' 'a-z')"
case "$backend" in
    nft)
        if ! check_command nft; then
            MISSING="$MISSING [cmd:nft]"
        fi
        ;;
    iptables)
        if ! check_command iptables; then
            MISSING="$MISSING [cmd:iptables]"
        fi
        ;;
    "")
        if ! command -v nft >/dev/null 2>&1 && ! command -v iptables >/dev/null 2>&1; then
            echo "Missing command: nft or iptables"
            MISSING="$MISSING [cmd:nft|iptables]"
        fi
        ;;
    *)
        echo "Invalid configured backend: $backend"
        MISSING="$MISSING [backend:$backend]"
        ;;
esac

case "$queue_backend" in
    nss)
        for pkg in sqm-scripts sqm-scripts-nss kmod-qca-nss-drv-qdisc kmod-qca-nss-drv-igs; do
            if ! check_package "$pkg"; then
                MISSING="$MISSING $pkg"
            fi
        done
        if [ ! -f /usr/lib/sqm/nss-zk.qos ]; then
            echo "Missing NSS script: /usr/lib/sqm/nss-zk.qos"
            MISSING="$MISSING [file:nss-zk.qos]"
        fi
        if [ ! -x /usr/lib/sqm-controller/nss_detect.py ]; then
            echo "Missing NSS detector: /usr/lib/sqm-controller/nss_detect.py"
            MISSING="$MISSING [file:nss_detect.py]"
        elif ! python3 /usr/lib/sqm-controller/nss_detect.py nss 2>/dev/null | grep -q '"resolved_backend": "nss"'; then
            echo "NSS runtime detection failed"
            MISSING="$MISSING [runtime:nss]"
        fi
        ;;
    auto|software|"")
        ;;
    *)
        echo "Invalid queue backend: $queue_backend"
        MISSING="$MISSING [queue_backend:$queue_backend]"
        ;;
esac

if [ -n "$MISSING" ]; then
    echo "Dependency check failed:$MISSING"
    echo "Configured backend: ${backend:-auto}"
    echo "Configured queue backend: ${queue_backend:-auto}"
    exit 1
fi

echo "All dependencies satisfied"
echo "Configured backend: ${backend:-auto}"
echo "Configured queue backend: ${queue_backend:-auto}"
exit 0
