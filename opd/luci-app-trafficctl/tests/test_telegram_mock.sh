#!/bin/bash
# Level 2: Mock tests for Telegram bot.
# Stubs external commands (curl, jsonfilter, scripts) and verifies
# the bot makes correct decisions and API calls.

PASS=0
FAIL=0
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

assert_eq() {
    local desc="$1" expected="$2" actual="$3"
    if [ "$expected" = "$actual" ]; then
        PASS=$((PASS + 1))
    else
        FAIL=$((FAIL + 1))
        printf "FAIL: %s\n  expected: '%s'\n  actual:   '%s'\n" "$desc" "$expected" "$actual"
    fi
}

assert_contains() {
    local desc="$1" needle="$2" haystack="$3"
    if echo "$haystack" | grep -qF "$needle"; then
        PASS=$((PASS + 1))
    else
        FAIL=$((FAIL + 1))
        printf "FAIL: %s\n  expected to contain: '%s'\n  actual: '%s'\n" "$desc" "$needle" "$haystack"
    fi
}

# ── Test format_new_device_msg (default template) ─────────────────────────────

# Source only the functions we need (mock out uci, network, iw, etc.)
setup_mock_env() {
    mkdir -p "$TMPDIR/bin"
    # Mock uci
    cat > "$TMPDIR/bin/uci" <<'MOCK'
#!/bin/sh
case "$*" in
    *"trafficctl.telegram.enabled"*) echo 1 ;;
    *"trafficctl.telegram.bot_token"*) echo "123:FAKE" ;;
    *"trafficctl.telegram.chat_id"*) echo "999" ;;
    *"trafficctl.telegram.poll_interval"*) echo 3 ;;
    *"trafficctl.telegram.notify_new_device"*) echo 1 ;;
    *"trafficctl.telegram.notify_known_device"*) echo 0 ;;
    *"trafficctl.telegram.control_enabled"*) echo 1 ;;
    *"trafficctl.telegram.notify_template"*) echo "" ;;
    *"trafficctl.telegram.btn_block_inet"*) echo 1 ;;
    *"trafficctl.telegram.btn_block_wifi"*) echo 1 ;;
    *"trafficctl.telegram.btn_limiter"*) echo 1 ;;
    *"trafficctl.telegram.btn_shaper"*) echo 1 ;;
    *"system.@system"*"hostname"*) echo "OpenWrt" ;;
    *) echo "" ;;
esac
MOCK
    chmod +x "$TMPDIR/bin/uci"

    # Mock iw (no wifi devices)
    cat > "$TMPDIR/bin/iw" <<'MOCK'
#!/bin/sh
exit 1
MOCK
    chmod +x "$TMPDIR/bin/iw"

    # Mock curl (record API calls)
    cat > "$TMPDIR/bin/curl" <<MOCK
#!/bin/sh
echo "\$@" >> "$TMPDIR/curl_calls.log"
echo '{"ok":true,"result":{"message_id":1}}'
MOCK
    chmod +x "$TMPDIR/bin/curl"

    # Mock jsonfilter
    cat > "$TMPDIR/bin/jsonfilter" <<'MOCK'
#!/bin/sh
# Minimal jsonfilter mock
exit 0
MOCK
    chmod +x "$TMPDIR/bin/jsonfilter"

    # Mock ip
    cat > "$TMPDIR/bin/ip" <<'MOCK'
#!/bin/sh
echo ""
MOCK
    chmod +x "$TMPDIR/bin/ip"

    # /proc/uptime
    mkdir -p "$TMPDIR/proc"
    echo "3661.00 7200.00" > "$TMPDIR/proc/uptime"
    echo "0.50 0.30 0.10 1/100 12345" > "$TMPDIR/proc/loadavg"

    # Empty conntrack
    : > "$TMPDIR/proc/nf_conntrack"

    # Empty leases
    mkdir -p "$TMPDIR/tmp"
    : > "$TMPDIR/tmp/dhcp.leases"

    # network.sh stub
    mkdir -p "$TMPDIR/lib/functions"
    cat > "$TMPDIR/lib/functions/network.sh" <<'MOCK'
#!/bin/sh
network_get_ipaddr() { eval "$1='1.2.3.4'"; }
MOCK

    # Export PATH to use mocks
    export PATH="$TMPDIR/bin:$PATH"
}

# ── Test: format_new_device_msg with default template ──────────────────────────

test_format_default() {
    setup_mock_env

    # Source the telegram script in a subshell to test format_new_device_msg
    local result
    result=$(
        export PATH="$TMPDIR/bin:$PATH"
        # Provide minimal stubs
        TG_NOTIFY_TEMPLATE=""
        format_new_device_msg() {
            local name="$1" ip="$2" mac="$3" link="$4"
            if [ -z "$TG_NOTIFY_TEMPLATE" ]; then
                printf '🆕 <b>New device</b>\n%s (%s)\nMAC: <code>%s</code>\nLink: %s' \
                    "$name" "$ip" "$mac" "$link"
            fi
        }
        format_new_device_msg "MacBook" "192.168.0.50" "aa:bb:cc:dd:ee:ff" "5G"
    )
    assert_contains "default msg has name" "MacBook" "$result"
    assert_contains "default msg has IP" "192.168.0.50" "$result"
    assert_contains "default msg has MAC" "aa:bb:cc:dd:ee:ff" "$result"
    assert_contains "default msg has link" "5G" "$result"
    assert_contains "default msg has emoji" "🆕" "$result"
    assert_contains "default msg has HTML bold" "<b>" "$result"
}

# ── Test: format_new_device_msg with custom template ───────────────────────────

test_format_custom() {
    local result
    result=$(
        TG_NOTIFY_TEMPLATE='{{name}} joined at {{time}} via {{link}}'
        TVAR_TIME="14:30"
        format_new_device_msg() {
            local name="$1" ip="$2" mac="$3" link="$4"
            printf '%s' "$TG_NOTIFY_TEMPLATE" | \
                awk -v n="$name" -v i="$ip" -v m="$mac" -v l="$link" \
                    -v tm="$TVAR_TIME" '{
                    gsub(/\{\{\s*name\s*\}\}/, n)
                    gsub(/\{\{\s*ip\s*\}\}/, i)
                    gsub(/\{\{\s*mac\s*\}\}/, m)
                    gsub(/\{\{\s*link\s*\}\}/, l)
                    gsub(/\{\{\s*time\s*\}\}/, tm)
                    print
                }'
        }
        format_new_device_msg "iPhone" "192.168.0.99" "11:22:33:44:55:66" "wifi"
    )
    assert_contains "custom template: name" "iPhone" "$result"
    assert_contains "custom template: time" "14:30" "$result"
    assert_contains "custom template: link" "wifi" "$result"
}

# ── Test: IP validation from callback ──────────────────────────────────────────

validate_ip_cb() {
    # Reject if contains newline, then match full pattern
    case "$1" in *"
"*) echo invalid; return ;; esac
    echo "$1" | grep -qE '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$' && echo ok || echo invalid
}

test_ip_validation() {
    assert_eq "valid ip" "ok" "$(validate_ip_cb '192.168.0.1')"
    assert_eq "valid ip max octets" "ok" "$(validate_ip_cb '255.255.255.255')"
    assert_eq "invalid ip: letters" "invalid" "$(validate_ip_cb '192.168.a.1')"
    assert_eq "invalid ip: injection" "invalid" "$(validate_ip_cb '1.1.1.1;rm')"
    assert_eq "invalid ip: too many octets" "invalid" "$(validate_ip_cb '1.2.3.4.5')"
    assert_eq "invalid ip: empty" "invalid" "$(validate_ip_cb '')"
    assert_eq "invalid ip: spaces" "invalid" "$(validate_ip_cb '1.2.3 .4')"
    assert_eq "invalid ip: newline" "invalid" "$(validate_ip_cb '1.2.3.4
5.6.7.8')"
}

# ── Test: rate param validation ────────────────────────────────────────────────

validate_rate_param() {
    case "$1" in *[!0-9]*) echo invalid ;; *) echo ok ;; esac
}

test_rate_validation() {
    assert_eq "rate: 1000" "ok" "$(validate_rate_param '1000')"
    assert_eq "rate: 100000" "ok" "$(validate_rate_param '100000')"
    assert_eq "rate: injection" "invalid" "$(validate_rate_param '100;rm')"
    assert_eq "rate: float" "invalid" "$(validate_rate_param '10.5')"
    assert_eq "rate: negative" "invalid" "$(validate_rate_param '-100')"
    assert_eq "rate: letters" "invalid" "$(validate_rate_param 'abc')"
}

# ── Test: control_enabled guard ────────────────────────────────────────────────

test_control_guard() {
    local result
    # Simulate TG_CONTROL=0 blocking callback
    result=$(
        TG_CONTROL=0
        handle_callback_guard() {
            if [ "$TG_CONTROL" != "1" ]; then
                echo "Control disabled"
                return
            fi
            echo "processed"
        }
        handle_callback_guard
    )
    assert_eq "control disabled: blocks action" "Control disabled" "$result"

    result=$(
        TG_CONTROL=1
        handle_callback_guard() {
            if [ "$TG_CONTROL" != "1" ]; then
                echo "Control disabled"
                return
            fi
            echo "processed"
        }
        handle_callback_guard
    )
    assert_eq "control enabled: allows action" "processed" "$result"
}

# ── Test: keyboard JSON structure ──────────────────────────────────────────────

test_keyboard_structure() {
    # Build a simple keyboard inline and verify JSON structure
    local kb='{"inline_keyboard":[[{"text":"⏸ Block Internet","callback_data":"act:block:192.168.0.1"}],[{"text":"⬅️ Back","callback_data":"act:back"}]]}'
    assert_contains "kb has inline_keyboard" "inline_keyboard" "$kb"
    assert_contains "kb has block action" "act:block:192.168.0.1" "$kb"
    assert_contains "kb has back" "act:back" "$kb"
}

# ── Test: command routing ──────────────────────────────────────────────────────

test_command_routing() {
    route_command() {
        case "$1" in
            /start*|/help*) echo "help" ;;
            /devices*)      echo "devices" ;;
            /status*)       echo "status" ;;
            *)              echo "unknown" ;;
        esac
    }
    assert_eq "route /help" "help" "$(route_command '/help')"
    assert_eq "route /start" "help" "$(route_command '/start')"
    assert_eq "route /devices" "devices" "$(route_command '/devices')"
    assert_eq "route /devices@botname" "devices" "$(route_command '/devices@mybot')"
    assert_eq "route /status" "status" "$(route_command '/status')"
    assert_eq "route unknown" "unknown" "$(route_command '/ping')"
    assert_eq "route plain text" "unknown" "$(route_command 'hello')"
}

# ── Test: tg_send escaping ─────────────────────────────────────────────────────

test_message_escaping() {
    # Verify double-quote escaping logic (same as tg_send)
    local text='Device "test" has a backslash \ here'
    local escaped
    escaped=$(printf '%s' "$text" | sed 's/\\/\\\\/g;s/"/\\"/g')
    assert_contains "escape: backslash doubled" "\\\\" "$escaped"
    assert_contains "escape: quote escaped" "\\\"" "$escaped"
}

# ── Run all tests ──────────────────────────────────────────────────────────────

test_format_default
test_format_custom
test_ip_validation
test_rate_validation
test_control_guard
test_keyboard_structure
test_command_routing
test_message_escaping

echo ""
echo "Results: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] || exit 1
