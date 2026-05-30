#!/bin/bash
# Unit tests for Telegram bot integration.

PASS=0
FAIL=0

assert_eq() {
    local desc="$1" expected="$2" actual="$3"
    if [ "$expected" = "$actual" ]; then
        PASS=$((PASS + 1))
    else
        FAIL=$((FAIL + 1))
        printf "FAIL: %s\n  expected: '%s'\n  actual:   '%s'\n" "$desc" "$expected" "$actual"
    fi
}

# ── Token format validation ─────────────────────────────────────────────────

validate_token() {
    echo "$1" | grep -qE '^[0-9]+:[A-Za-z0-9_-]+$' && echo 0 || echo 1
}

assert_eq "valid token 123456:ABCdef" "0" "$(validate_token '123456:ABCdef')"
assert_eq "valid token long" "0" "$(validate_token '7104583920:AAF_x9k-Lm2NpQ3rS5tU7vW')"
assert_eq "valid token with underscore/dash" "0" "$(validate_token '100:A_b-C')"
assert_eq "invalid token empty" "1" "$(validate_token '')"
assert_eq "invalid token no colon" "1" "$(validate_token '123456ABCdef')"
assert_eq "invalid token spaces" "1" "$(validate_token '123456:ABC def')"
assert_eq "invalid token special chars" "1" "$(validate_token '123456:ABC!@#')"
assert_eq "invalid token no bot id" "1" "$(validate_token ':ABCdef')"
assert_eq "invalid token injection" "1" "$(validate_token '123; rm -rf /')"

# ── Chat ID validation ──────────────────────────────────────────────────────

validate_chat_id() {
    echo "$1" | grep -qE '^-?[0-9]+$' && echo 0 || echo 1
}

assert_eq "valid chat_id positive" "0" "$(validate_chat_id '123456789')"
assert_eq "valid chat_id negative (group)" "0" "$(validate_chat_id '-100123456789')"
assert_eq "invalid chat_id empty" "1" "$(validate_chat_id '')"
assert_eq "invalid chat_id letters" "1" "$(validate_chat_id 'abc123')"
assert_eq "invalid chat_id spaces" "1" "$(validate_chat_id '123 456')"
assert_eq "invalid chat_id injection" "1" "$(validate_chat_id '123;whoami')"

# ── Callback data parsing ───────────────────────────────────────────────────

parse_verb()  { echo "$1" | cut -d: -f2; }
parse_ip()    { echo "$1" | cut -d: -f3; }
parse_param() { echo "$1" | cut -d: -f4; }

assert_eq "cb parse verb: menu" "menu" "$(parse_verb 'act:menu:192.168.0.1')"
assert_eq "cb parse ip" "192.168.0.1" "$(parse_ip 'act:menu:192.168.0.1')"
assert_eq "cb parse verb: limit" "limit" "$(parse_verb 'act:limit:192.168.0.1:10000')"
assert_eq "cb parse param: rate" "10000" "$(parse_param 'act:limit:192.168.0.1:10000')"
assert_eq "cb parse verb: back" "back" "$(parse_verb 'act:back')"
assert_eq "cb parse ip: back empty" "" "$(parse_ip 'act:back')"

# ── Callback data length (Telegram limit: 64 bytes) ────────────────────────

check_cb_len() {
    local data="$1"
    [ "${#data}" -le 64 ] && echo 0 || echo 1
}

assert_eq "cb len: menu" "0" "$(check_cb_len 'act:menu:192.168.255.255')"
assert_eq "cb len: limit max" "0" "$(check_cb_len 'act:limit:192.168.255.255:100000')"
assert_eq "cb len: shape max" "0" "$(check_cb_len 'act:shape:192.168.255.255:100000')"
assert_eq "cb len: back" "0" "$(check_cb_len 'act:back')"

# ── Known devices JSON manipulation ─────────────────────────────────────────

TMPDIR=$(mktemp -d)
KNOWN_TEST="$TMPDIR/known.json"
trap 'rm -rf "$TMPDIR"' EXIT

echo '[]' > "$KNOWN_TEST"

# is_known (grep-based, same as daemon)
is_known() { grep -q "\"$1\"" "$KNOWN_TEST" 2>/dev/null && echo 1 || echo 0; }

assert_eq "empty known: not found" "0" "$(is_known 'aa:bb:cc:dd:ee:ff')"

# add first device
printf '[{"mac":"aa:bb:cc:dd:ee:ff","name":"test1","ip":"192.168.0.1"}]' > "$KNOWN_TEST"
assert_eq "known: found after add" "1" "$(is_known 'aa:bb:cc:dd:ee:ff')"
assert_eq "known: other not found" "0" "$(is_known '11:22:33:44:55:66')"

# add second device (same pattern as daemon: sed append)
sed 's/\]$/,{"mac":"11:22:33:44:55:66","name":"test2","ip":"192.168.0.2"}]/' \
    "$KNOWN_TEST" > "${KNOWN_TEST}.tmp" && mv "${KNOWN_TEST}.tmp" "$KNOWN_TEST"
assert_eq "known: second found" "1" "$(is_known '11:22:33:44:55:66')"
assert_eq "known: first still found" "1" "$(is_known 'aa:bb:cc:dd:ee:ff')"

# ── Results ─────────────────────────────────────────────────────────────────

echo ""
echo "Results: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] || exit 1
