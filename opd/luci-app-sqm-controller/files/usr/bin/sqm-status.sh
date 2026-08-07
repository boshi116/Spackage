#!/bin/sh

echo "=== SQM状态 ==="
python3 /usr/lib/sqm-controller/main.py --status-json

echo ""
echo "TC规则:"
tc qdisc show dev $(uci get sqm_controller.basic_config.interface) 2>/dev/null
tc qdisc show dev ifb0 2>/dev/null || echo "无 ifb0"
