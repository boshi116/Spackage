local sys = require "luci.sys"
local util = require "luci.util"
local translate = luci.i18n.translate
local INITD = "/etc/init.d/sqm-controller"

local function trim_uci_value(value)
    value = tostring(value or "")
    value = value:gsub("%s+$", "")
    if value == "" then
        return nil
    end
    return value
end

local function get_basic_config_snapshot()
    return {
        enabled = trim_uci_value(sys.exec("uci -q get sqm_controller.basic_config.enabled 2>/dev/null")),
        interface = trim_uci_value(sys.exec("uci -q get sqm_controller.basic_config.interface 2>/dev/null")),
        download_speed = trim_uci_value(sys.exec("uci -q get sqm_controller.basic_config.download_speed 2>/dev/null")),
        upload_speed = trim_uci_value(sys.exec("uci -q get sqm_controller.basic_config.upload_speed 2>/dev/null")),
        queue_algorithm = trim_uci_value(sys.exec("uci -q get sqm_controller.basic_config.queue_algorithm 2>/dev/null"))
    }
end

local function set_basic_config_value(option, value)
    local key = "sqm_controller.basic_config." .. option
    if value == nil or value == "" then
        return sys.call("uci -q delete " .. key .. " >/dev/null 2>&1")
    end
    return sys.call("uci -q set " .. key .. "=" .. util.shellquote(value))
end

local function restore_basic_config(snapshot)
    local rc = 0
    local options = { "enabled", "interface", "download_speed", "upload_speed", "queue_algorithm" }
    for _, option in ipairs(options) do
        rc = rc + set_basic_config_value(option, snapshot[option])
    end
    rc = rc + sys.call("uci -q commit sqm_controller")
    return rc
end

local function runtime_related_basic_change(before, after)
    local options = { "enabled", "interface", "download_speed", "upload_speed", "queue_algorithm" }
    for _, option in ipairs(options) do
        if tostring(before[option] or "") ~= tostring(after[option] or "") then
            return true
        end
    end
    return false
end

local function managed_runtime_running(iface)
    iface = tostring(iface or "")
    if iface == "" then
        return false
    end

    local wan_qdisc = sys.exec("tc qdisc show dev " .. util.shellquote(iface) .. " 2>/dev/null")
    local ifb_qdisc = sys.exec("tc qdisc show dev ifb0 2>/dev/null")
    if tostring(wan_qdisc or ""):find("qdisc htb 1:", 1, true) then
        return true
    end
    if tostring(ifb_qdisc or ""):find("qdisc htb 2:", 1, true) then
        return true
    end
    return false
end

local function parse_tc_rate_kbit(text)
    local value, unit = tostring(text or ""):match("rate%s+([0-9%.]+)([KMG])bit")
    value = tonumber(value)
    if not value then
        return nil
    end
    if unit == "G" then
        return math.floor(value * 1000000 + 0.5)
    end
    if unit == "M" then
        return math.floor(value * 1000 + 0.5)
    end
    return math.floor(value + 0.5)
end

local function merged_basic_config(after, requested)
    if type(requested) ~= "table" then
        return after
    end

    return {
        enabled = requested.enabled ~= nil and tostring(requested.enabled) or after.enabled,
        interface = requested.interface or after.interface,
        download_speed = requested.download_speed or after.download_speed,
        upload_speed = requested.upload_speed or after.upload_speed,
        queue_algorithm = requested.queue_algorithm or after.queue_algorithm,
    }
end

local function managed_runtime_matches(target)
    target = target or {}
    local iface = tostring(target.interface or "")
    if iface == "" then
        return false
    end

    local wan_qdisc = sys.exec("tc qdisc show dev " .. util.shellquote(iface) .. " 2>/dev/null")
    local ifb_qdisc = sys.exec("tc qdisc show dev ifb0 2>/dev/null")
    local wan_class = sys.exec("tc class show dev " .. util.shellquote(iface) .. " 2>/dev/null")
    local ifb_class = sys.exec("tc class show dev ifb0 2>/dev/null")

    local upload_runtime = parse_tc_rate_kbit((wan_class or ""):match("class htb 1:1.-\n") or wan_class)
    local download_runtime = parse_tc_rate_kbit((ifb_class or ""):match("class htb 2:1.-\n") or ifb_class)
    local upload_target = tonumber(target.upload_speed or "")
    local download_target = tonumber(target.download_speed or "")
    local algo = tostring(target.queue_algorithm or "fq_codel")

    local upload_algo_ok = tostring(wan_qdisc or ""):find("qdisc " .. algo .. " 10:", 1, true) ~= nil
    local download_algo_ok = tostring(ifb_qdisc or ""):find("qdisc " .. algo .. " 20:", 1, true) ~= nil

    local upload_ok = (upload_target == nil) or (upload_runtime == upload_target)
    local download_ok = (download_target == nil) or (download_runtime == download_target)

    return upload_ok and download_ok and upload_algo_ok and download_algo_ok
end

local function get_service_status()
    local enabled = sys.exec("uci -q get sqm_controller.basic_config.enabled"):gsub("%s+", "")
    if enabled == "1" then
        return "已启用"
    end
    return "未启用"
end

m = Map("sqm_controller", translate("SQM流量控制器"),
    translate("智能队列管理（SQM）用于优化时延并提高带宽公平性。"))

m.apply_on_parse = false

m._basic_config_before = get_basic_config_snapshot()

status_section = m:section(SimpleSection, translate("服务状态"))
status_field = status_section:option(DummyValue, "_status", translate("当前状态"))
status_field.cfgvalue = function()
    return get_service_status()
end

basic = m:section(NamedSection, "basic_config", "basic_config", translate("基础设置"))
basic.addremove = false

enabled = basic:option(Flag, "enabled", translate("启用SQM"))
enabled.default = 0
enabled.rmempty = false

interface = basic:option(ListValue, "interface", translate("网络接口"))
for _, dev in ipairs(sys.net.devices()) do
    if dev ~= "lo" then
        interface:value(dev)
    end
end
interface:value("eth0", "eth0")

-- Keep a safe fallback in case device list is empty in VM/container.

download_speed = basic:option(Value, "download_speed", translate("下载带宽 (kbit/s)"))
download_speed.datatype = "uinteger"

upload_speed = basic:option(Value, "upload_speed", translate("上传带宽 (kbit/s)"))
upload_speed.datatype = "uinteger"

queue_algorithm = basic:option(ListValue, "queue_algorithm", translate("队列算法"))
queue_algorithm:value("fq_codel", "fq_codel")
queue_algorithm:value("cake", "cake")
queue_algorithm.default = "fq_codel"

policy = m:section(NamedSection, "policy", "policy", translate("策略设置"))
policy.addremove = false

policy_enabled = policy:option(Flag, "enabled", translate("启用策略引擎"))
policy_enabled.default = 1
policy_enabled.rmempty = false
policy_enabled.description = translate("启用后可根据时延、丢包和分类流量占比动态调整下载侧分类带宽。")

policy_mode = policy:option(ListValue, "mode", translate("策略模式"))
policy_mode:value("auto", translate("自动"))
policy_mode:value("balanced", translate("均衡"))
policy_mode:value("gaming", translate("游戏优先"))
policy_mode:value("streaming", translate("流媒体优先"))
policy_mode:value("bulk", translate("批量优先"))
policy_mode.default = "auto"
policy_mode.rmempty = false
policy_mode.description = translate("自动模式会根据当前拥塞和分类流量占比，在均衡、游戏、流媒体、批量之间切换。")

advanced = m:section(NamedSection, "advanced_config", "advanced_config", translate("高级设置"))
advanced.addremove = false

autostart = advanced:option(Flag, "autostart", translate("开机自启"))
autostart.default = 1

log_level = advanced:option(ListValue, "log_level", translate("日志级别"))
log_level:value("debug", "Debug")
log_level:value("info", "Info")
log_level:value("warn", "Warn")
log_level:value("error", "Error")
log_level.default = "info"

log_file = advanced:option(Value, "log_file", translate("日志文件路径"))
log_file.default = "/var/log/sqm_controller.log"

local function sync_basic_runtime(hook_name, requested)
    local before = m._basic_config_before or get_basic_config_snapshot()
    local after = get_basic_config_snapshot()
    local target = merged_basic_config(after, requested)
    local enabled_now = (target.enabled == "1")
    local runtime_running = managed_runtime_running(target.interface or before.interface)
    local config_changed = runtime_related_basic_change(before, target)
    local runtime_mismatch = (enabled_now and (not runtime_running or not managed_runtime_matches(target)))
        or ((not enabled_now) and runtime_running)

    if not config_changed and not runtime_mismatch then
        m._basic_config_before = after
        return
    end

    local action = enabled_now and "start" or "stop"
    local rc = sys.call(INITD .. " " .. action .. " >/tmp/sqm_cbi_apply.out 2>&1")
    if rc == 0 then
        m._basic_config_before = get_basic_config_snapshot()
        return
    end

    restore_basic_config(before)
    if (before.enabled or "0") == "1" then
        sys.call(INITD .. " start >/tmp/sqm_cbi_restore.out 2>&1")
    else
        sys.call(INITD .. " stop >/tmp/sqm_cbi_restore.out 2>&1")
    end
    m._basic_config_before = get_basic_config_snapshot()
end

local base_parse = m.parse

function m.parse(self, ...)
    local submitted = self:submitstate()
    local requested
    if submitted then
        requested = {
            enabled = self:formvalue("cbid.sqm_controller.basic_config.enabled") and "1" or "0",
            interface = trim_uci_value(self:formvalue("cbid.sqm_controller.basic_config.interface")),
            download_speed = trim_uci_value(self:formvalue("cbid.sqm_controller.basic_config.download_speed")),
            upload_speed = trim_uci_value(self:formvalue("cbid.sqm_controller.basic_config.upload_speed")),
            queue_algorithm = trim_uci_value(self:formvalue("cbid.sqm_controller.basic_config.queue_algorithm")),
        }
    end
    m._basic_config_before = get_basic_config_snapshot()

    local rv = base_parse(self, ...)

    if submitted and self.save then
        local after = get_basic_config_snapshot()
        local target = merged_basic_config(after, requested)
        if runtime_related_basic_change(after, target) then
            restore_basic_config(target)
        end
        sync_basic_runtime("parse", target)
        sys.call(INITD .. " sync_policy_cron_service >/tmp/sqm_cbi_policy.out 2>&1")
    end

    return rv
end

return m

