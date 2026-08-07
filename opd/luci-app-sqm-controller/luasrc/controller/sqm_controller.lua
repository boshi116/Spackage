module("luci.controller.sqm_controller", package.seeall)

local fs = require "nixio.fs"
local http = require "luci.http"
local jsonc = require "luci.jsonc"
local sys = require "luci.sys"
local util = require "luci.util"

local APP_PY = "/usr/lib/sqm-controller/main.py"
local LOGF = "/var/log/sqm_controller.log"
local CONF = "/etc/config/sqm_controller"
local DECISION_STATE_FILE = "/tmp/sqm_decision_state.json"
local INITD = "/etc/init.d/sqm-controller"
local BACKEND_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"

local function exec_with_rc(cmd)
    local marker = "__SQM_RC__:"
    local out = sys.exec("(env PATH=" .. util.shellquote(BACKEND_PATH) .. " " .. cmd .. ") 2>&1; echo " .. marker .. "$?")
    local code = tonumber(out:match(marker .. "(%d+)%s*$")) or 1
    out = out:gsub("\n?" .. marker .. "%d+%s*$", "")
    return code, out
end

local function exec_json(cmd, fallback)
    local code, out = exec_with_rc(cmd)
    local data = jsonc.parse(out)
    if type(data) == "table" then
        return data
    end

    local result = {}
    if type(fallback) == "table" then
        for k, v in pairs(fallback) do
            result[k] = v
        end
    end

    result.success = false
    result.code = code
    result.error = result.error or "后端返回不是合法JSON"
    result.output = out or ""
    return result
end

local function load_policy_cron_runtime()
    local runtime = {
        policy_cron_command = "",
        policy_cron_mode = "disabled"
    }
    local raw = fs.readfile("/etc/crontabs/root") or ""
    for line in raw:gmatch("[^\r\n]+") do
        if line:find("sqm%-controller%-policy") then
            runtime.policy_cron_command = line
            if line:find("%-%-policy%-apply") then
                runtime.policy_cron_mode = "apply"
            elseif line:find("%-%-policy%-once") then
                runtime.policy_cron_mode = "dry_run"
            else
                runtime.policy_cron_mode = "unknown"
            end
            return runtime
        end
    end
    return runtime
end

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
        interface = trim_uci_value(sys.exec("uci -q get sqm_controller.basic_config.interface 2>/dev/null")),
        download_speed = trim_uci_value(sys.exec("uci -q get sqm_controller.basic_config.download_speed 2>/dev/null")),
        upload_speed = trim_uci_value(sys.exec("uci -q get sqm_controller.basic_config.upload_speed 2>/dev/null")),
        queue_algorithm = trim_uci_value(sys.exec("uci -q get sqm_controller.basic_config.queue_algorithm 2>/dev/null")),
        enabled = trim_uci_value(sys.exec("uci -q get sqm_controller.basic_config.enabled 2>/dev/null"))
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
    local options = { "interface", "download_speed", "upload_speed", "queue_algorithm", "enabled" }
    for _, option in ipairs(options) do
        rc = rc + set_basic_config_value(option, snapshot[option])
    end
    rc = rc + sys.call("uci -q commit sqm_controller")
    return rc
end

function index()
    entry({"admin", "services", "sqm_controller"}, alias("admin", "services", "sqm_controller", "settings"), _("SQM流量控制"), 60)
    entry({"admin", "services", "sqm_controller", "settings"}, cbi("sqm_controller"), _("基础设置"), 10)
    entry({"admin", "services", "sqm_controller", "wizard"}, template("sqm_controller/wizard"), _("配置向导"), 12)
    entry({"admin", "services", "sqm_controller", "status"}, template("sqm_controller/status"), _("状态监控"), 20)
    entry({"admin", "services", "sqm_controller", "monitor"}, template("sqm_controller/monitor"), _("实时监控"), 23)
    entry({"admin", "services", "sqm_controller", "traffic"}, template("sqm_controller/traffic"), _("分类流量统计"), 24)
    entry({"admin", "services", "sqm_controller", "policy"}, template("sqm_controller/policy"), _("策略中心"), 26)
    entry({"admin", "services", "sqm_controller", "report"}, alias("admin", "services", "sqm_controller", "policy")).leaf = true
    entry({"admin", "services", "sqm_controller", "logs"}, template("sqm_controller/logs"), _("系统日志"), 30)
    entry({"admin", "services", "sqm_controller", "help"}, template("sqm_controller/help"), _("帮助文档"), 40)

    entry({"admin", "services", "sqm_controller", "get_status"}, call("action_get_status")).leaf = true
    entry({"admin", "services", "sqm_controller", "get_monitor"}, call("action_get_monitor")).leaf = true
    entry({"admin", "services", "sqm_controller", "get_monitor_history"}, call("action_get_monitor_history")).leaf = true
    entry({"admin", "services", "sqm_controller", "speedtest"}, call("action_speedtest")).leaf = true
    entry({"admin", "services", "sqm_controller", "self_check"}, call("action_self_check")).leaf = true
    entry({"admin", "services", "sqm_controller", "wizard_apply"}, call("action_wizard_apply")).leaf = true
    entry({"admin", "services", "sqm_controller", "backup_config"}, call("action_backup_config")).leaf = true
    entry({"admin", "services", "sqm_controller", "restore_config"}, call("action_restore_config")).leaf = true

    entry({"admin", "services", "sqm_controller", "start_service"}, call("action_start_service")).leaf = true
    entry({"admin", "services", "sqm_controller", "stop_service"}, call("action_stop_service")).leaf = true
    entry({"admin", "services", "sqm_controller", "restart_service"}, call("action_restart_service")).leaf = true

    entry({"admin", "services", "sqm_controller", "get_logs"}, call("action_get_logs")).leaf = true
    entry({"admin", "services", "sqm_controller", "clear_logs"}, call("action_clear_logs")).leaf = true
    entry({"admin", "services", "sqm_controller", "download_log"}, call("action_download_log")).leaf = true
    entry({"admin", "services", "sqm_controller", "rotate_logs"}, call("action_rotate_logs")).leaf = true
    entry({"admin", "services", "sqm_controller", "apply_classifier"}, call("action_apply_classifier")).leaf = true
    entry({"admin", "services", "sqm_controller", "clear_classifier"}, call("action_clear_classifier")).leaf = true
    entry({"admin", "services", "sqm_controller", "get_class_stats"}, call("action_get_class_stats")).leaf = true
    entry({"admin", "services", "sqm_controller", "get_classifier_state"}, call("action_get_classifier_state")).leaf = true
    entry({"admin", "services", "sqm_controller", "policy_once"}, call("action_policy_once")).leaf = true
    entry({"admin", "services", "sqm_controller", "get_policy_state"}, call("action_get_policy_state")).leaf = true
    entry({"admin", "services", "sqm_controller", "export_report"}, call("action_export_report")).leaf = true
    entry({"admin", "services", "sqm_controller", "get_policy_status"}, call("action_get_policy_status")).leaf = true
    entry({"admin", "services", "sqm_controller", "get_policy_log"}, call("action_get_policy_log")).leaf = true
    entry({"admin", "services", "sqm_controller", "aggregate_unknowns"}, call("action_aggregate_unknowns")).leaf = true
    entry({"admin", "services", "sqm_controller", "list_port_heuristics"}, call("action_list_port_heuristics")).leaf = true
    entry({"admin", "services", "sqm_controller", "list_dns_rules"}, call("action_list_dns_rules")).leaf = true
    entry({"admin", "services", "sqm_controller", "add_class_rule"}, call("action_add_class_rule")).leaf = true
    entry({"admin", "services", "sqm_controller", "update_class_rule"}, call("action_update_class_rule")).leaf = true
    entry({"admin", "services", "sqm_controller", "delete_class_rule"}, call("action_delete_class_rule")).leaf = true
    entry({"admin", "services", "sqm_controller", "save_dns_user_rules"}, call("action_save_dns_user_rules")).leaf = true
    entry({"admin", "services", "sqm_controller", "export_unmatched_dns"}, call("action_export_unmatched_dns")).leaf = true
    entry({"admin", "services", "sqm_controller", "import_ai_dns_rules"}, call("action_import_ai_dns_rules")).leaf = true
end

local function action_service_control(op)
    local allowed = { start = true, stop = true, restart = true }
    local action = tostring(op or ""):lower()
    if not allowed[action] then
        http.write_json({ success = false, error = "invalid service action" })
        return
    end

    local code, out = exec_with_rc(util.shellquote(INITD) .. " " .. action)
    http.write_json({
        success = (code == 0),
        code = code,
        action = action,
        output = out
    })
end

function action_get_status()
    local data = exec_json("python3 " .. APP_PY .. " --status-json", {
        service_status = "error",
        pid = "N/A",
        tc_state = "error",
        tc_wan = "",
        tc_ifb = "",
        configured_backend = "",
        active_backend = "",
        policy_cron_present = false,
        policy_cron_expression = "",
        rule_conflicts_count = 0,
        upload_class_queues_present = false,
        download_class_queues_present = false,
        classifier_tc_complete = false,
        validation_errors = {},
        validation_warnings = {},
        error = "状态后端失败"
    })
    local cron_runtime = load_policy_cron_runtime()
    data.policy_cron_command = cron_runtime.policy_cron_command
    data.policy_cron_mode = cron_runtime.policy_cron_mode
    http.write_json(data)
end

function action_get_monitor()
    local data = exec_json("python3 " .. APP_PY .. " --monitor", {
        latency = "-",
        loss = "-",
        bandwidth = "-",
        bandwidth_kbps = "-",
        error = "监控后端失败"
    })
    http.write_json(data)
end

function action_get_monitor_history()
    local window = http.formvalue("window") or "5m"
    if window ~= "1m" and window ~= "5m" and window ~= "1h" and window ~= "6h" and window ~= "24h" then
        window = "5m"
    end

    local data = exec_json(
        "python3 " .. APP_PY .. " --monitor-history --window " .. util.shellquote(window),
        {
            success = false,
            window = window,
            points = {},
            current = { bandwidth = "-", bandwidth_kbps = "-", latency = "-", loss = "-" },
            error = "监控历史后端失败"
        }
    )
    http.write_json(data)
end

function action_speedtest()
    local data = exec_json("python3 " .. APP_PY .. " --speedtest", {
        error = "测速后端失败"
    })
    http.write_json(data)
end

function action_self_check()
    local data = exec_json("python3 " .. APP_PY .. " --self-check", {
        success = false,
        error = "自检后端失败"
    })
    http.write_json(data)
end

function action_wizard_apply()
    local iface = (http.formvalue("iface") or ""):gsub("%s+", "")
    local download = (http.formvalue("download") or ""):gsub("%s+", "")
    local upload = (http.formvalue("upload") or ""):gsub("%s+", "")
    local algorithm = (http.formvalue("algorithm") or ""):gsub("%s+", "")
    local enabled = (http.formvalue("enabled") or "1"):gsub("%s+", "")

    if not iface:match("^[%w%._:%-]+$") then
        http.write_json({ success = false, error = "接口参数错误" })
        return
    end
    if not download:match("^%d+$") or tonumber(download) <= 0 then
        http.write_json({ success = false, error = "下载带宽参数错误" })
        return
    end
    if not upload:match("^%d+$") or tonumber(upload) <= 0 then
        http.write_json({ success = false, error = "上传带宽参数错误" })
        return
    end
    if algorithm ~= "fq_codel" and algorithm ~= "cake" then
        http.write_json({ success = false, error = "队列算法参数错误" })
        return
    end
    if enabled ~= "0" and enabled ~= "1" then
        http.write_json({ success = false, error = "启停参数错误" })
        return
    end

    local qiface = util.shellquote(iface)
    local qdownload = util.shellquote(download)
    local qupload = util.shellquote(upload)
    local qalgo = util.shellquote(algorithm)
    local qenabled = util.shellquote(enabled)
    local previous = get_basic_config_snapshot()

    local rc = 0
    rc = rc + sys.call("uci -q set sqm_controller.basic_config.interface=" .. qiface)
    rc = rc + sys.call("uci -q set sqm_controller.basic_config.download_speed=" .. qdownload)
    rc = rc + sys.call("uci -q set sqm_controller.basic_config.upload_speed=" .. qupload)
    rc = rc + sys.call("uci -q set sqm_controller.basic_config.queue_algorithm=" .. qalgo)
    rc = rc + sys.call("uci -q set sqm_controller.basic_config.enabled=" .. qenabled)
    rc = rc + sys.call("uci -q commit sqm_controller")

    if rc ~= 0 then
        http.write_json({ success = false, error = "保存配置失败", code = rc })
        return
    end

    local runtime_code, out
    if enabled == "1" then
        runtime_code, out = exec_with_rc(util.shellquote(INITD) .. " start")
    else
        runtime_code, out = exec_with_rc(util.shellquote(INITD) .. " stop")
    end

    local rollback_code = 0
    local rolled_back = false
    if runtime_code ~= 0 then
        rollback_code = restore_basic_config(previous)
        rolled_back = (rollback_code == 0)
    end

    http.write_json({
        success = (runtime_code == 0),
        runtime_code = runtime_code,
        rollback_code = rollback_code,
        rolled_back = rolled_back,
        output = out,
        config = {
            iface = iface,
            download = tonumber(download),
            upload = tonumber(upload),
            algorithm = algorithm,
            enabled = (enabled == "1")
        }
    })
end

function action_backup_config()
    if not fs.access(CONF) then
        http.status(404, "Not Found")
        http.prepare_content("application/json")
        http.write_json({ success = false, error = "配置文件不存在" })
        return
    end

    local filename = "sqm_controller-" .. os.date("%Y%m%d-%H%M%S") .. ".backup"
    http.header("Content-Disposition", 'attachment; filename="' .. filename .. '"')
    http.prepare_content("text/plain")
    http.write(sys.exec("cat " .. util.shellquote(CONF)))
end

function action_restore_config()
    local tmpfile = "/tmp/sqm_controller.restore.upload"
    local fp = nil
    local uploaded = false

    fs.remove(tmpfile)

    http.setfilehandler(function(meta, chunk, eof)
        if not fp and meta and meta.name == "backup_file" then
            fp = io.open(tmpfile, "w")
            uploaded = fp ~= nil
        end
        if fp and chunk then
            fp:write(chunk)
        end
        if fp and eof then
            fp:close()
            fp = nil
        end
    end)

    http.formvalue("backup_file")
    if fp then
        fp:close()
    end

    if not uploaded or not fs.access(tmpfile) then
        http.prepare_content("application/json")
        http.write_json({ success = false, error = "未上传备份文件" })
        return
    end

    local apply_now = http.formvalue("apply_now")
    local cmd = "python3 " .. APP_PY .. " --restore-config " .. util.shellquote(tmpfile)
    if apply_now == "0" or apply_now == "false" then
        cmd = cmd .. " --no-apply"
    end

    local data = exec_json(cmd, {
        success = false,
        error = "恢复后端失败"
    })

    fs.remove(tmpfile)
    http.write_json(data)
end

function action_start_service()
    action_service_control("start")
end

function action_stop_service()
    action_service_control("stop")
end

function action_restart_service()
    action_service_control("restart")
end

function action_get_logs()
    local data = sys.exec("test -f " .. LOGF .. " && cat " .. LOGF .. " || true")
    http.prepare_content("application/json")
    http.write_json({ content = data })
end

function action_clear_logs()
    sys.call("mkdir -p /var/log; : > " .. LOGF)
    http.prepare_content("application/json")
    http.write_json({ success = true })
end

function action_download_log()
    http.header("Content-Disposition", 'attachment; filename="sqm_controller.log"')
    http.prepare_content("text/plain")
    http.write(sys.exec("test -f " .. LOGF .. " && cat " .. LOGF .. " || echo 'no log'"))
end

function action_rotate_logs()
    local data = exec_json("python3 " .. APP_PY .. " --rotate-logs", {
        success = false,
        error = "日志轮转后端失败"
    })
    http.write_json(data)
end

function action_apply_classifier()
    local data = exec_json("python3 " .. APP_PY .. " --apply-classifier", {
        error = "apply_classifier failed"
    })
    http.write_json(data)
end

function action_clear_classifier()
    local data = exec_json("python3 " .. APP_PY .. " --clear-classifier", {
        error = "clear_classifier failed"
    })
    http.write_json(data)
end

function action_get_class_stats()
    local dev = http.formvalue("dev") or "ifb0"
    if not (
        dev == "ifb0" or
        dev == "iface" or
        dev == "wan" or
        dev == "interface" or
        dev:match("^[A-Za-z0-9_.:%-]+$")
    ) then
        dev = "ifb0"
    end

    local data = exec_json(
        "python3 " .. APP_PY .. " --get-class-stats --dev " .. util.shellquote(dev),
        { error = "get_class_stats failed" }
    )
    http.write_json(data)
end

function action_get_classifier_state()
    local dev = http.formvalue("dev") or "ifb0"
    if not (
        dev == "ifb0" or
        dev == "iface" or
        dev == "wan" or
        dev == "interface" or
        dev:match("^[A-Za-z0-9_.:%-]+$")
    ) then
        dev = "ifb0"
    end

    local data = exec_json("python3 " .. APP_PY .. " --get-classifier-state --dev " .. util.shellquote(dev), {
        success = false,
        time = 0,
        window_sec = 0,
        backend = "",
        focus_dev = "ifb0",
        summary = {
            total_kbps = 0,
            classified_kbps = 0,
            other_kbps = 0,
            classification_ratio = 0,
            rules_total = 0,
            rules_active = 0,
            health = "degraded"
        },
        categories = {
            other = { classid = "2:20", tc_bytes = 0, tc_packets = 0, tc_kbps = 0, pct = 0 },
            gaming = { classid = "2:21", tc_bytes = 0, tc_packets = 0, tc_kbps = 0, pct = 0 },
            streaming = { classid = "2:22", tc_bytes = 0, tc_packets = 0, tc_kbps = 0, pct = 0 },
            bulk = { classid = "2:23", tc_bytes = 0, tc_packets = 0, tc_kbps = 0, pct = 0 }
        }
    })

    http.prepare_content("application/json")
    http.header("Content-Type", "application/json; charset=utf-8")
    http.write(jsonc.stringify(data) or "{}")
end

function action_policy_once()
    local data = exec_json("python3 " .. APP_PY .. " --policy-once", {
        error = "策略评估失败"
    })

    if type(data) ~= "table" then
        data = {
            success = false,
            error = "策略评估失败"
        }
    end

    local normalized_actions = {}
    if type(data.actions) == "table" then
        local seq_len = #data.actions
        if seq_len > 0 then
            for i = 1, seq_len do
                table.insert(normalized_actions, data.actions[i])
            end
        else
            local numeric_keys = {}
            for key, _ in pairs(data.actions) do
                if type(key) == "number" and key >= 1 and key == math.floor(key) then
                    table.insert(numeric_keys, key)
                end
            end
            table.sort(numeric_keys)
            for _, key in ipairs(numeric_keys) do
                table.insert(normalized_actions, data.actions[key])
            end
        end
    end
    data.actions = normalized_actions

    if type(data.changed) ~= "boolean" then
        data.changed = false
    end

    local payload = jsonc.stringify(data) or "{}"
    if #normalized_actions == 0 then
        payload = payload:gsub('"actions"%s*:%s*{}', '"actions":[]', 1)
    end

    http.prepare_content("application/json")
    http.header("Content-Type", "application/json; charset=utf-8")
    http.write(payload)
end

function action_get_policy_state()
    http.prepare_content("application/json")
    http.header("Content-Type", "application/json; charset=utf-8")

    if not fs.access(DECISION_STATE_FILE) then
        http.write('{"success":true,"empty":true,"note":"no state yet","state_file":"/tmp/sqm_decision_state.json","current_mode":"","last_change_ts":0,"last_run_ts":0,"actions":[]}')
        return
    end

    local ok_read, raw = pcall(fs.readfile, DECISION_STATE_FILE)
    if not ok_read then
        http.write_json({
            success = false,
            error = "invalid policy state json",
            state_file = DECISION_STATE_FILE,
            raw = ""
        })
        return
    end

    raw = raw or ""
    local ok_parse, parsed = pcall(jsonc.parse, raw)
    if not ok_parse or type(parsed) ~= "table" then
        http.write_json({
            success = false,
            error = "invalid policy state json",
            state_file = DECISION_STATE_FILE,
            raw = string.sub(raw, 1, 4096)
        })
        return
    end

    parsed.success = true
    parsed.state_file = DECISION_STATE_FILE
    parsed.last_change_ts = parsed.last_change_ts or parsed.last_switch_time or 0
    parsed.last_run_ts = parsed.last_run_ts or parsed.last_run_time or 0
    if type(parsed.actions) ~= "table" then
        parsed.actions = {}
    end
    http.write(jsonc.stringify(parsed) or "{}")
end

function action_get_policy_log()
    local limit = tonumber(http.formvalue("limit") or "5") or 5
    local data = exec_json("python3 " .. APP_PY .. " --get-policy-log --limit " .. limit, {
        success = false,
        error = "策略日志后端失败"
    })
    http.prepare_content("application/json")
    http.header("Content-Type", "application/json; charset=utf-8")
    http.write(jsonc.stringify(data) or "{}")
end

function action_aggregate_unknowns()
    local limit = tonumber(http.formvalue("limit") or "10") or 10
    local sort_by = http.formvalue("sort_by") or "bytes"
    if limit < 1 then limit = 1 end
    if limit > 50 then limit = 50 end
    if sort_by ~= "bytes" and sort_by ~= "count" then
        sort_by = "bytes"
    end
    local data = exec_json(
        "python3 " .. APP_PY .. " --aggregate-unknowns --limit " .. limit .. " --sort-by " .. util.shellquote(sort_by),
        { success = false, error = "未知流量分析后端失败" }
    )
    http.prepare_content("application/json")
    http.header("Content-Type", "application/json; charset=utf-8")
    http.write(jsonc.stringify(data) or "{}")
end


function action_get_policy_status()
    local data = exec_json("python3 " .. APP_PY .. " --policy-status", {
        success = false,
        error = "策略状态后端失败"
    })
    http.prepare_content("application/json")
    http.header("Content-Type", "application/json; charset=utf-8")
    http.write(jsonc.stringify(data) or "{}")
end

function action_export_report()
    local fmt = (http.formvalue("format") or "json"):lower()
    if fmt ~= "json" and fmt ~= "csv" then
        fmt = "json"
    end

    local code, out = exec_with_rc("python3 " .. APP_PY .. " --export-report --format " .. util.shellquote(fmt))
    if code ~= 0 then
        http.status(500, "Internal Server Error")
        http.prepare_content("application/json")
        http.header("Content-Type", "application/json; charset=utf-8")
        http.write(jsonc.stringify({
            success = false,
            code = code,
            error = "export_report failed",
            output = out or ""
        }))
        return
    end

    if fmt == "json" then
        http.prepare_content("application/json")
        http.header("Content-Type", "application/json; charset=utf-8")
        http.write(out or "")
        return
    end

    http.header("Content-Disposition", 'attachment; filename="sqm-policy-report.csv"')
    http.prepare_content("text/csv")
    http.header("Content-Type", "text/csv; charset=utf-8")
    http.write(out or "")
end

-- Classification rule management endpoints

local function _exec_json_with_data_file(cmd, stdin_data, data_flag, fallback)
    local tmpfile = "/tmp/sqm_luci_input_" .. tostring(os.time()) .. "_" .. tostring(math.random(100000, 999999)) .. ".json"
    local f = io.open(tmpfile, "w")
    if f then
        f:write(stdin_data)
        f:close()
    end
    local data = exec_json(cmd .. " --" .. data_flag .. " " .. util.shellquote(tmpfile), fallback)
    fs.remove(tmpfile)
    return data
end

function action_list_port_heuristics()
    local data = exec_json("python3 " .. APP_PY .. " --list-port-heuristics", {
        success = false,
        error = "端口规则后端失败"
    })
    http.write_json(data)
end

function action_list_dns_rules()
    local data = exec_json("python3 " .. APP_PY .. " --list-dns-rules", {
        success = false,
        error = "DNS 规则后端失败"
    })
    http.write_json(data)
end

function action_add_class_rule()
    local body = http.content()
    if not body or body == "" then
        http.write_json({ success = false, error = "请求体为空" })
        return
    end
    local data = _exec_json_with_data_file("python3 " .. APP_PY .. " --add-class-rule", body, "class-rule-data", {
        success = false,
        error = "添加规则后端失败"
    })
    http.write_json(data)
end

function action_update_class_rule()
    local body = http.content()
    if not body or body == "" then
        http.write_json({ success = false, error = "请求体为空" })
        return
    end
    local data = _exec_json_with_data_file("python3 " .. APP_PY .. " --update-class-rule", body, "class-rule-data", {
        success = false,
        error = "更新规则后端失败"
    })
    http.write_json(data)
end

function action_delete_class_rule()
    local name = http.formvalue("name") or ""
    if name == "" then
        local body = http.content()
        if body and body ~= "" then
            local ok, parsed = pcall(jsonc.parse, body)
            if ok and type(parsed) == "table" and parsed.name then
                name = parsed.name
            end
        end
    end
    if name == "" then
        http.write_json({ success = false, error = "缺少规则名称" })
        return
    end
    local data = exec_json(
        "python3 " .. APP_PY .. " --delete-class-rule " .. util.shellquote(name),
        { success = false, error = "删除规则后端失败" }
    )
    http.write_json(data)
end

function action_save_dns_user_rules()
    local body = http.content()
    if not body or body == "" then
        http.write_json({ success = false, error = "请求体为空" })
        return
    end
    local data = _exec_json_with_data_file("python3 " .. APP_PY .. " --save-dns-user-rules", body, "dns-rule-data", {
        success = false,
        error = "保存 DNS 规则后端失败"
    })
    http.write_json(data)
end

function action_export_unmatched_dns()
    local min_count = tonumber(http.formvalue("min_count") or "3") or 3
    local limit = tonumber(http.formvalue("limit") or "150") or 150
    local data = exec_json(
        "python3 " .. APP_PY .. " --export-unmatched-dns --unmatched-min-count " .. min_count .. " --unmatched-limit " .. limit,
        { success = false, error = "导出未匹配DNS后端失败" }
    )
    http.prepare_content("application/json")
    http.header("Content-Type", "application/json; charset=utf-8")
    http.write(jsonc.stringify(data) or "{}")
end

function action_import_ai_dns_rules()
    local body = http.content()
    if not body or body == "" then
        http.write_json({ success = false, error = "请求体为空" })
        return
    end
    local data = _exec_json_with_data_file("python3 " .. APP_PY .. " --import-ai-dns-rules", body, "ai-rules-data", {
        success = false,
        error = "导入AI规则后端失败"
    })
    http.write_json(data)
end
