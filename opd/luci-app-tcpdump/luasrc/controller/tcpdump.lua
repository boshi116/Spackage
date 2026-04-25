module("luci.controller.tcpdump", package.seeall)

local fs = require "nixio.fs"
local http = require "luci.http"
local sys = require "luci.sys"
local util = require "luci.util"
local app_i18n = require "luci.tcpdump.i18n"

local t = app_i18n.translate

local helper = "/usr/bin/luci-tcpdump"
local pid_file = "/var/run/luci-tcpdump.pid"
local log_file = "/tmp/luci-tcpdump.log"
local meta_file = "/tmp/luci-tcpdump.meta"

function index()
	entry({"admin", "services", "tcpdump"}, template("tcpdump/index"), t("Tcpdump"), 90)
	entry({"admin", "services", "tcpdump", "status"}, call("action_status")).leaf = true
	entry({"admin", "services", "tcpdump", "start"}, call("action_start")).leaf = true
	entry({"admin", "services", "tcpdump", "stop"}, call("action_stop")).leaf = true
	entry({"admin", "services", "tcpdump", "download"}, call("action_download")).leaf = true
end

local function translate_runtime_message(message)
	local messages = {
		["tcpdump binary not found"] = "Tcpdump binary not found",
		["capture is already running"] = "Capture is already running",
		["capture started"] = "Capture started",
		["failed to start capture"] = "Failed to start capture",
		["capture is not running"] = "Capture is not running",
		["failed to stop capture"] = "Failed to stop capture",
		["capture stopped"] = "Capture stopped",
		["interface is required"] = "Interface is required",
		["packet_count must be >= 0"] = "Packet limit must be greater than or equal to 0",
		["snaplen must be >= 0"] = "Snaplen must be greater than or equal to 0",
		["stop the capture before downloading"] = "Stop the capture before downloading",
		["capture file not found"] = "Capture file not found"
	}

	return t(messages[message] or message)
end

local function parse_kv(text)
	local result = {}

	for line in (text or ""):gmatch("[^\r\n]+") do
		local key, value = line:match("^([%w_]+)=(.*)$")
		if key then
			result[key] = value
		end
	end

	return result
end

local function read_meta()
	if not fs.access(meta_file) then
		return {}
	end

	return parse_kv(fs.readfile(meta_file) or "")
end

local function write_meta(meta)
	local keys = {
		"interface",
		"filter",
		"packet_count",
		"snaplen",
		"promiscuous",
		"file_name",
		"file_path",
		"started_at"
	}
	local lines = {}

	for _, key in ipairs(keys) do
		if meta[key] then
			lines[#lines + 1] = key .. "=" .. tostring(meta[key])
		end
	end

	fs.writefile(meta_file, table.concat(lines, "\n") .. (#lines > 0 and "\n" or ""))
end

local function read_pid()
	local value = fs.readfile(pid_file)
	if not value then
		return nil
	end

	local pid = tonumber(util.trim(value))
	if not pid then
		return nil
	end

	if sys.call(string.format("kill -0 %d >/dev/null 2>&1", pid)) == 0 then
		return pid
	end

	fs.remove(pid_file)
	return nil
end

local function read_log_tail()
	if not fs.access(log_file) then
		return ""
	end

	return util.trim(sys.exec("tail -n 20 " .. util.shellquote(log_file) .. " 2>/dev/null"))
end

local function helper_status()
	return parse_kv(sys.exec(util.shellquote(helper) .. " status 2>/dev/null"))
end

local function capture_size(file_path)
	if not file_path or file_path == "" then
		return 0
	end

	local stat = fs.stat(file_path)
	return stat and stat.size or 0
end

local function write_json(data)
	http.prepare_content("application/json")
	http.write_json(data)
end

function action_status()
	local meta = read_meta()
	local status = helper_status()
	local pid = tonumber(status.pid or "") or read_pid()
	local running = status.running == "1" or pid ~= nil
	local file_path = meta.file_path or status.file_path or ""
	local file_name = meta.file_name or status.file_name or ""
	local pcap_size = capture_size(file_path)
	local has_pcap = file_path ~= "" and fs.access(file_path) and pcap_size > 0
	local can_download = (not running) and has_pcap

	write_json({
		running = running,
		pid = pid,
		interface = meta.interface or "",
		filter = meta.filter or "",
		packet_count = meta.packet_count or "0",
		snaplen = meta.snaplen or "0",
		promiscuous = meta.promiscuous or "1",
		started_at = meta.started_at or "",
		file_name = file_name,
		pcap_size = pcap_size,
		has_capture = has_pcap,
		log = read_log_tail(),
		download_url = can_download and luci.dispatcher.build_url("admin", "services", "tcpdump", "download") or ""
	})
end

function action_start()
	local interface = util.trim(http.formvalue("interface") or "any")
	local filter = util.trim(http.formvalue("filter") or "")
	local packet_count = tonumber(http.formvalue("packet_count") or "0") or 0
	local snaplen = tonumber(http.formvalue("snaplen") or "0") or 0
	local promiscuous = http.formvalue("promiscuous") == "0" and "0" or "1"

	if interface == "" then
		return write_json({ success = false, message = t("Interface is required") })
	end

	if packet_count < 0 then
		return write_json({ success = false, message = t("Packet limit must be greater than or equal to 0") })
	end

	if snaplen < 0 then
		return write_json({ success = false, message = t("Snaplen must be greater than or equal to 0") })
	end

	local command = string.format(
		"%s start %s %s %s %s %s 2>&1",
		util.shellquote(helper),
		util.shellquote(interface),
		util.shellquote(filter),
		util.shellquote(tostring(packet_count)),
		util.shellquote(tostring(snaplen)),
		util.shellquote(promiscuous)
	)
	local result = parse_kv(sys.exec(command))

	write_json({
		success = result.success == "1",
		message = translate_runtime_message(result.message or "failed to start capture")
	})
end

function action_stop()
	local result = parse_kv(sys.exec(util.shellquote(helper) .. " stop 2>&1"))

	write_json({
		success = result.success == "1",
		message = translate_runtime_message(result.message or "capture stopped")
	})
end

function action_download()
	local meta = read_meta()
	local status = helper_status()
	local file_path = meta.file_path or ""
	local file_name = meta.file_name or "tcpdump-capture.pcap"

	if status.running == "1" then
		http.status(409, "Conflict")
		http.prepare_content("text/plain")
		http.write(t("Stop the capture before downloading"))
		return
	end

	if file_path == "" or not fs.access(file_path) then
		http.status(404, "Not Found")
		http.prepare_content("text/plain")
		http.write(t("Capture file not found"))
		return
	end

	http.header("Content-Disposition", "attachment; filename=\"" .. file_name .. "\"")
	http.prepare_content("application/vnd.tcpdump.pcap")
	http.write(fs.readfile(file_path) or "")
	fs.remove(file_path)
	meta.file_path = nil
	meta.file_name = nil
	write_meta(meta)
end
