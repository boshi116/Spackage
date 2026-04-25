local http = require "luci.http"
local dispatcher = require "luci.dispatcher"

local M = {}

local zh_cn = {
	["Tcpdump"] = "抓包工具",
	["Tcpdump Capture"] = "Tcpdump 抓包",
	["Run tcpdump in the background, stop it from LuCI, and download the generated pcap file."] = "在后台运行 tcpdump，可在 LuCI 中停止抓包并下载生成的 pcap 文件。",
	["Interface"] = "接口",
	["BPF Filter"] = "BPF 过滤条件",
	["Packet Limit"] = "抓包数量上限",
	["0 means capture until manually stopped."] = "0 表示持续抓包，直到手动停止。",
	["Snaplen"] = "抓包长度",
	["0 means capture the full packet."] = "0 表示抓取完整数据包。",
	["Promiscuous Mode"] = "混杂模式",
	["Start Capture"] = "开始抓包",
	["Stop Capture"] = "停止抓包",
	["Download Capture"] = "下载抓包文件",
	["Stop the capture before downloading"] = "请先停止抓包再下载",
	["Status"] = "状态",
	["Loading..."] = "加载中...",
	["running"] = "运行中",
	["interface"] = "接口",
	["filter"] = "过滤条件",
	["packet_count"] = "抓包数量",
	["snaplen"] = "抓包长度",
	["promiscuous"] = "混杂模式",
	["started_at"] = "开始时间",
	["file_name"] = "文件名",
	["pcap_size"] = "抓包文件大小",
	["bytes"] = "字节",
	["log"] = "日志",
	["yes"] = "是",
	["no"] = "否",
	["Failed to load status"] = "加载状态失败",
	["Request failed"] = "请求失败",
	["Tcpdump binary not found"] = "未找到 tcpdump 可执行文件",
	["Capture is already running"] = "抓包已在运行",
	["Capture started"] = "抓包已启动",
	["Failed to start capture"] = "启动抓包失败",
	["Capture is not running"] = "抓包未在运行",
	["Failed to stop capture"] = "停止抓包失败",
	["Capture stopped"] = "抓包已停止",
	["Interface is required"] = "接口不能为空",
	["Packet limit must be greater than or equal to 0"] = "抓包数量上限必须大于或等于 0",
	["Snaplen must be greater than or equal to 0"] = "抓包长度必须大于或等于 0",
	["Capture file not found"] = "未找到抓包文件"
}

local function normalize_lang(lang)
	lang = (lang or ""):lower():gsub("-", "_")

	if lang:match("^zh") then
		return "zh_cn"
	end

	return "en"
end

local function current_lang()
	if dispatcher and dispatcher.context and dispatcher.context.lang then
		return dispatcher.context.lang
	end

	return http.getenv("HTTP_ACCEPT_LANGUAGE") or ""
end

function M.translate(text)
	if normalize_lang(current_lang()) == "zh_cn" then
		return zh_cn[text] or text
	end

	return text
end

return M