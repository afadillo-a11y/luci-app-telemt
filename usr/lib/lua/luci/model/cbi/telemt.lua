-- ==============================================================================
-- Telemt CBI Model (Configuration Binding Interface)
-- Version: 3.3.15-5 LTS (Monolithic CSR, Deep ME Tuning, Unified API, RAM Cache)
-- ==============================================================================

local sys = require "luci.sys"
local http = require "luci.http"
local dsp = require "luci.dispatcher"
local uci_cursor = require("luci.model.uci").cursor()

-- Universal AJAX kill switch: suppresses 436 errors and prevents footer rendering
-- Essential for returning raw text/JSON directly to the client-side JS engine.
local function end_ajax()
    pcall(function() if dsp.context then dsp.context.dispatched = true end end)
    pcall(function() http.close() end)
end

local function has_cmd(c) return (sys.call("command -v " .. c .. " >/dev/null 2>&1") == 0) end
local fetch_bin = nil; if has_cmd("wget") then fetch_bin = "wget" elseif has_cmd("uclient-fetch") then fetch_bin = "uclient-fetch" end

local function read_file(path)
    local f = io.open(path, "r"); if not f then return "" end
    local d = f:read("*all") or ""; f:close(); return d
end

-- OpenWrt 25+ Client-side rendering detection (for UI injections)
local is_owrt25_lua = "false"
local ow_rel = sys.exec("cat /etc/openwrt_release 2>/dev/null") or ""
if ow_rel:match("DISTRIB_RELEASE='25") or ow_rel:match('DISTRIB_RELEASE="25') or ow_rel:match("SNAPSHOT") or ow_rel:match("%-rc") then is_owrt25_lua = "true" end

-- Safely build the current URL for AJAX calls
local _unpack = unpack or table.unpack
local _ok_url, current_url = pcall(function() if dsp.context and dsp.context.request then return dsp.build_url(_unpack(dsp.context.request)) end return nil end)
if not _ok_url or not current_url or current_url == "" then current_url = dsp.build_url("admin", "services", "telemt") end
local safe_url = current_url:gsub('"', '\\"'):gsub('<', '&lt;'):gsub('>', '&gt;')

local function tip(txt) return string.format([[<span class="telemt-tip" title="%s">(?)</span>]], txt:gsub('"', '&quot;')) end
local is_ajax = (http.getenv("REQUEST_METHOD") == "POST" or http.formvalue("get_metrics") or http.formvalue("get_fw_status") or http.formvalue("get_scanners") or http.formvalue("get_log") or http.formvalue("get_wan_ip") or http.formvalue("get_qr"))

-- ==============================================================================
-- AJAX DISPATCHER (Zero-CORS Local Proxy)
-- ==============================================================================
local is_post = (http.getenv("REQUEST_METHOD") == "POST")

if is_post and http.formvalue("log_ui_event") == "1" then
    local msg = http.formvalue("msg")
    if msg then sys.call(string.format("logger -t telemt %q", "WebUI: " .. msg:gsub("[%c]", " "):gsub("[^A-Za-z0-9 _.%-%:]", ""):sub(1, 128))) end
    http.prepare_content("text/plain")
    pcall(function() http.write("ok") end)
    end_ajax(); return
end

if is_post and http.formvalue("auto_pause_user") then
    local u = http.formvalue("auto_pause_user"); local reason = http.formvalue("reason") or "Limit Exceeded"
    if u and u ~= "" then
        uci_cursor:set("telemt", u, "enabled", "0")
        uci_cursor:save("telemt"); uci_cursor:commit("telemt")
        sys.call(string.format("logger -t telemt 'WebUI: Auto-paused user %s (Reason: %s)'", u, reason))
        sys.call("/etc/init.d/telemt reload >/dev/null 2>&1 &")
    end
    http.prepare_content("text/plain")
    pcall(function() http.write("ok") end)
    end_ajax(); return
end

if is_post and http.formvalue("reset_config") == "1" then
    sys.call("logger -t telemt 'WebUI: FACTORY RESET ALL SETTINGS'")
    local default_uci = "config telemt 'general'\n\toption enabled '0'\n\toption mode 'tls'\n\toption domain 'google.com'\n\toption port '8443'\n\toption metrics_port '9092'\n\toption api_port '9091'\n\toption extended_runtime_enabled '1'\n\toption metrics_allow_lo '1'\n\toption metrics_allow_lan '1'\n\toption log_level 'normal'\n"
    local f = io.open("/etc/config/telemt", "w")
    if f then f:write(default_uci); f:close() end
    sys.call("rm -f /var/etc/telemt.toml")
    sys.call("/etc/init.d/telemt stop 2>/dev/null")
    http.prepare_content("text/plain")
    pcall(function() http.write("ok") end)
    end_ajax(); return
end

if is_post and http.formvalue("reset_stats") == "1" then sys.call("logger -t telemt 'WebUI: Executed manual Reset Traffic Stats'; rm -f /tmp/telemt_stats.txt") end
if is_post and http.formvalue("start") == "1" then sys.call("logger -t telemt 'WebUI: Manual START service requested'; /etc/init.d/telemt start") end
if is_post and http.formvalue("stop") == "1" then sys.call("logger -t telemt 'WebUI: Manual STOP service requested'; /etc/init.d/telemt run_save_stats; /etc/init.d/telemt stop; sleep 1; pidof telemt >/dev/null && killall -9 telemt 2>/dev/null") end
if is_post and http.formvalue("restart") == "1" then sys.call("logger -t telemt 'WebUI: Manual RESTART service requested'; /etc/init.d/telemt run_save_stats; /etc/init.d/telemt stop; sleep 1; pidof telemt >/dev/null && killall -9 telemt 2>/dev/null; /etc/init.d/telemt start") end

if is_post and http.formvalue("export_config") == "1" then
    local conf = read_file("/var/etc/telemt.toml")
    if conf == "" then conf = "# telemt.toml not found or empty\n" end
    http.prepare_content("application/toml")
    http.header("Content-Disposition", "attachment; filename=\"telemt.toml\"")
    pcall(function() http.write(conf) end)
    end_ajax(); return
end

if http.formvalue("get_fw_status") == "1" then
    local afw = uci_cursor:get("telemt", "general", "auto_fw") or "0"
    local port = tonumber(uci_cursor:get("telemt", "general", "port")) or 8443
    local cmd = string.format("/bin/sh -c \"iptables-save 2>/dev/null | grep -qiE 'Allow-Telemt-Magic|dport.*%d.*accept' || nft list ruleset 2>/dev/null | grep -qiE 'Allow-Telemt-Magic|dport.*%d.*accept'\"", port, port)
    local is_physically_open = (sys.call(cmd) == 0)
    local procd_check = sys.exec("ubus call service list '{\"name\":\"telemt\"}' 2>/dev/null")
    local is_procd_open = (procd_check and procd_check:match("Allow%-Telemt%-Magic") ~= nil)
    local is_running = (sys.call("pidof telemt >/dev/null 2>&1") == 0)
    local status_msg, tip_msg = "<span style='color:red; font-weight:bold'>CLOSED</span>", "(Port not found in rules)"
    if is_physically_open then status_msg = "<span style='color:green; font-weight:bold'>OPEN (OK)</span>"; tip_msg = (afw == "0") and "(Auto-FW off, but port is open)" or ""
    elseif is_procd_open and is_running then status_msg = "<span style='color:green; font-weight:bold'>OPEN (OK)</span>"; tip_msg = "(Visible via ubus API)" end
    if not is_running then status_msg = "<span style='color:#d9534f; font-weight:bold'>SERVICE STOPPED</span> <span style='color:#888'>|</span> " .. status_msg end
    http.prepare_content("text/plain")
    pcall(function() http.write(status_msg .. (tip_msg ~= "" and " <span style='color:#888; font-size:0.85em; margin-left:5px;'>" .. tip_msg .. "</span>" or "")) end)
    end_ajax(); return
end

if http.formvalue("get_metrics") == "1" then
    local m_port = tonumber(uci_cursor:get("telemt", "general", "metrics_port")) or 9092
    local metrics = ""
    if sys.call("pidof telemt >/dev/null 2>&1") == 0 then
        local fetch_cmd = (fetch_bin == "wget") and "wget -q --timeout=3 -O -" or "uclient-fetch -q --timeout=3 -O -"
        metrics = sys.exec(string.format("%s 'http://127.0.0.1:%d/metrics' 2>/dev/null", fetch_cmd, m_port) .. " | grep -E '^telemt_user|^telemt_uptime|^telemt_connections|^telemt_desync'") or ""
    end
    -- Include accumulated offline stats from RAM file
    local f = io.open("/tmp/telemt_stats.txt", "r")
    if f then metrics = metrics .. "\n# ACCUMULATED\n"; for line in f:lines() do local u, tx, rx = line:match("^(%S+) (%S+) (%S+)$"); if u then metrics = metrics .. string.format("telemt_accumulated_tx{user=\"%s\"} %s\ntelemt_accumulated_rx{user=\"%s\"} %s\n", u, tx, u, rx) end end; f:close() end
    http.prepare_content("text/plain")
    pcall(function() http.write(metrics) end)
    end_ajax(); return
end

if http.formvalue("get_scanners") == "1" then
    local m_port = tonumber(uci_cursor:get("telemt", "general", "metrics_port")) or 9092
    local fetch_cmd = (fetch_bin == "wget") and "wget -q --timeout=3 -O -" or "uclient-fetch -q --timeout=3 -O -"
    local res = sys.exec(string.format("%s 'http://127.0.0.1:%d/beobachten' 2>/dev/null", fetch_cmd, m_port))
    if not res or res:gsub("%s+", "") == "" then res = "No active scanners detected or proxy is offline." end
    http.prepare_content("text/plain")
    pcall(function() http.write(res) end)
    end_ajax(); return
end

if http.formvalue("get_log") == "1" then
    http.prepare_content("text/plain")
    local cmd = "logread -e 'telemt' | tail -n 100 2>/dev/null"
    if has_cmd("timeout") then cmd = "timeout 2 " .. cmd end
    local log_data = sys.exec(cmd)
    if not log_data or log_data:gsub("%s+", "") == "" then log_data = "No logs found." end
    log_data = log_data:gsub("\27%[[%d;]*m", "") -- Strip ANSI
    pcall(function() http.write(log_data) end)
    end_ajax(); return
end

if http.formvalue("get_wan_ip") == "1" then
    local fetch_cmd = (fetch_bin == "wget") and "wget -q --timeout=3 -O -" or "uclient-fetch -q --timeout=3 -O -"
    local ip = (sys.exec(fetch_cmd .. " https://ipv4.internet.yandex.net/api/v0/ip 2>/dev/null") or ""):gsub("%s+", ""):gsub("\"", "")
    if not ip:match("^%d+%.%d+%.%d+%.%d+$") then ip = (sys.exec(fetch_cmd .. " https://checkip.amazonaws.com 2>/dev/null") or ""):gsub("%s+", "") end
    http.prepare_content("text/plain")
    pcall(function() http.write(ip:match("^%d+%.%d+%.%d+%.%d+$") and ip or "0.0.0.0") end)
    end_ajax(); return
end

if http.formvalue("get_qr") == "1" then
    local link = http.formvalue("link")
    if not link or link == "" or not link:match("^tg://proxy%?[a-zA-Z0-9=%%&_.-]+$") then 
        http.prepare_content("text/plain"); pcall(function() http.write("error: invalid_link") end); end_ajax(); return 
    end
    if not has_cmd("qrencode") then 
        http.prepare_content("text/plain"); pcall(function() http.write("error: qrencode_missing") end); end_ajax(); return 
    end
    local cmd = string.format("qrencode -t SVG -s 4 -m 1 -o - %q 2>/dev/null", link)
    if has_cmd("timeout") then cmd = "timeout 2 " .. cmd end
    http.prepare_content("image/svg+xml")
    pcall(function() http.write(sys.exec(cmd)) end)
    end_ajax(); return
end

local function norm_secret(s) if not s then return nil end; s = s:match("secret=(%x+)") or s; local hex = s:match("(%x+)"); if not hex then return nil end; local pfx = hex:sub(1,2):lower(); if pfx == "ee" or pfx == "dd" then hex = hex:sub(3) end; if #hex < 32 then return nil end; return hex:sub(1, 32):lower() end

if is_post and http.formvalue("import_users") == "1" then
    local csv = http.formvalue("csv_data")
    if csv and csv ~= "" then
        local valid_users = {}; local char_cr, char_lf, bom = string.char(13), string.char(10), string.char(239, 187, 191)
        csv = csv:gsub("^" .. bom, ""):gsub(char_cr .. char_lf, char_lf):gsub(char_cr, char_lf)
        for line in csv:gmatch("[^" .. char_lf .. "]+") do
            if not line:match("^username,") and not line:match("^<") then
                local p = {}; for f in (line..","):gmatch("([^,]*),") do table.insert(p, (f:gsub("^%s*(.-)%s*$", "%1"))) end
                local u, sec, c, uips, q, exp = p[1], p[2], p[3], p[4], p[5], p[6]; local sec_clean = norm_secret(sec)
                if c and c ~= "" and c ~= "unlimited" and not c:match("^%d+$") then c = "" end
                if uips and uips ~= "" and uips ~= "unlimited" and not uips:match("^%d+$") then uips = "" end
                if q and q ~= "" and q ~= "unlimited" and not q:match("^%d+%.?%d*$") then q = "" end
                if u and u ~= "" and u:match("^[A-Za-z0-9_]+$") and #u <= 15 and sec_clean then table.insert(valid_users, {u=u, sec=sec_clean, c=c, uips=uips, q=q, exp=exp}) end
            end
        end
        if #valid_users > 0 then
            if http.formvalue("import_mode") == "replace" then local to_delete = {}; uci_cursor:foreach("telemt", "user", function(s) table.insert(to_delete, s['.name']) end); for _, name in ipairs(to_delete) do uci_cursor:delete("telemt", name) end end
            for _, v in ipairs(valid_users) do
                uci_cursor:set("telemt", v.u, "user"); uci_cursor:set("telemt", v.u, "secret", v.sec); uci_cursor:set("telemt", v.u, "enabled", "1")
                if v.c and v.c ~= "" then uci_cursor:set("telemt", v.u, "max_tcp_conns", v.c) else uci_cursor:delete("telemt", v.u, "max_tcp_conns") end
                if v.uips and v.uips ~= "" then uci_cursor:set("telemt", v.u, "max_unique_ips", v.uips) else uci_cursor:delete("telemt", v.u, "max_unique_ips") end
                if v.q and v.q ~= "" then uci_cursor:set("telemt", v.u, "data_quota", v.q) else uci_cursor:delete("telemt", v.u, "data_quota") end
                if v.exp and v.exp:match("^%d%d%.%d%d%.%d%d%d%d %d%d:%d%d$") then uci_cursor:set("telemt", v.u, "expire_date", v.exp) else uci_cursor:delete("telemt", v.u, "expire_date") end
            end
            uci_cursor:save("telemt"); uci_cursor:commit("telemt")
            sys.call("logger -t telemt \"WebUI: Successfully imported " .. #valid_users .. " users via CSV.\"")
            http.redirect(current_url .. (current_url:match("?") and "&" or "?") .. "import_ok=" .. tostring(#valid_users)); return
        end
    end
    http.redirect(current_url); return
end

local clean_csv = "username,secret,max_tcp_conns,max_unique_ips,data_quota,expire_date\n"
uci_cursor:foreach("telemt", "user", function(s) clean_csv = clean_csv .. string.format("%s,%s,%s,%s,%s,%s\n", s['.name'] or "", s.secret or "", s.max_tcp_conns or "", s.max_unique_ips or "", s.data_quota or "", s.expire_date or "") end)
clean_csv = clean_csv:gsub("\n", "\\n"):gsub("\r", "")

-- ==============================================================================
-- 0% CPU Binary check with RAM Cache Fallback
-- ==============================================================================
local bin_info = ""
if not is_ajax then
    local bin_path = (sys.exec("command -v telemt 2>/dev/null") or ""):gsub("%s+", "")
    if bin_path == "" then 
        bin_info = "<span style='color:#d9534f; font-weight:bold; font-size:0.9em;'>Not installed (telemt binary not found)</span>"
    else 
        local ext_ver = ""
        -- 1. Try to read cache created by init.d (instant, 0 CPU)
        local f = io.open("/var/etc/telemt.version", "r")
        if f then ext_ver = f:read("*all"):gsub("%s+", ""); f:close() end
        
        -- 2. Fallback to reading the binary tail if cache is absent
        if ext_ver == "" then
            ext_ver = sys.exec("tail -c 128 /usr/bin/telemt 2>/dev/null | grep -a -i 'MTProxy v' | grep -oE '[0-9]+\\.[0-9]+\\.[0-9]+' | head -n 1"):gsub("%s+", "")
        end
        
        if ext_ver == "" then ext_ver = "unknown" end
        bin_info = string.format("<small style='opacity: 0.6;'>%s (v%s)</small>", bin_path, ext_ver) 
    end
end

-- ==============================================================================
-- CBI MAP DEFINITION
-- ==============================================================================
m = Map("telemt", "Telegram Proxy (MTProto)", [[Multi-user proxy server based on <a href="https://github.com/telemt/telemt" target="_blank" style="text-decoration:none; color:inherit; font-weight:bold; border-bottom: 1px dotted currentColor;">telemt</a>.<br><b>LuCI App Version: <a href="https://github.com/Medvedolog/luci-app-telemt" target="_blank" style="text-decoration:none; color:inherit; border-bottom: 1px dotted currentColor;">3.3.15 LTS</a></b> | <span style='color:#d35400; font-weight:bold;'>Requires telemt v3.3.15+</span>]])
m.on_commit = function(self) sys.call("logger -t telemt 'WebUI: Config saved. Dumping stats before procd reload...'; /etc/init.d/telemt run_save_stats 2>/dev/null") end

s = m:section(NamedSection, "general", "telemt")
s.anonymous = true

-- TABS DEFINITION
s:tab("general", "General Settings")
s:tab("upstreams", "Upstream Proxies")
s:tab("users", "Users")
s:tab("advanced", "Advanced Tuning")
s:tab("bot", "Telegram Bot")
s:tab("log", "Diagnostics")

-- === TAB: GENERAL ===
s:taboption("general", Flag, "enabled", "Enable Service")
local ctrl = s:taboption("general", DummyValue, "_controls", "Controls")
ctrl.rawhtml = true
ctrl.default = string.format([[
<div class="btn-controls">
    <input type="button" class="cbi-button cbi-button-apply" id="btn_telemt_start" value="Start" />
    <input type="button" class="cbi-button cbi-button-reset" id="btn_telemt_stop" value="Stop" />
    <input type="button" class="cbi-button cbi-button-reload" id="btn_telemt_restart" value="Restart" />
</div>
<script>
function postAction(action) {
    var form = document.createElement('form'); form.method = 'POST'; form.action = lu_current_url.split('?')[0].split('#')[0];
    var inp = document.createElement('input'); inp.type = 'hidden'; inp.name = action; inp.value = '1'; form.appendChild(inp);
    var tokenVal = null;
    var tokenNode = document.querySelector('input[name="token"]');
    if (tokenNode) { tokenVal = tokenNode.value; }
    else if (typeof L !== 'undefined' && L.env) { tokenVal = L.env.token || L.env.requesttoken || null; }
    if (!tokenVal) {
        var m = document.cookie.match(/(?:sysauth_http|sysauth)=([^;]+)/);
        if (m) tokenVal = m[1];
    }
    if (tokenVal) {
        var t = document.createElement('input'); t.type = 'hidden'; t.name = 'token'; t.value = tokenVal; form.appendChild(t);
    }
    document.body.appendChild(form); form.submit();
}
setTimeout(function(){
    var b1=document.getElementById('btn_telemt_start'); if(b1) b1.addEventListener('click', function(){ logAction('Manual Start'); postAction('start'); });
    var b2=document.getElementById('btn_telemt_stop'); if(b2) b2.addEventListener('click', function(){ logAction('Manual Stop'); postAction('stop'); });
    var b3=document.getElementById('btn_telemt_restart'); if(b3) b3.addEventListener('click', function(){ logAction('Manual Restart'); postAction('restart'); });
}, 500);
</script>]], current_url)

local pid = not is_ajax and (sys.exec("pidof telemt | awk '{print $1}'") or ""):gsub("%s+", "") or ""
local process_status = "<span style='color:#d9534f; font-weight:bold;'>STOPPED</span><br>" .. bin_info
if pid ~= "" and sys.call("kill -0 " .. pid .. " 2>/dev/null") == 0 then process_status = string.format("<span style='color:green;font-weight:bold'>RUNNING (PID: %s)</span><br>%s", pid, bin_info) end
local st = s:taboption("general", DummyValue, "_status", "Process Status"); st.rawhtml = true; st.value = process_status

local mode = s:taboption("general", ListValue, "mode", "Protocol Mode" .. tip("FakeTLS: HTTPS masking. DD: Old obfuscation. Classic: MTProto without masking."))
mode:value("tls", "FakeTLS (Recommended)"); mode:value("dd", "DD (Random Padding)"); mode:value("classic", "Classic"); mode:value("all", "All together (Debug)"); mode.default = "tls"

local lfmt = s:taboption("general", ListValue, "_link_fmt", "Link Format to Display" .. tip("Select which protocol link to show in the Users tab for copying."))
lfmt:depends("mode", "all"); lfmt:value("tls", "FakeTLS (Recommended)"); lfmt:value("dd", "Secure (DD)"); lfmt:value("classic", "Classic"); lfmt.default = "tls"

local dom = s:taboption("general", Value, "domain", "FakeTLS Domain" .. tip("Unauthenticated DPI traffic will be routed here. Must be ASCII only."))
dom.datatype = "hostname"; dom.default = "google.com"; dom.description = "<span class='warn-txt' style='color:#d35400; font-weight:bold;'>Warning: Change the default domain!</span>"
dom:depends("mode", "tls"); dom:depends("mode", "all")

local saved_ip = m.uci:get("telemt", "general", "external_ip")
if type(saved_ip) == "table" then saved_ip = saved_ip[1] or "" end; saved_ip = saved_ip or ""; if saved_ip:match("%s") then saved_ip = saved_ip:match("^([^%s]+)") end

local myip = s:taboption("general", Value, "external_ip", "External IP / DynDNS" .. tip("IP address or domain used strictly for generating tg:// links in UI."))
myip.datatype = "string"; myip.default = saved_ip; function myip.validate(self, value) if value and #value > 0 then value = value:match("^([^%s]+)"); if not value:match("^[a-zA-Z0-9%-%.:]+$") then return nil, "Invalid characters!" end end; return value end

local p = s:taboption("general", Value, "port", "MTProxy Port" .. tip("The port on which the MTProxy server will listen for connections.")); p.datatype = "port"; p.rmempty = false; p.default = "8443"

local afw = s:taboption("general", Flag, "auto_fw", "Auto-open Port (Magic)" .. tip("Uses procd API to open port in RAM. Rule will not appear in Firewall menu. Closes automatically if proxy stops."))
afw.default = "0"; afw.description = "<div style='margin-top:5px; padding:8px; background:rgba(128,128,128,0.1); border-left:3px solid #00a000; font-size:0.9em;'><b>Current Status:</b> <span id='fw_status_span' style='color:#888; font-style:italic;'>Checking...</span></div>"

local ll = s:taboption("general", ListValue, "log_level", "Log Level" .. tip("Verbosity of telemt daemon log output.")); ll:value("debug", "Debug"); ll:value("verbose", "Verbose"); ll:value("normal", "Normal (default)"); ll:value("silent", "Silent"); ll.default = "normal"

-- === TAB: UPSTREAMS (CASCADES) ===
local up_anchor = s:taboption("upstreams", DummyValue, "_up_anchor", ""); up_anchor.rawhtml = true; up_anchor.default = '<div id="upstreams_tab_anchor" style="display:none"></div>'
local up_master = s:taboption("upstreams", Flag, "enable_upstreams", "Enable All Cascades" .. tip("Master switch for Upstream Proxies. Disabling this falls back to Direct.")); up_master.default = "1"

s_up = m:section(TypedSection, "upstream", "Upstream Proxies (Cascades)", "Chain your outgoing Telegram traffic through other servers to bypass ISP DPI.<br><span style='color:#555;'><b>Note:</b> If no upstreams are enabled, the proxy will gracefully fallback to <b>Direct Connection</b>.</span>")
s_up.addremove = true; s_up.anonymous = true

local u_lbl = s_up:option(Value, "alias", "Cascade Name" .. tip("Optional. Latin letters, numbers and spaces only."))
u_lbl.placeholder = "e.g. Frankfurt Server"
function u_lbl.validate(self, v, section)
    if not v or v == "" then return v end
    if not v:match("^[A-Za-z0-9 _]+$") then return nil, "Only Latin letters, numbers and spaces allowed!" end
    local count = 0
    uci_cursor:foreach("telemt", "upstream", function(s) if s.alias == v and s['.name'] ~= section then count = count + 1 end end)
    if count > 0 then return nil, "Cascade name must be unique!" end
    return v
end

local uen = s_up:option(Flag, "enabled", "Active"); uen.default = "1"; uen.rmempty = false
local ut = s_up:option(ListValue, "type", "Protocol")
ut:value("direct", "Direct"); ut:value("socks4", "SOCKS4"); ut:value("socks5", "SOCKS5"); ut.default = "socks5"

local ua = s_up:option(Value, "address", "Address" .. tip("Format: IP:PORT or HOST:PORT."))
ua.datatype = "hostport"; ua:depends("type", "socks4"); ua:depends("type", "socks5")
function ua.validate(self, v) if v and v ~= "" and not v:match("^[A-Za-z0-9%.%:%-]+$") then return nil, "Invalid characters! Only Latin letters, numbers, dots, colons, and hyphens allowed." end return v end

local uint = s_up:option(Value, "interface", "Interface / Bind IP" .. tip("Optional. Bind outgoing traffic to specific local IP.")); uint:depends("type", "direct")
function uint.validate(self, v) if v and v ~= "" and not v:match("^[A-Za-z0-9%.%:%-%_]+$") then return nil, "Invalid characters! Use valid IP or interface name." end return v end

local uu = s_up:option(Value, "username", "Username" .. tip("Optional. Latin letters and numbers only, no hyphens."))
uu:depends("type", "socks5")
function uu.validate(self, v) if v and v ~= "" and not v:match("^[A-Za-z0-9_]+$") then return nil, "Only Latin letters, numbers and underscores allowed!" end return v end

local up = s_up:option(Value, "password", "Password" .. tip("Optional. Password for SOCKS. Latin only, no hyphens.")); up.password = true
up:depends("type", "socks5")
function up.validate(self, v) if v and v ~= "" and not v:match("^[A-Za-z0-9_]+$") then return nil, "Only Latin letters, numbers and underscores allowed!" end return v end

local uw = s_up:option(Value, "weight", "Weight" .. tip("Routing priority weight. Default: 10.")); uw.datatype = "uinteger"; uw.default = "10"; uw.placeholder = "10"

local usc = s_up:option(Value, "scopes", "Scopes" .. tip("Optional. Comma-separated scopes (e.g. 'premium,me'). Leave empty for all."))
usc.placeholder = "premium,me"
function usc.validate(self, v) if v and v ~= "" and not v:match("^[A-Za-z0-9_,]+$") then return nil, "Only Latin letters, numbers, underscores and commas allowed!" end return v end

-- === TAB: ADVANCED ===
local hnet = s:taboption("advanced", DummyValue, "_head_net"); hnet.rawhtml = true; hnet.default = "<h3>Network Listeners</h3>"
s:taboption("advanced", Flag, "listen_ipv4", "Enable IPv4 Listener" .. tip("Listen for incoming IPv4 connections on 0.0.0.0")).default = "1"
s:taboption("advanced", Flag, "listen_ipv6", "Enable IPv6 Listener (::)" .. tip("Listen for incoming IPv6 connections on ::")).default = "0"
local pref_ip = s:taboption("advanced", ListValue, "prefer_ip", "Preferred IP Protocol" .. tip("Which protocol to prefer when connecting to Telegram DC.")); pref_ip:value("4", "IPv4"); pref_ip:value("6", "IPv6"); pref_ip.default = "4"

local hme = s:taboption("advanced", DummyValue, "_head_me"); hme.rawhtml = true; hme.default = "<h3 style='margin-top:20px;'>Middle-End Proxy</h3>"
local mp = s:taboption("advanced", Flag, "use_middle_proxy", "Use ME Proxy" .. tip("Allows Media/CDN (DC=203) to work correctly.")); mp.default = "0"; mp.description = "<span style='color:#d35400; font-weight:bold;'>Requires public IP on interface OR NAT 1:1 with STUN enabled.</span>"
local stun = s:taboption("advanced", Flag, "use_stun", "Enable STUN-probing" .. tip("Leave enabled if your server is behind NAT. Required for ME proxy on standard setups.")); stun:depends("use_middle_proxy", "1"); stun.default = "0"
s:taboption("advanced", Value, "me_pool_size", "ME Pool Size" .. tip("Desired number of concurrent ME writers in pool. Default: 16.")):depends("use_middle_proxy", "1")

-- DEEP ME TUNING SPOILER
local h_me_adv = s:taboption("advanced", DummyValue, "_head_me_adv"); h_me_adv.rawhtml = true
h_me_adv.default = [[<div style="display:block; width:100%;"><details id="telemt_me_opts_details" style="display:block; width:100%; box-sizing:border-box; margin-top:15px; padding:10px; background:rgba(128,128,128,0.05); border:1px solid rgba(128,128,128,0.3); border-radius:6px; cursor:pointer;"><summary style="font-weight:bold; font-size:1.05em; outline:none; cursor:pointer; color:inherit;">Deep ME Tuning (Click to expand)</summary><p style="font-size:0.85em; opacity:0.8; margin-top:5px; margin-bottom:0;">Advanced Adaptive Pool and Recovery parameters. Edit only if you understand the runtime model.</p></details></div><script>function populateMESpoiler(){var d=document.getElementById('telemt_me_opts_details');if(!d)return;var tM=['me_floor_mode','me_adaptive_floor_idle_secs','me_adaptive_floor_recover_grace_secs','me_adaptive_floor_min_writers_single_endpoint','me_warm_standby','me_single_endpoint_shadow_writers','me_single_endpoint_outage_mode_enabled','me_single_endpoint_outage_disable_quarantine','me_single_endpoint_shadow_rotate_every_secs','hardswap','me_drain_ttl','auto_degradation','degradation_min_dc'];var moved=0;tM.forEach(function(n){var el=document.querySelector('.cbi-value[data-name="'+n+'"]')||document.getElementById('cbi-telemt-general-'+n)||document.querySelector('[id$="-'+n+'"]');if(el&&el.parentNode!==d){el.style.paddingLeft='15px';d.appendChild(el);moved++;}});if(moved<tM.length)setTimeout(populateMESpoiler,500);}setTimeout(populateMESpoiler,300);</script>]]
h_me_adv:depends("use_middle_proxy", "1")

local fmode = s:taboption("advanced", ListValue, "me_floor_mode", "ME Floor Mode" .. tip("Static maintains fixed pool, Adaptive shrinks pool during idle.")); fmode:value("static", "Static (Fixed)"); fmode:value("adaptive", "Adaptive (Dynamic)"); fmode.default = "static"; fmode:depends("use_middle_proxy", "1")
s:taboption("advanced", Value, "me_adaptive_floor_idle_secs", "Adaptive Idle (sec)" .. tip("Time without traffic before shrinking. Default: 600.")):depends("me_floor_mode", "adaptive")
s:taboption("advanced", Value, "me_adaptive_floor_recover_grace_secs", "Adaptive Grace (sec)" .. tip("Grace period preventing pool flapping. Default: 120.")):depends("me_floor_mode", "adaptive")
s:taboption("advanced", Value, "me_adaptive_floor_min_writers_single_endpoint", "Adaptive Min Writers" .. tip("Minimum writers to keep alive during deep idle. Default: 1.")):depends("me_floor_mode", "adaptive")
s:taboption("advanced", Value, "me_warm_standby", "ME Warm Standby" .. tip("Pre-initialized connections kept idle. Default: 8.")):depends("use_middle_proxy", "1")
s:taboption("advanced", Value, "me_single_endpoint_shadow_writers", "Shadow Writers" .. tip("Hidden backup connections for fragile DCs. Default: 2.")):depends("use_middle_proxy", "1")
local outm = s:taboption("advanced", Flag, "me_single_endpoint_outage_mode_enabled", "Outage Recovery Mode" .. tip("Aggressive reconnect loop if all writers die.")); outm.default = "1"; outm:depends("use_middle_proxy", "1")
s:taboption("advanced", Flag, "me_single_endpoint_outage_disable_quarantine", "Bypass Quarantine" .. tip("Ignore reconnect delays during an outage to restore fast.")):depends("me_single_endpoint_outage_mode_enabled", "1")
s:taboption("advanced", Value, "me_single_endpoint_shadow_rotate_every_secs", "Shadow Rotate (sec)" .. tip("Period to refresh idle shadow writers. Default: 900.")):depends("use_middle_proxy", "1")
s:taboption("advanced", Flag, "hardswap", "ME Pool Hardswap" .. tip("Enable C-like hard-swap for ME pool generations.")):depends("use_middle_proxy", "1")
s:taboption("advanced", Value, "me_drain_ttl", "ME Drain TTL (sec)" .. tip("Drain-TTL in seconds for stale ME writers. Default: 90.")):depends("use_middle_proxy", "1")
local adeg = s:taboption("advanced", Flag, "auto_degradation", "Auto-Degradation" .. tip("Enable auto-degradation from ME to Direct-DC if ME fails. Default: enabled.")); adeg.default = "1"; adeg:depends("use_middle_proxy", "1")
s:taboption("advanced", Value, "degradation_min_dc", "Degradation Min DC" .. tip("Minimum unavailable ME DC groups before degrading. Default: 2.")):depends("auto_degradation", "1")

local hadv = s:taboption("advanced", DummyValue, "_head_adv"); hadv.rawhtml = true
hadv.default = [[<div style="display:block; width:100%;"><details id="telemt_adv_opts_details" style="display:block; width:100%; box-sizing:border-box; margin-top:20px; padding:10px; background:rgba(128,128,128,0.05); border:1px solid rgba(128,128,128,0.3); border-radius:6px; cursor:pointer;"><summary style="font-weight:bold; font-size:1.05em; outline:none; cursor:pointer;">Additional Options (Click to expand)</summary><p style="font-size:0.85em; opacity:0.8; margin-top:5px; margin-bottom:0;">Extra proxy settings and overrides.</p></details></div><script>setTimeout(function(){var d = document.getElementById('telemt_adv_opts_details');if(!d) return;var tM = ['desync_all_full', 'mask_proxy_protocol', 'announce_ip', 'ad_tag', 'fake_cert_len', 'tls_full_cert_ttl_secs', 'ignore_time_skew'];tM.forEach(function(n){var el = document.querySelector('.cbi-value[data-name="' + n + '"]') || document.getElementById('cbi-telemt-general-' + n) || document.querySelector('[id$="-' + n + '"]');if(el) { el.style.paddingLeft = '15px'; d.appendChild(el); }});}, 300);</script>]]
s:taboption("advanced", Flag, "desync_all_full", "Full Crypto-Desync Logs" .. tip("Emit full forensic logs for every event. Default: disabled (false).")).default = "0"
local mpp = s:taboption("advanced", ListValue, "mask_proxy_protocol", "Mask Proxy Protocol" .. tip("Send PROXY protocol header to mask_host (if behind HAProxy/Nginx).")); mpp:value("0", "0 (Off)"); mpp:value("1", "1 (v1 - Text)"); mpp:value("2", "2 (v2 - Binary)"); mpp.default = "0"
local ip = s:taboption("advanced", Value, "announce_ip", "Announce Address" .. tip("Optional. Public IP or Domain for tg:// links. Overrides 'External IP' if set."))
ip.datatype = "string"
function ip.validate(self, v) if v and v ~= "" and not v:match("^[a-zA-Z0-9%-%.:]+$") then return nil, "Invalid characters! Use valid IP or domain." end return v end

local ad = s:taboption("advanced", Value, "ad_tag", "Ad Tag" .. tip("Get your 32-hex promotion tag from @mtproxybot.")); ad.datatype = "hexstring"
s:taboption("advanced", Value, "fake_cert_len", "Fake Cert Length" .. tip("Size of the generated fake TLS certificate in bytes. Default: 2048.")).datatype = "uinteger"
s:taboption("advanced", Value, "tls_full_cert_ttl_secs", "TLS Full Cert TTL (sec)" .. tip("Time-to-Live for the full certificate chain per client IP. Default: 90.")).datatype = "uinteger"
s:taboption("advanced", Flag, "ignore_time_skew", "Ignore Time Skew" .. tip("Disable strict time checks. Useful if clients have desynced clocks.")).default = "0"

local htm = s:taboption("advanced", DummyValue, "_head_tm"); htm.rawhtml = true
htm.default = [[<div style="display:block; width:100%;"><details id="telemt_timeouts_details" style="display:block; width:100%; box-sizing:border-box; margin-top:20px; padding:10px; background:rgba(128,128,128,0.05); border:1px solid rgba(128,128,128,0.3); border-radius:6px; cursor:pointer;"><summary style="font-weight:bold; font-size:1.05em; outline:none; cursor:pointer;">Timeouts & Replay Protection (Click to expand)</summary><p style="font-size:0.85em; opacity:0.8; margin-top:5px; margin-bottom:0;">Adjust connection timeouts and replay window. Leave defaults if unsure.</p></details></div><script>setTimeout(function(){var details = document.getElementById('telemt_timeouts_details');if(!details) return;var toMove = ['tm_handshake', 'tm_connect', 'tm_keepalive', 'tm_ack', 'replay_window_secs'];toMove.forEach(function(name){var el = document.querySelector('.cbi-value[data-name="' + name + '"]') || document.getElementById('cbi-telemt-general-' + name) || document.querySelector('[id$="-' + name + '"]');if(el) { el.style.paddingLeft = '15px'; details.appendChild(el); }});}, 300);</script>]]
s:taboption("advanced", Value, "tm_handshake", "Handshake" .. tip("Client handshake timeout in seconds.")).default = "15"
s:taboption("advanced", Value, "tm_connect", "Connect" .. tip("Telegram DC connect timeout in seconds.")).default = "10"
s:taboption("advanced", Value, "tm_keepalive", "Keepalive" .. tip("Client keepalive interval in seconds.")).default = "60"
s:taboption("advanced", Value, "tm_ack", "ACK" .. tip("Client ACK timeout in seconds.")).default = "300"
s:taboption("advanced", Value, "replay_window_secs", "Replay Window (sec)" .. tip("Time window for replay attack protection. Default: 1800.")).default = "1800"

local hmet = s:taboption("advanced", DummyValue, "_head_met"); hmet.rawhtml = true; hmet.default = "<h3 style='margin-top:20px;'>Metrics & Control API</h3>"
s:taboption("advanced", Flag, "extended_runtime_enabled", "Enable Control API & Extended Runtime" .. tip("Unified switch. Required for detailed UI diagnostics, Live Traffic stats, and the autonomous Telegram Bot.")).default = "1"
local mport = s:taboption("advanced", Value, "metrics_port", "Prometheus Port" .. tip("Port for internal Prometheus exporter. Default: 9092.")); mport.datatype = "port"; mport.default = "9092"
local aport = s:taboption("advanced", Value, "api_port", "Control API Port" .. tip("Port for the REST API (v1). Default: 9091.")); aport.datatype = "port"; aport.default = "9091"
s:taboption("advanced", Flag, "metrics_allow_lo", "Allow Localhost" .. tip("Auto-allow 127.0.0.1 and ::1. Required for Live Traffic stats.")).default = "1"
s:taboption("advanced", Flag, "metrics_allow_lan", "Allow LAN Subnet" .. tip("Auto-detect and allow your router's local network.")).default = "1"
local mwl = s:taboption("advanced", Value, "metrics_whitelist", "Additional Whitelist" .. tip("Optional. Comma separated CIDRs for external access.")); mwl.placeholder = "e.g. 10.8.0.0/24"
local cur_m_port = tonumber(m.uci:get("telemt", "general", "metrics_port")) or 9092
local mlink = s:taboption("advanced", DummyValue, "_mlink", "Prometheus Endpoint" .. tip("Click to open in a new tab, or copy for Grafana.")); mlink.rawhtml = true
mlink.default = string.format([[<a id="prom_link" href="#" target="_blank" class="telemt-prom-link" style="font-family: monospace; color: #00a000; padding: 4px; background: rgba(0,0,0,0.05); border-radius: 4px; text-decoration: none; border: 1px solid rgba(0,160,0,0.2);">http://&lt;router_ip&gt;:%d/metrics</a><script>setTimeout(function(){ var a = document.getElementById('prom_link'); if(a) { a.href = window.location.protocol + '//' + window.location.hostname + ':%d/metrics'; } }, 500);</script>]], cur_m_port, cur_m_port)

-- === TAB: TELEGRAM BOT ===
local hbot = s:taboption("bot", DummyValue, "_head_bot", ""); hbot.rawhtml = true; hbot.default = "<div style='margin-bottom:15px; padding-top:10px;'><h3 style='margin-top:0;'>Autonomous Telegram Bot (Sidecar)</h3><p style='opacity:0.8; margin-top:5px; margin-bottom:0;'>Configure the autonomous local bot to monitor Telemt status and fetch stats.</p></div>"
s:taboption("bot", Flag, "bot_enabled", "Enable Bot Sidecar" .. tip("Start the autonomous monitoring script via procd.")).default = "0"
local bt = s:taboption("bot", Value, "bot_token", "Bot Token" .. tip("Get it from @BotFather.")); bt.password = true; bt:depends("bot_enabled", "1")
local bc = s:taboption("bot", Value, "bot_chat_id", "Admin Chat ID" .. tip("Your personal or group Chat ID for alerts.")); bc:depends("bot_enabled", "1")

-- === TAB: DIAGNOSTICS ===
local lv = s:taboption("log", DummyValue, "_lv"); lv.rawhtml = true
lv.default = [[
<div class="telemt-dash-top-row" style="margin-bottom:15px; padding:12px; background:rgba(128,128,128,0.05); border:1px solid var(--border-color, rgba(128,128,128,0.2)); border-radius:6px; display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:10px;">
    <div style="font-weight:bold; font-size:1.05em; color:var(--text-color, #555);">Diagnostics & Maintenance</div>
    <div style="display:flex; gap:10px; flex-wrap:wrap;">
        <input type="button" class="cbi-button cbi-button-action" id="btn_export_config" value="Export Active Config" style="background:#4a90e2; color:#fff; border:1px solid #357abd;" />
        <input type="button" class="cbi-button cbi-button-remove" id="btn_reset_config" value="Reset to defaults" />
    </div>
</div>
<div style="width:100%; box-sizing:border-box; height:500px; font-family:monospace; font-size:12px; padding:12px; background: #1e1e1e; color: #d4d4d4; border: 1px solid #333; border-radius: 4px; overflow-y:auto; overflow-x:auto; white-space:pre;" id="telemt_log_container">Click a button below to load data.</div>
<div style="margin-top:10px; display:flex; gap:10px; flex-wrap:wrap;">
    <input type="button" class="cbi-button cbi-button-apply" id="btn_load_log" value="System Log" />
    <input type="button" class="cbi-button cbi-button-reset" id="btn_load_scanners" value="Show Active Scanners" />
    <input type="button" class="cbi-button cbi-button-action" id="btn_copy_log" value="Copy Output" />
</div>
<script>
setTimeout(function(){
    document.getElementById('btn_load_log').addEventListener('click', loadLog);
    document.getElementById('btn_load_scanners').addEventListener('click', loadScanners);
    document.getElementById('btn_copy_log').addEventListener('click', function(){ copyLogContent(this); });
    
    document.getElementById('btn_export_config').addEventListener('click', function() {
        var fd = new FormData(); fd.append('export_config', '1');
        var tok = null; var tn = document.querySelector('input[name="token"]');
        if (tn) tok = tn.value; else if (typeof L !== 'undefined' && L.env) tok = L.env.token || L.env.requesttoken || null;
        if (!tok) { var cm = document.cookie.match(/(?:sysauth_http|sysauth)=([^;]+)/); if (cm) tok = cm[1]; }
        if (tok) fd.append('token', tok);
        fetch(lu_current_url.split('#')[0], {method: 'POST', body: fd}).then(r => r.text()).then(txt => {
            txt = cleanResponse(txt);
            var blob = new Blob([txt], {type: 'application/toml'});
            var a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = 'telemt.toml';
            document.body.appendChild(a); a.click(); document.body.removeChild(a);
        });
    });
}, 500);
</script>
]]

-- === TAB: USERS ===
local anchor = s:taboption("users", DummyValue, "_users_anchor", ""); anchor.rawhtml = true; anchor.default = '<div id="users_tab_anchor" style="display:none"></div>'
local myip_u = s:taboption("users", DummyValue, "_ip_display", "External IP / DynDNS" .. tip("IP address or domain used for generating tg:// links.")); myip_u.rawhtml = true; myip_u.default = string.format([[<input type="text" class="cbi-input-text" style="width:250px;" id="telemt_mirror_ip" value="%s">]], saved_ip)

s2 = m:section(TypedSection, "user", "")
s2.template = "cbi/tblsection"; s2.addremove = true; s2.anonymous = false

local sec = s2:option(Value, "secret", "Secret (32 hex)" .. tip("Leave empty to auto-generate.")); sec.rmempty = false; sec.datatype = "hexstring"; function sec.validate(self, value) if not value or value:gsub("%s+", "") == "" then value = (sys.exec("cat /proc/sys/kernel/random/uuid") or ""):gsub("%-", ""):gsub("%s+", ""):sub(1,32) end; if #value ~= 32 or not value:match("^[0-9a-fA-F]+$") then return nil, "Secret must be exactly 32 hex chars!" end; return value end
local u_en = s2:option(Flag, "enabled", "Active"); u_en.default = "1"; u_en.rmempty = false
s2:option(Value, "max_tcp_conns", "TCP Conns").datatype = "uinteger"
s2:option(Value, "max_unique_ips", "Max IPs").datatype = "uinteger"
s2:option(Value, "data_quota", "Quota (GB)").datatype = "ufloat"
local t_exp = s2:option(Value, "expire_date", "Expire Date"); t_exp.datatype = "string"; function t_exp.validate(self, value) if not value then return "" end value = value:match("^%s*(.-)%s*$"); if value == "" or value == "unlimited" then return "" end if not value:match("^%d%d%.%d%d%.%d%d%d%d %d%d:%d%d$") then return nil, "Format: DD.MM.YYYY HH:MM" end return value end
local lst = s2:option(DummyValue, "_stat", "Status and Stats" .. tip("Accumulated usage & sessions")); lst.rawhtml = true
function lst.cfgvalue(self, section) 
    local q = self.map:get(section, "data_quota") or ""; local e = self.map:get(section, "expire_date") or ""; local en = self.map:get(section, "enabled") or "1"
    return string.format('<div class="user-flat-stat" data-user="%s" data-q="%s" data-e="%s" data-en="%s"><span style="color:#888;">No Data</span></div>', section:gsub("[<>&\"']", ""), q, e, en) 
end
local lnk = s2:option(DummyValue, "_link", "Ready-to-use link"); lnk.rawhtml = true; function lnk.cfgvalue(self, section) return [[<div class="link-wrapper"><input type="text" class="cbi-input-text user-link-out" readonly onclick="this.select()"></div>]] end

m.description = [[
<style>
/* CSR Styles and Dark Overlays Preserved from v3.2.1 */
.cbi-value-helpicon, .cbi-tooltip-container, .cbi-tooltip { display: none !important; }
.telemt-tip { cursor: help; opacity: 0.5; font-size: 0.85em; border-bottom: 1px dotted currentColor; margin-left: 4px; }
.user-flat-stat { display: flex; flex-wrap: wrap; align-items: center; line-height: 1.4; font-size: 0.95em; }
.telemt-btn-cross { flex: 0 0 24px; width: 24px; height: 24px; cursor: pointer; background: transparent url("data:image/svg+xml;charset=utf-8,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%23d9534f' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Cline x1='18' y1='6' x2='6' y2='18'/%3E%3Cline x1='6' y1='6' x2='18' y2='18'/%3E%3C/svg%3E") no-repeat center; background-size: 14px; border: none; }
.qr-modal-overlay { position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.85); z-index: 9999; display: flex; align-items: center; justify-content: center; opacity: 0; pointer-events: none; transition: opacity 0.2s; }
.qr-modal-overlay.active { opacity: 1; pointer-events: auto; }
.custom-modal-content { background: #1e1e1e; color: #eee; padding: 20px; border-radius: 8px; border: 1px solid #444; width: 90%; max-width: 450px; }
</style>

<script type="text/javascript">
var lu_current_url = "]] .. safe_url .. [[";
var is_owrt25 = ]] .. is_owrt25_lua .. [[;

function logAction(msg) { var f = new FormData(); f.append('log_ui_event', '1'); f.append('msg', msg); fetch(lu_current_url.split('#')[0], { method: 'POST', body: f }); }
function cleanResponse(txt) { if (!txt) return ''; var cut = txt.search(/<(!DOCTYPE|html[\s>])/i); return (cut > 0) ? txt.substring(0, cut).trim() : txt.trim(); }

function updateCascadesState() {
    var upRows = document.querySelectorAll('#cbi-telemt-upstream .cbi-section-node:not([id*="-template"])');
    var masterSwitch = document.querySelector('input[type="checkbox"][name*="enable_upstreams"]');
    if (masterSwitch) {
        upRows.forEach(function(row) {
            row.style.opacity = masterSwitch.checked ? '1' : '0.4';
            row.style.filter = masterSwitch.checked ? '' : 'grayscale(1)';
            row.style.pointerEvents = masterSwitch.checked ? 'auto' : 'none';
        });
        if (!masterSwitch.dataset.injected) {
            masterSwitch.dataset.injected = "1";
            masterSwitch.addEventListener('change', updateCascadesState);
        }
    }
}

function fetchMetrics() {
    fetch(lu_current_url.split('#')[0] + (lu_current_url.indexOf('?') > -1 ? '&' : '?') + 'get_metrics=1&_t=' + Date.now()).then(r => r.text()).then(txt => {
        txt = cleanResponse(txt); 
        var lines = txt.split('\n');
        var userStats = {};
        document.querySelectorAll('.user-flat-stat').forEach(el => {
            var u = el.getAttribute('data-user');
            userStats[u] = { rx: 0, tx: 0, conns: 0 };
            
            lines.forEach(line => {
                if (line.includes('user="' + u + '"')) {
                    var val = parseFloat(line.split('} ')[1]);
                    if (line.includes('octets_from_client') || line.includes('acc_rx')) userStats[u].rx += val;
                    if (line.includes('octets_to_client') || line.includes('acc_tx')) userStats[u].tx += val;
                    if (line.includes('connections_current')) userStats[u].conns = val;
                }
            });
            
            var rxMB = (userStats[u].rx / 1048576).toFixed(2);
            var txMB = (userStats[u].tx / 1048576).toFixed(2);
            el.innerHTML = "<span style='color:#00a000;'>&darr; " + txMB + " MB</span> | <span style='color:#d35400;'>&uarr; " + rxMB + " MB</span> | <b>" + userStats[u].conns + " conns</b>";
        });
    });
}

function injectUI() {
    updateCascadesState();
    document.querySelectorAll('#cbi-telemt-user .cbi-section-table-row:not([data-injected="1"])').forEach(row => {
        if (row.classList.contains('cbi-row-template')) return;
        var secInp = row.querySelector('input[name*=".secret"]');
        if (!secInp) return;
        row.dataset.injected = "1";
        
        var uName = secInp.name.match(/cbid\.telemt\.([^.]+)\.secret/)[1];
        if (is_owrt25) {
            var td = secInp.closest('td');
            var div = document.createElement('div');
            div.style.cssText = 'color:#0069d6; font-weight:bold; margin-bottom:5px; font-size:1.1em;';
            div.innerText = '👤 User: ' + uName;
            td.insertBefore(div, td.firstChild);
        }
    });
}

setInterval(fetchMetrics, 3000);
setTimeout(injectUI, 500);
</script>
]] .. (m.description or "")

return m
