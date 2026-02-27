-- ==============================================================================
-- Telemt CBI Model (Configuration Binding Interface)
-- Version: 3.1.2-8 (Golden Master UI + Block Upstreams)
-- ==============================================================================

local sys = require "luci.sys"
local http = require "luci.http"
local dsp = require "luci.dispatcher"
local uci_cursor = require("luci.model.uci").cursor()

local function has_cmd(c) return (sys.call("command -v " .. c .. " >/dev/null 2>&1") == 0) end
local fetch_bin = nil
if has_cmd("wget") then fetch_bin = "wget" elseif has_cmd("uclient-fetch") then fetch_bin = "uclient-fetch" end

local function read_file(path)
    local f = io.open(path, "r"); if not f then return "" end
    local d = f:read("*all") or ""; f:close(); return (d:gsub("%s+", ""))
end

local is_owrt25_lua = "false"
local ow_rel = sys.exec("cat /etc/openwrt_release 2>/dev/null") or ""
if ow_rel:match("DISTRIB_RELEASE='25") or ow_rel:match('DISTRIB_RELEASE="25') or ow_rel:match("SNAPSHOT") or ow_rel:match("%-rc") then is_owrt25_lua = "true" end

local _unpack = unpack or table.unpack
local _ok_url, current_url = pcall(function()
    if dsp.context and dsp.context.request then return dsp.build_url(_unpack(dsp.context.request)) end return nil
end)
if not _ok_url or not current_url or current_url == "" then current_url = dsp.build_url("admin", "services", "telemt") end
local safe_url = current_url:gsub('"', '\\"'):gsub('<', '&lt;'):gsub('>', '&gt;')

local function tip(txt) return string.format([[<span class="telemt-tip" title="%s">(?)</span>]], txt:gsub('"', '&quot;')) end

local is_post = (http.getenv("REQUEST_METHOD") == "POST")

if is_post and http.formvalue("log_ui_event") == "1" then
    local msg = http.formvalue("msg")
    if msg then sys.call(string.format("logger -t telemt %q", "WebUI: " .. msg:gsub("[%c]", " "):gsub("[^A-Za-z0-9 _.%-]", ""):sub(1, 128))) end
    http.prepare_content("text/plain"); http.write("ok"); http.close(); return
end

if is_post and http.formvalue("reset_stats") == "1" then
    sys.call("logger -t telemt 'WebUI: Executed manual Reset Traffic Stats'"); sys.call("rm -f /tmp/telemt_stats.txt")
    http.redirect(current_url); return
end

if is_post and http.formvalue("start") == "1" then 
    sys.call("logger -t telemt 'WebUI: Manual START'"); sys.call("/etc/init.d/telemt start")
    http.redirect(current_url); return 
end

if is_post and http.formvalue("stop") == "1" then 
    sys.call("logger -t telemt 'WebUI: Manual STOP'"); sys.call("/etc/init.d/telemt run_save_stats 2>/dev/null; /etc/init.d/telemt stop; sleep 1; pidof telemt >/dev/null && killall -9 telemt 2>/dev/null")
    http.redirect(current_url); return 
end

if is_post and http.formvalue("restart") == "1" then 
    sys.call("logger -t telemt 'WebUI: Manual RESTART'"); sys.call("/etc/init.d/telemt run_save_stats 2>/dev/null; /etc/init.d/telemt stop; sleep 1; pidof telemt >/dev/null && killall -9 telemt 2>/dev/null; /etc/init.d/telemt start")
    http.redirect(current_url); return 
end

local is_ajax = (http.formvalue("get_metrics") or http.formvalue("get_fw_status") or http.formvalue("get_log") or http.formvalue("get_wan_ip") or http.formvalue("get_qr") or http.formvalue("log_ui_event"))

if http.formvalue("get_fw_status") == "1" then
    local afw = uci_cursor:get("telemt", "general", "auto_fw") or "0"
    local port = tonumber(uci_cursor:get("telemt", "general", "port")) or 4443
    http.prepare_content("text/plain")
    local cmd = string.format("/bin/sh -c \"iptables-save 2>/dev/null | grep -qiE 'Allow-Telemt-Magic|dport.*%d.*accept' || nft list ruleset 2>/dev/null | grep -qiE 'Allow-Telemt-Magic|dport.*%d.*accept'\"", port, port)
    local is_physically_open = (sys.call(cmd) == 0)
    local procd_check = sys.exec("ubus call service list '{\"name\":\"telemt\"}' 2>/dev/null")
    local is_procd_open = (procd_check and procd_check:match("firewall") and procd_check:match("Allow%-Telemt%-Magic"))
    local is_running = (sys.call("pidof telemt >/dev/null 2>&1") == 0)
    
    local status_msg = ""; local tip_msg = ""
    if is_physically_open then status_msg = "<span style='color:green; font-weight:bold'>OPEN (OK)</span>"; if afw == "0" then tip_msg = "(Auto-FW disabled, but port is open in FW rules)" end
    elseif is_procd_open and is_running then status_msg = "<span style='color:green; font-weight:bold'>OPEN (OK)</span>"; tip_msg = "(Not visible in FW rules. Manual port opening recommended)"
    else status_msg = "<span style='color:red; font-weight:bold'>CLOSED</span>"; tip_msg = "(Port not found in FW rules. Consider adding manually)" end
    if not is_running then status_msg = "<span style='color:#d9534f; font-weight:bold'>SERVICE STOPPED</span> <span style='color:#888'>|</span> " .. status_msg end
    http.write(status_msg .. " <span style='color:#888; font-size:0.85em; margin-left:5px;'>" .. tip_msg .. "</span>"); http.close(); return
end

if http.formvalue("get_metrics") == "1" then
    local m_port = tonumber(uci_cursor:get("telemt", "general", "metrics_port")) or 9091
    local metrics = ""
    if sys.call("pidof telemt >/dev/null 2>&1") == 0 then
        local fetch_cmd = (fetch_bin == "wget") and "wget -q --timeout=3 -O -" or "uclient-fetch -q --timeout=3 -O -"
        metrics = sys.exec(string.format("%s 'http://127.0.0.1:%d/metrics' 2>/dev/null", fetch_cmd, m_port) .. " | grep -E '^telemt_user|^telemt_uptime|^telemt_connections|^telemt_desync_total'") or ""
    end
    local f = io.open("/tmp/telemt_stats.txt", "r")
    if f then
        metrics = metrics .. "\n# ACCUMULATED\n"
        for line in f:lines() do
            local u, tx, rx = line:match("^(%S+) (%S+) (%S+)$")
            if u then metrics = metrics .. string.format("telemt_accumulated_tx{user=\"%s\"} %s\ntelemt_accumulated_rx{user=\"%s\"} %s\n", u, tx, u, rx) end
        end
        f:close()
    end
    http.prepare_content("text/plain"); http.write(metrics); http.close(); return
end

if http.formvalue("get_log") == "1" then
    http.prepare_content("text/plain")
    local cmd = "logread -e 'telemt' | tail -n 50 2>/dev/null"
    if has_cmd("timeout") then cmd = "timeout 2 " .. cmd end
    local log_data = sys.exec(cmd); if not log_data or log_data:gsub("%s+", "") == "" then log_data = "No logs found." end
    -- Escaping HTML chars to prevent UI breaking
    log_data = log_data:gsub("\27%[[%d;]*m", ""):gsub("<", "&lt;"):gsub(">", "&gt;")
    http.write(log_data); http.close(); return
end

if http.formvalue("get_wan_ip") == "1" then
    http.prepare_content("text/plain")
    local fetch_cmd = (fetch_bin == "wget") and "wget -q --timeout=3 -O -" or "uclient-fetch -q --timeout=3 -O -"
    local ip = sys.exec(fetch_cmd .. " https://ipv4.internet.yandex.net/api/v0/ip 2>/dev/null") or ""
    ip = ip:gsub("%s+", ""):gsub("\"", "")
    if not ip:match("^%d+%.%d+%.%d+%.%d+$") then ip = sys.exec(fetch_cmd .. " https://checkip.amazonaws.com 2>/dev/null") or ""; ip = ip:gsub("%s+", "") end
    if not ip:match("^%d+%.%d+%.%d+%.%d+$") then ip = "0.0.0.0" end
    http.write(ip); http.close(); return
end

if http.formvalue("get_qr") == "1" then
    local link = http.formvalue("link")
    if not link or link == "" then http.close(); return end
    if not link:match("^tg://proxy%?[a-zA-Z0-9=%%&_.-]+$") then http.prepare_content("text/plain"); http.write("error: invalid_link"); http.close(); return end
    if not has_cmd("qrencode") then http.prepare_content("text/plain"); http.write("error: qrencode_missing"); http.close(); return end
    http.prepare_content("image/svg+xml")
    local cmd = string.format("qrencode -t SVG -s 4 -m 1 -o - %q 2>/dev/null", link)
    if has_cmd("timeout") then cmd = "timeout 2 " .. cmd end
    local svg = sys.exec(cmd); http.write(svg); http.close(); return
end

local clean_csv = "username,secret,max_tcp_conns,max_unique_ips,data_quota,expire_date\n"
uci_cursor:foreach("telemt", "user", function(s)
    local name = s['.name'] or ""; local sec = s.secret or ""; local conns = s.max_tcp_conns or ""; local uips = s.max_unique_ips or ""; local quota = s.data_quota or ""; local exp = s.expire_date or ""
    clean_csv = clean_csv .. string.format("%s,%s,%s,%s,%s,%s\n", name, sec, conns, uips, quota, exp)
end)
clean_csv = clean_csv:gsub("\n", "\\n"):gsub("\r", "")

local function norm_secret(s)
    if not s then return nil end
    s = s:match("secret=(%x+)") or s; local hex = s:match("(%x+)")
    if not hex then return nil end; local pfx = hex:sub(1,2):lower()
    if pfx == "ee" or pfx == "dd" then hex = hex:sub(3) end
    if #hex < 32 then return nil end; return hex:sub(1, 32):lower()
end

if is_post and http.formvalue("import_users") == "1" then
    local csv = http.formvalue("csv_data")
    if csv and csv ~= "" then
        local valid_users = {}
        local char_cr = string.char(13); local char_lf = string.char(10); local bom = string.char(239, 187, 191)
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
            if http.formvalue("import_mode") == "replace" then
                local to_delete = {}; uci_cursor:foreach("telemt", "user", function(s) table.insert(to_delete, s['.name']) end)
                for _, name in ipairs(to_delete) do uci_cursor:delete("telemt", name) end
            end
            for _, v in ipairs(valid_users) do
                uci_cursor:set("telemt", v.u, "user"); uci_cursor:set("telemt", v.u, "secret", v.sec)
                if v.c and v.c ~= "" then uci_cursor:set("telemt", v.u, "max_tcp_conns", v.c) else uci_cursor:delete("telemt", v.u, "max_tcp_conns") end
                if v.uips and v.uips ~= "" then uci_cursor:set("telemt", v.u, "max_unique_ips", v.uips) else uci_cursor:delete("telemt", v.u, "max_unique_ips") end
                if v.q and v.q ~= "" then uci_cursor:set("telemt", v.u, "data_quota", v.q) else uci_cursor:delete("telemt", v.u, "data_quota") end
                if v.exp and v.exp:match("^%d%d%.%d%d%.%d%d%d%d %d%d:%d%d$") then uci_cursor:set("telemt", v.u, "expire_date", v.exp) else uci_cursor:delete("telemt", v.u, "expire_date") end
            end
            uci_cursor:save("telemt"); uci_cursor:commit("telemt")
            sys.call("logger -t telemt \"WebUI: Successfully imported " .. #valid_users .. " users via CSV.\"")
            local redir = current_url
            if redir:match("?") then redir = redir .. "&import_ok=" .. tostring(#valid_users) else redir = redir .. "?import_ok=" .. tostring(#valid_users) end
            http.redirect(redir); return
        end
    end
    http.redirect(current_url); return
end

local bin_info = ""
if not is_ajax then
    local bin_path = (sys.exec("command -v telemt 2>/dev/null") or ""):gsub("%s+", "")
    if bin_path == "" then bin_info = "<span style='color:#d9534f; font-weight:bold; font-size:0.9em;'>Not installed (telemt binary not found)</span>"
    else local ver = read_file("/var/etc/telemt.version"); if ver == "" then ver = "unknown" end; bin_info = string.format("<small style='opacity: 0.6;'>%s (v%s)</small>", bin_path, ver) end
end

m = Map("telemt", "Telegram Proxy (MTProto)", [[Multi-user proxy server based on <a href="https://github.com/telemt/telemt" target="_blank" style="text-decoration:none; color:inherit; font-weight:bold; border-bottom: 1px dotted currentColor;">telemt</a>.<br><b>LuCI App Version: 3.1.2-8 (Master)</b>]])
m.on_commit = function(self) sys.call("logger -t telemt 'WebUI: Config saved. Dumping stats before procd reload...'; /etc/init.d/telemt run_save_stats 2>/dev/null") end

s = m:section(NamedSection, "general", "telemt")
s:tab("general", "General Settings")
s:tab("upstream", "Upstream Proxy")
s:tab("users", "Users")
s:tab("advanced", "Advanced Tuning")
s:tab("bot", "Telegram Bot")
s:tab("log", "Diagnostics")
s.anonymous = true

-- ==============================================================================
-- TAB 1: GENERAL
-- ==============================================================================
s:taboption("general", Flag, "enabled", "Enable Service")
local ctrl = s:taboption("general", DummyValue, "_controls", "Controls")
ctrl.rawhtml = true; ctrl.default = string.format([[<div class="btn-controls"><input type="button" class="cbi-button cbi-button-apply" id="btn_telemt_start" value="Start" /><input type="button" class="cbi-button cbi-button-reset" id="btn_telemt_stop" value="Stop" /><input type="button" class="cbi-button cbi-button-reload" id="btn_telemt_restart" value="Restart" /></div><script>function postAction(action) { var form = document.createElement('form'); form.method = 'POST'; form.action = '%s'.split('#')[0]; var input = document.createElement('input'); input.type = 'hidden'; input.name = action; input.value = '1'; form.appendChild(input); var token = document.querySelector('input[name="token"]'); if (token) { var t = document.createElement('input'); t.type = 'hidden'; t.name = 'token'; t.value = token.value; form.appendChild(t); } else if (typeof L !== 'undefined' && L.env && L.env.token) { var t2 = document.createElement('input'); t2.type = 'hidden'; t2.name = 'token'; t2.value = L.env.token; form.appendChild(t2); } document.body.appendChild(form); form.submit(); } setTimeout(function(){ var b1=document.getElementById('btn_telemt_start'); if(b1) b1.addEventListener('click', function(){ logAction('Manual Start'); postAction('start'); }); var b2=document.getElementById('btn_telemt_stop'); if(b2) b2.addEventListener('click', function(){ logAction('Manual Stop'); postAction('stop'); }); var b3=document.getElementById('btn_telemt_restart'); if(b3) b3.addEventListener('click', function(){ logAction('Manual Restart'); postAction('restart'); }); }, 500);</script>]], current_url)

local pid = ""
if not is_ajax then pid = (sys.exec("pidof telemt | awk '{print $1}'") or ""):gsub("%s+", "") end
local process_status = "<span style='color:#d9534f; font-weight:bold;'>STOPPED</span><br>" .. bin_info
if pid ~= "" and sys.call("kill -0 " .. pid .. " 2>/dev/null") == 0 then process_status = string.format("<span style='color:green;font-weight:bold'>RUNNING (PID: %s)</span><br>%s", pid, bin_info) end
local st = s:taboption("general", DummyValue, "_status", "Process Status"); st.rawhtml = true; st.value = process_status

local mode = s:taboption("general", ListValue, "mode", "Protocol Mode"); mode:value("tls", "FakeTLS (Recommended)"); mode:value("dd", "DD (Random Padding)"); mode:value("classic", "Classic"); mode:value("all", "All together (Debug)"); mode.default = "tls"
local lfmt = s:taboption("general", ListValue, "_link_fmt", "Link Format to Display"); lfmt:depends("mode", "all"); lfmt:value("tls", "FakeTLS (Recommended)"); lfmt:value("dd", "Secure (DD)"); lfmt:value("classic", "Classic"); lfmt.default = "tls"

local dom = s:taboption("general", Value, "domain", "FakeTLS Domain" .. tip("Domain for DPI masking")); dom.datatype = "hostname"; dom.default = "google.com"; dom.description = "<span class='warn-txt' style='color:#d35400; font-weight:bold;'>Warning: Change the default domain!</span>"; dom:depends("mode", "tls"); dom:depends("mode", "all")

local saved_ip = m.uci:get("telemt", "general", "external_ip")
if type(saved_ip) == "table" then saved_ip = saved_ip[1] end
saved_ip = saved_ip or ""; if saved_ip:match("%s") then saved_ip = saved_ip:match("^([^%s]+)") end

local myip = s:taboption("general", Value, "external_ip", "External IP / DynDNS" .. tip("IP address or domain used strictly for generating tg:// links in UI.")); myip.datatype = "string"; myip.default = saved_ip
function myip.validate(self, value)
    if value and #value > 0 then value = value:match("^([^%s]+)"); if not value:match("^[a-zA-Z0-9%-%.:]+$") then return nil, "Invalid characters! Allowed: a-z, 0-9, . - :" end end return value
end

local p = s:taboption("general", Value, "port", "Proxy Port"); p.datatype = "port"; p.rmempty = false
local afw = s:taboption("general", Flag, "auto_fw", "Auto-open Port (Magic)"); afw.default = "0"; afw.description = string.format("<div style='margin-top:5px; padding:8px; background:rgba(128,128,128,0.1); border-left:3px solid #00a000; font-size:0.9em;'><b>Current Status:</b> <span id='fw_status_span' style='color:#888; font-style:italic;'>Checking...</span></div>")

local hll = s:taboption("general", DummyValue, "_head_ll"); hll.rawhtml = true; hll.default = "<h3 style='margin-top:20px;'>Logging</h3>"
local ll = s:taboption("general", ListValue, "log_level", "Log Level"); ll:value("debug", "Debug"); ll:value("verbose", "Verbose"); ll:value("normal", "Normal (default)"); ll:value("silent", "Silent"); ll.default = "normal"


-- ==============================================================================
-- TAB 2: UPSTREAMS (Master Switch + Anchors)
-- ==============================================================================
local up_master = s:taboption("upstream", Flag, "enable_upstreams", "Enable Upstream Routing" .. tip("Master switch. If unchecked, all proxy traffic is routed Direct.")); up_master.default = "0"
local anchor_up = s:taboption("upstream", DummyValue, "_up_anchor", ""); anchor_up.rawhtml = true; anchor_up.default = '<div id="upstreams_tab_anchor" style="display:none"></div>'


-- ==============================================================================
-- TAB 3: USERS (Anchors & Hidden IPs)
-- ==============================================================================
local anchor = s:taboption("users", DummyValue, "_users_anchor", ""); anchor.rawhtml = true; anchor.default = '<div id="users_tab_anchor" style="display:none"></div>'
local myip_u = s:taboption("users", DummyValue, "_ip_display", ""); myip_u.rawhtml = true; myip_u.default = string.format([[<div id="telemt_mirror_ip_wrapper" style="display:none;"><div style="display:flex; align-items:center; gap:10px;"><span style="font-weight:bold; color:#555;">External IP / DynDNS:</span><input type="text" class="cbi-input-text" style="width:200px;" id="telemt_mirror_ip" value="%s"><input type="button" class="cbi-button cbi-button-neural" value="Get IP" onclick="fetchIPViaWget(this)"></div></div>]], saved_ip)


-- ==============================================================================
-- TAB 4: ADVANCED TUNING
-- ==============================================================================
local hnet = s:taboption("advanced", DummyValue, "_head_net"); hnet.rawhtml = true; hnet.default = "<h3 style='margin-top:15px;'>Network Listeners</h3>"
s:taboption("advanced", Flag, "listen_ipv4", "Enable IPv4 Listener").default = "1"
s:taboption("advanced", Flag, "listen_ipv6", "Enable IPv6 Listener (::)").default = "0"
local pref_ip = s:taboption("advanced", ListValue, "prefer_ip", "Preferred IP Protocol"); pref_ip:value("4", "IPv4"); pref_ip:value("6", "IPv6"); pref_ip.default = "4"

local hme = s:taboption("advanced", DummyValue, "_head_me"); hme.rawhtml = true; hme.default = "<h3 style='margin-top:20px;'>Middle-End Proxy</h3>"
local mp = s:taboption("advanced", Flag, "use_middle_proxy", "Use ME Proxy"); mp.default = "0"; mp.description = "<span style='color:#d35400; font-weight:bold;'>Requires public IP on interface OR NAT 1:1 with STUN enabled.</span>"
local stun = s:taboption("advanced", Flag, "use_stun", "Enable STUN-probing"); stun:depends("use_middle_proxy", "1"); stun.default = "1"
s:taboption("advanced", Value, "me_pool_size", "ME Pool Size"):depends("use_middle_proxy", "1")
s:taboption("advanced", Value, "me_warm_standby", "ME Warm Standby"):depends("use_middle_proxy", "1")
s:taboption("advanced", Flag, "hardswap", "ME Pool Hardswap"):depends("use_middle_proxy", "1")
s:taboption("advanced", Value, "me_drain_ttl", "ME Drain TTL (sec)"):depends("use_middle_proxy", "1")
local auto_deg = s:taboption("advanced", Flag, "auto_degradation", "Auto-Degradation"); auto_deg:depends("use_middle_proxy", "1"); auto_deg.default = "1"
s:taboption("advanced", Value, "degradation_min_dc", "Degradation Min DC"):depends("auto_degradation", "1")

-- Spoiler 1: Additional Options
local hadv = s:taboption("advanced", DummyValue, "_head_adv"); hadv.rawhtml = true
hadv.default = [[<details id="telemt_adv_opts_details" style="margin-top:20px; margin-bottom:15px; padding:10px; background:rgba(128,128,128,0.05); border:1px solid rgba(128,128,128,0.3); border-radius:6px; cursor:pointer;"><summary style="font-weight:bold; outline:none; font-size:1.05em;">Additional Options (Click to expand)</summary><div id="telemt_adv_opts_content" style="margin-top:10px;"></div></details>]]

s:taboption("advanced", Flag, "desync_all_full", "Full Crypto-Desync Logs").default = "0"
local mpp = s:taboption("advanced", ListValue, "mask_proxy_protocol", "Mask Proxy Protocol"); mpp:value("0", "0 (Off)"); mpp:value("1", "1 (v1 - Text)"); mpp:value("2", "2 (v2 - Binary)"); mpp.default = "0"
local ip_ann = s:taboption("advanced", Value, "announce_ip", "Announce Address"); ip_ann.datatype = "string"
function ip_ann.validate(self, value) if value and #value > 0 then value = value:match("^([^%s]+)"); if not value:match("^[a-zA-Z0-9%-%.:]+$") then return nil, "Invalid characters!" end end return value end
local ad = s:taboption("advanced", Value, "ad_tag", "Ad Tag"); ad.datatype = "hexstring"
function ad.validate(self, value) if value and #value > 0 and #value ~= 32 then return nil, "Ad Tag must be exactly 32 hex characters!" end return value end
s:taboption("advanced", Value, "fake_cert_len", "Fake Cert Length").datatype = "uinteger"
s:taboption("advanced", Value, "tls_full_cert_ttl_secs", "TLS Full Cert TTL (sec)").datatype = "uinteger"
s:taboption("advanced", Flag, "ignore_time_skew", "Ignore Time Skew").default = "0"

-- Spoiler 2: Timeouts
local htm = s:taboption("advanced", DummyValue, "_head_tm"); htm.rawhtml = true
htm.default = [[<details id="telemt_timeouts_details" style="margin-top:20px; margin-bottom:15px; padding:10px; background:rgba(128,128,128,0.05); border:1px solid rgba(128,128,128,0.3); border-radius:6px; cursor:pointer;"><summary style="font-weight:bold; outline:none; font-size:1.05em;">Timeouts & Replay Protection (Click to expand)</summary><div id="telemt_timeouts_content" style="margin-top:10px;"></div></details>]]
s:taboption("advanced", Value, "tm_handshake", "Handshake").default = "15"
s:taboption("advanced", Value, "tm_connect", "Connect").default = "10"
s:taboption("advanced", Value, "tm_keepalive", "Keepalive").default = "60"
s:taboption("advanced", Value, "tm_ack", "ACK").default = "300"
s:taboption("advanced", Value, "replay_window_secs", "Replay Window (sec)").default = "1800"

local hmet = s:taboption("advanced", DummyValue, "_head_met"); hmet.rawhtml = true; hmet.default = "<h3 style='margin-top:20px;'>Metrics & Prometheus API</h3>"
s:taboption("advanced", Value, "metrics_port", "Metrics Port").default = "9091"
s:taboption("advanced", Flag, "metrics_allow_lo", "Allow Localhost").default = "1"
s:taboption("advanced", Flag, "metrics_allow_lan", "Allow LAN Subnet").default = "1"
local mwl = s:taboption("advanced", Value, "metrics_whitelist", "Additional Whitelist"); mwl.placeholder = "e.g. 10.8.0.0/24"
function mwl.validate(self, value) if not value or value == "" then return value end value = value:gsub("%s+", ""); for cidr in value:gmatch("([^,]+)") do if not cidr:match("^[0-9a-fA-F%.:%/]+$") or not cidr:match("/%d+$") then return nil, "Invalid CIDR list." end end return value end
local cur_m_port = tonumber(m.uci:get("telemt", "general", "metrics_port")) or 9091
local mlink = s:taboption("advanced", DummyValue, "_mlink", "Prometheus Endpoint"); mlink.rawhtml = true; mlink.default = string.format([[<a href="http://127.0.0.1:%d/metrics" target="_blank" style="font-family: monospace; color:#00a000;">http://&lt;router_ip&gt;:%d/metrics</a>]], cur_m_port, cur_m_port)


-- ==============================================================================
-- TAB 5: TELEGRAM BOT
-- ==============================================================================
local bot_head = s:taboption("bot", DummyValue, "_bot_head", ""); bot_head.rawhtml = true
bot_head.default = [[<div style="padding:15px; background:rgba(0,136,204,0.05); border-left:4px solid #0088cc; border-radius:4px; margin-bottom:20px;">
<h3 style="margin-top:0; color:#0088cc;">Telegram Bot & Alerts</h3>
<p style="margin-bottom:0; font-size:0.95em;">The bot backend is currently under development. These settings will be active in the next release.</p></div>]]

local bot_en = s:taboption("bot", DummyValue, "bot_enabled", "Enable Bot"); bot_en.rawhtml = true; bot_en.default = [[<input type="checkbox" disabled> <span style="opacity:0.6;">(Coming soon)</span>]]
s:taboption("bot", Value, "bot_token", "Bot Token" .. tip("From @BotFather"))
s:taboption("bot", Value, "bot_chat_id", "Admin Chat ID" .. tip("Your personal ID or Group ID"))


-- ==============================================================================
-- TAB 6: LOGS
-- ==============================================================================
local lv = s:taboption("log", DummyValue, "_lv"); lv.rawhtml = true
lv.default = [[<div style="width:100%; box-sizing:border-box; height:500px; font-family:monospace; font-size:12px; padding:12px; background: #1e1e1e; color: #d4d4d4; border: 1px solid #333; border-radius: 4px; overflow-y:auto; overflow-x:auto; white-space:pre;" id="telemt_log_container">Click "Load Log" to view system logs.</div><div style="margin-top:10px; display:flex; gap:10px;"><input type="button" class="cbi-button cbi-button-apply" id="btn_load_log" value="Load Log" /><input type="button" class="cbi-button cbi-button-action" id="btn_copy_log" value="Copy Log" /></div><script>setTimeout(function(){ var b1=document.getElementById('btn_load_log'); if(b1) b1.addEventListener('click', loadLog); var b2=document.getElementById('btn_copy_log'); if(b2) b2.addEventListener('click', function(){ copyLogContent(this); }); }, 500);</script>]]


-- ==============================================================================
-- SECTION 1: UPSTREAMS (Block form, NO tblsection template)
-- ==============================================================================
s3 = m:section(TypedSection, "upstream", "Routing Chain")
s3.addremove = true
s3.anonymous = false

local up_en = s3:option(Flag, "enabled", "Enable")
up_en.default = "1"; up_en.rmempty = false

local up_type = s3:option(ListValue, "type", "Protocol Type")
up_type:value("direct", "Direct")
up_type:value("socks4", "SOCKS4")
up_type:value("socks5", "SOCKS5")
up_type.default = "socks5"

local up_addr = s3:option(Value, "address", "Address (IP:Port)")
up_addr.placeholder = "192.168.1.1:1080"
up_addr:depends("type", "socks4")
up_addr:depends("type", "socks5")
function up_addr.validate(self, value)
    if not value or value == "" then return value end
    if not value:match("^[a-zA-Z0-9%-%.:]+$") then return nil, "Invalid format (e.g. 192.168.1.1:1080)" end
    return value
end

local up_user = s3:option(Value, "username", "Username")
up_user:depends("type", "socks5")

local up_pass = s3:option(Value, "password", "Password")
up_pass.password = true
up_pass:depends("type", "socks5")

local up_weight = s3:option(Value, "weight", "Weight")
up_weight.datatype = "uinteger"
up_weight.default = "10"


-- ==============================================================================
-- SECTION 2: USERS (Table format)
-- ==============================================================================
s2 = m:section(TypedSection, "user", "")
s2.template = "cbi/tblsection"
s2.addremove = true
s2.anonymous = false
s2.create = function(self, section) 
    if not section or not section:match("^[A-Za-z0-9_]+$") then return nil end 
    if #section > 15 then return nil end 
    sys.call(string.format("logger -t telemt 'WebUI: Added new user -> %s'", section:gsub("[^A-Za-z0-9_]", "")))
    return TypedSection.create(self, section) 
end
s2.remove = function(self, section) 
    sys.call(string.format("logger -t telemt 'WebUI: Deleted user -> %s'", section:gsub("[^A-Za-z0-9_]", "")))
    return TypedSection.remove(self, section) 
end

local sec = s2:option(Value, "secret", "Secret (32 hex)")
sec.rmempty = false; sec.datatype = "hexstring"
function sec.validate(self, value)
    if not value or value:gsub("%s+", "") == "" then local uuid = sys.exec("cat /proc/sys/kernel/random/uuid") or ""; value = uuid:gsub("%-", ""):gsub("%s+", ""):sub(1,32) end
    if #value ~= 32 or not value:match("^[0-9a-fA-F]+$") then return nil, "Secret must be exactly 32 hex chars!" end
    return value
end

local t_con = s2:option(Value, "max_tcp_conns", "TCP Conns"); t_con.datatype = "uinteger"; t_con.placeholder = "unlimited"
local t_uips = s2:option(Value, "max_unique_ips", "Max IPs"); t_uips.datatype = "uinteger"; t_uips.placeholder = "unlimited"
local t_qta = s2:option(Value, "data_quota", "Quota (GB)"); t_qta.datatype = "ufloat"; t_qta.placeholder = "unlimited"
local t_exp = s2:option(Value, "expire_date", "Expire Date"); t_exp.datatype = "string"; t_exp.placeholder = "DD.MM.YYYY HH:MM"
function t_exp.validate(self, value) if not value then return "" end value = value:match("^%s*(.-)%s*$"); if value == "" or value == "unlimited" then return "" end if not value:match("^%d%d%.%d%d%.%d%d%d%d %d%d:%d%d$") then return nil, "Format: DD.MM.YYYY HH:MM" end return value end

local lst = s2:option(DummyValue, "_stat", "Live Traffic"); lst.rawhtml = true; function lst.cfgvalue(self, section) return string.format('<div class="user-flat-stat" data-user="%s"><span style="color:#888;">No Data</span></div>', section:gsub("[<>&\"']", "")) end
local lnk = s2:option(DummyValue, "_link", "Ready-to-use link"); lnk.rawhtml = true; lnk.default = [[<div class="link-wrapper"><input type="text" class="cbi-input-text user-link-out" readonly onclick="this.select()"></div>]]


-- ==============================================================================
-- MASSIVE CSS & JS INJECTION (The Soul of the Golden Master)
-- ==============================================================================
m.description = [[
<style>
.cbi-value-helpicon, img[src*="help.gif"], img[src*="help.png"] { display: none !important; }
#cbi-telemt-user .cbi-section-table-descr { display: none !important; width: 0 !important; height: 0 !important; visibility: hidden !important; }
#cbi-telemt-user .cbi-row-template, #cbi-telemt-user [id*="-template"] { display: none !important; visibility: hidden !important; height: 0 !important; overflow: hidden !important; pointer-events: none !important; }

/* Add User Button (Green Styling) */
html body #cbi-telemt-user .cbi-button-add { color: #00a000 !important; -webkit-text-fill-color: #00a000 !important; background-color: transparent !important; border: 1px solid #00a000 !important; padding: 0 16px !important; height: 32px !important; line-height: 30px !important; border-radius: 4px !important; font-weight: bold !important; box-shadow: none !important; }
html body #cbi-telemt-user .cbi-button-add:hover { background-color: #00a000 !important; color: #ffffff !important; -webkit-text-fill-color: #ffffff !important; opacity: 1 !important; border-color: #00a000 !important; }

/* Fix for native columns */
#cbi-telemt-user .cbi-section-table td:first-child { vertical-align: middle !important; }

/* Delete Buttons styling */
html body #cbi-telemt-user .cbi-section-table .cbi-button-remove:not(.telemt-btn-cross), html body #cbi-telemt-user .cbi-section-table .cbi-button-del, html body #cbi-telemt-user .cbi-section-actions .cbi-button-remove:not(.telemt-btn-cross), html body #cbi-telemt-user td.cbi-section-actions .cbi-button-remove:not(.telemt-btn-cross), html body #cbi-telemt-upstream .cbi-section-table .cbi-button-remove { color: #d9534f !important; -webkit-text-fill-color: #d9534f !important; background-color: transparent !important; border: 1px solid #d9534f !important; padding: 0 12px !important; height: 30px !important; line-height: 28px !important; border-radius: 4px; }
html body #cbi-telemt-user .cbi-section-table .cbi-button-remove:not(.telemt-btn-cross):hover, html body #cbi-telemt-user .cbi-section-table .cbi-button-del:hover, html body #cbi-telemt-upstream .cbi-section-table .cbi-button-remove:hover { background-color: #d9534f !important; color: #ffffff !important; -webkit-text-fill-color: #ffffff !important; }

.cbi-value-description { margin: -8px 0 0 0 !important; padding: 0 !important; font-size: 0.85em !important; opacity: 0.8; display: block !important; white-space: normal !important; }
.telemt-tip { display: inline-block !important; cursor: help !important; opacity: 0.5 !important; font-size: 0.85em !important; border-bottom: 1px dotted currentColor !important; margin-left: 4px !important; }
#cbi-telemt-user .cbi-section-table th { white-space: nowrap !important; vertical-align: middle !important; }
#cbi-telemt-user .cbi-section-table td:last-child, #cbi-telemt-user .cbi-section-table th:last-child { width: 1% !important; white-space: nowrap !important; vertical-align: middle !important; padding-top: 0 !important; text-align: center !important; }

[data-name="external_ip"] .cbi-value-field, #cbi-telemt-general-external_ip .cbi-value-field { display: flex !important; align-items: center !important; }
.telemt-sec-wrap { display: flex; flex-direction: column; width: 100%; gap: 4px; }
.telemt-sec-btns, .link-btn-group { display: flex; gap: 4px; }
.telemt-sec-btns input.cbi-button, .link-btn-group input.cbi-button { flex: 1; height: 20px !important; min-height: 20px !important; line-height: 18px !important; padding: 0 8px !important; font-size: 11px !important; }
.telemt-num-wrap { display: flex !important; align-items: center !important; width: 100% !important; box-sizing: border-box !important; gap: 4px; height: 32px; }
.telemt-num-wrap > input:not([type="button"]) { flex: 1 1 auto !important; width: 100% !important; min-width: 40px !important; height: 100% !important; margin: 0 !important; }

.telemt-btn-cross { flex: 0 0 24px !important; width: 24px !important; min-width: 24px !important; height: 24px !important; min-height: 24px !important; padding: 0 !important; margin: 0 !important; cursor: pointer !important; background-color: transparent !important; background-image: url("data:image/svg+xml;charset=utf-8,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%23666666' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Cline x1='18' y1='6' x2='6' y2='18'/%3E%3Cline x1='6' y1='6' x2='18' y2='18'/%3E%3C/svg%3E") !important; background-repeat: no-repeat !important; background-position: center !important; background-size: 14px !important; border: none !important; box-shadow: none !important; opacity: 1 !important; transition: all 0.2s ease !important; }
.telemt-btn-cross:hover { background-color: rgba(217, 83, 79, 0.1) !important; border-radius: 4px; background-image: url("data:image/svg+xml;charset=utf-8,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%23d9534f' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Cline x1='18' y1='6' x2='6' y2='18'/%3E%3Cline x1='6' y1='6' x2='18' y2='18'/%3E%3C/svg%3E") !important; }
.telemt-cal-wrap { position: relative; display: flex; flex: 0 0 24px; width: 24px; height: 24px; margin: 0; }
.telemt-btn-cal { width: 100% !important; height: 100% !important; padding: 0 !important; margin: 0 !important; cursor: pointer !important; background-color: transparent !important; background-image: url("data:image/svg+xml;charset=utf-8,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%23666666' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Crect x='3' y='4' width='18' height='18' rx='2' ry='2'/%3E%3Cline x1='16' y1='2' x2='16' y2='6'/%3E%3Cline x1='8' y1='2' x2='8' y2='6'/%3E%3Cline x1='3' y1='10' x2='21' y2='10'/%3E%3C/svg%3E") !important; background-repeat: no-repeat !important; background-position: center !important; background-size: 14px !important; border: none !important; box-shadow: none !important; opacity: 1 !important; transition: all 0.2s ease !important; }
.telemt-cal-wrap:hover .telemt-btn-cal { background-color: rgba(0, 160, 0, 0.1) !important; border-radius: 4px; background-image: url("data:image/svg+xml;charset=utf-8,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%2300a000' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Crect x='3' y='4' width='18' height='18' rx='2' ry='2'/%3E%3Cline x1='16' y1='2' x2='16' y2='6'/%3E%3Cline x1='8' y1='2' x2='8' y2='6'/%3E%3Cline x1='3' y1='10' x2='21' y2='10'/%3E%3C/svg%3E") !important; }
.telemt-cal-picker { position: absolute; top: 0; left: 0; width: 100%; height: 100%; opacity: 0; cursor: pointer; color-scheme: light dark; z-index:2; }

@media (prefers-color-scheme: dark) {
    .telemt-btn-cross { background-image: url("data:image/svg+xml;charset=utf-8,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%23cccccc' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Cline x1='18' y1='6' x2='6' y2='18'/%3E%3Cline x1='6' y1='6' x2='18' y2='18'/%3E%3C/svg%3E") !important; }
    .telemt-btn-cal { background-image: url("data:image/svg+xml;charset=utf-8,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%23cccccc' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Crect x='3' y='4' width='18' height='18' rx='2' ry='2'/%3E%3Cline x1='16' y1='2' x2='16' y2='6'/%3E%3Cline x1='8' y1='2' x2='8' y2='6'/%3E%3Cline x1='3' y1='10' x2='21' y2='10'/%3E%3C/svg%3E") !important; }
}

#cbi-telemt-user .user-link-out { height: 32px !important; line-height: 32px !important; width: 100%; font-family: monospace; font-size: 11px; background: transparent !important; color: inherit !important; border: 1px solid var(--border-color, rgba(128,128,128,0.5)) !important; box-sizing: border-box; margin: 0; cursor: pointer; }
.user-link-err { color: #d9534f !important; font-weight: bold; border-color: #d9534f !important; }
.user-flat-stat { display: flex; flex-wrap: wrap; align-items: center; line-height: 1.4; font-size: 0.95em; }
.stat-divider, .sum-divider { color: #ccc; margin: 0 4px; }
.telemt-dash-summary { font-size:1.05em; display:flex; flex-wrap:wrap; align-items:center; flex: 1 1 auto; row-gap: 5px; }

@media screen and (min-width: 769px) {
    #cbi-telemt-user .cbi-section-table { width: 100% !important; table-layout: auto !important; }
    #cbi-telemt-user .cbi-section-table td { padding: 6px 8px !important; white-space: nowrap !important; vertical-align: middle !important; }
    .user-flat-stat { flex-wrap: nowrap !important; white-space: nowrap !important; }
    td[data-name="_stat"] { min-width: 180px !important; }
    td[data-name="max_tcp_conns"] .telemt-num-wrap, td[data-name="max_unique_ips"] .telemt-num-wrap, td[data-name="data_quota"] .telemt-num-wrap { max-width: 95px !important; }
    td[data-name="expire_date"] { min-width: 155px !important; }
    td[data-name="expire_date"] .telemt-num-wrap { min-width: 155px !important; width: 100% !important; }
    td[data-name="_link"] .link-wrapper { min-width: 160px !important; }
    td[data-name="secret"] .telemt-sec-wrap { min-width: 160px !important; }
    .telemt-dash-btns, .telemt-action-btns { display: flex !important; align-items: center !important; gap: 10px !important; flex: 0 0 auto !important; }
    .telemt-dash-btns { margin-left: auto; }
    .telemt-dash-top-row { display:flex; justify-content:space-between; align-items:center; padding:12px; background:rgba(0,160,0,0.05); border:1px solid rgba(0,160,0,0.2); border-radius:6px; margin-bottom:15px; flex-wrap:wrap; gap:15px; }
    .telemt-dash-bot-row { display:flex; flex-direction:column; justify-content:center; align-items:center; gap:10px; margin-bottom:15px; text-align:center; width:100%; }
}

@media screen and (max-width: 768px) {
    #telemt_mirror_ip, input[name*="cbid.telemt.general.external_ip"] { flex: 1 1 100% !important; width: 100% !important; max-width: 100% !important; }
    #cbi-telemt-user .cbi-section-table .cbi-section-table-row { display: flex !important; flex-direction: column !important; margin-bottom: 15px !important; border: 1px solid var(--border-color, #ddd) !important; padding: 10px !important; border-radius: 6px !important; }
    #cbi-telemt-user .cbi-section-table td { display: block !important; width: 100% !important; box-sizing: border-box !important; padding: 6px 0 !important; border: none !important; white-space: normal !important; }
    #cbi-telemt-user .cbi-section-table td[data-title]::before { content: attr(data-title) !important; display: block !important; font-weight: bold !important; margin-bottom: 4px !important; color: var(--text-color, #555) !important; }
    #cbi-telemt-user .cbi-section-actions .cbi-button::before { display: none !important; content: none !important; }
    html body #cbi-telemt-user .cbi-section-table .cbi-button-remove:not(.telemt-btn-cross) { display: flex !important; width: 100% !important; max-width: 100% !important; height: 44px !important; font-size: 14px !important; align-items: center !important; justify-content: center !important; }
    .user-flat-stat { flex-direction: column; align-items: flex-start; }
    .stat-divider, .sum-divider { display: none !important; }
    .telemt-dash-btns, .telemt-action-btns { flex-direction: column; align-items: stretch; width: 100%; gap: 8px !important; }
    .telemt-dash-btns input.cbi-button { width: 100% !important; height: 36px !important; }
    .telemt-dash-top-row, .telemt-dash-bot-row { display:flex; flex-direction:column; padding:12px; margin-bottom:15px; }
}

.qr-modal-overlay { position: fixed; top: 0; left: 0; right: 0; bottom: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.8); z-index: 2147483647 !important; display: flex; align-items: center; justify-content: center; opacity: 0; pointer-events: none; transition: opacity 0.2s; }
.qr-modal-overlay.active { opacity: 1; pointer-events: auto; }
.custom-modal-content { background-color: var(--card-bg-color, #ffffff) !important; color: var(--text-color, #333333) !important; padding: 20px; border-radius: 8px; box-shadow: 0 10px 30px rgba(0,0,0,0.5); border: 1px solid var(--border-color, #cccccc) !important; text-align: center; max-width: 450px; width: 90%; }
#csv_text_area { background-color: var(--background-color, #f9f9f9) !important; color: var(--text-color, #333333) !important; border: 1px solid var(--border-color, #cccccc) !important; width: 100%; height: 120px; font-family: monospace; font-size: 11px; margin-bottom: 10px; box-sizing: border-box; padding: 5px; resize: vertical; }
</style>

<script type="text/javascript">
var lu_current_url = "]] .. safe_url .. [[";
var is_owrt25 = ]] .. is_owrt25_lua .. [[;

function logAction(msg) { console.log("[Telemt UI] " + msg); }
function escHTML(s) { return String(s).replace(/[&<>'"]/g, function(c) { return '&#' + c.charCodeAt(0) + ';'; }); }
function logToRouter(msg) { var form = new FormData(); form.append('log_ui_event', '1'); form.append('msg', msg); fetch(lu_current_url.split('#')[0], { method: 'POST', body: form }); }
function formatMB(bytes) { if(!bytes || bytes === 0) return '0.00 MB'; var mb = bytes / 1048576; if (mb >= 1024) return (mb / 1024).toFixed(2) + ' GB'; return mb.toFixed(2) + ' MB'; }
function formatUptime(secs) { if(!secs) return '0s'; var d = Math.floor(secs / 86400), h = Math.floor((secs % 86400) / 3600), m = Math.floor((secs % 3600) / 60), s = Math.floor(secs % 60); var str = ""; if(d > 0) str += d + "d "; if(h > 0 || d > 0) str += h + "h "; str += m + "m " + s + "s"; return str; }

window._telemtLastStats = null;

function fetchMetrics() {
    if (!document.getElementById('cbi-telemt-user')) return; 
    if (window._telemtFetching) return; window._telemtFetching = true;
    fetch(lu_current_url.split('#')[0] + (lu_current_url.indexOf('?') > -1 ? '&' : '?') + 'get_metrics=1&_t=' + Date.now()).then(r => r.text()).then(txt => {
        window._telemtFetching = false; txt = (txt || ""); 
        var userStats = {}; var allUserRows = document.querySelectorAll('.user-flat-stat');
        allUserRows.forEach(function(statEl) { var u = statEl.getAttribute('data-user'); if(u) userStats[u] = { live_rx: 0, live_tx: 0, acc_rx: 0, acc_tx: 0, conns: 0 }; });
        var globalStatsObj = { uptime: 0, dpiProbes: 0 }; var totalLiveRx = 0, totalLiveTx = 0, totalAccRx = 0, totalAccTx = 0;
        var lines = txt.split('\n');
        for (var i = 0; i < lines.length; i++) {
            var line = lines[i].trim(); if (line.indexOf('#') === 0 || line === "") continue;
            if (line.indexOf('telemt_uptime_seconds') === 0) { var m = line.match(/\s+([0-9\.eE\+\-]+)/); if(m) globalStatsObj.uptime = parseFloat(m[1]); continue; }
            if (line.indexOf('telemt_desync_total ') === 0) { var m = line.match(/\s+([0-9\.eE\+\-]+)/); if(m) globalStatsObj.dpiProbes = parseInt(m[1]); continue; }
            var userMatch = line.match(/user="([^"]+)"/);
            if (userMatch) {
                var u = userMatch[1]; if (!userStats[u]) userStats[u] = { live_rx: 0, live_tx: 0, acc_rx: 0, acc_tx: 0, conns: 0 };
                var valMatch = line.match(/\}\s+([0-9\.eE\+\-]+)/);
                if (valMatch) {
                    var val = parseFloat(valMatch[1]);
                    if (line.indexOf('telemt_user_octets_from_client') > -1) { userStats[u].live_rx = val; totalLiveRx += val; }
                    else if (line.indexOf('telemt_user_octets_to_client') > -1) { userStats[u].live_tx = val; totalLiveTx += val; }
                    else if (line.indexOf('telemt_user_connections_current') > -1) { userStats[u].conns = val; }
                    else if (line.indexOf('telemt_accumulated_rx') > -1) { userStats[u].acc_rx = val; totalAccRx += val; }
                    else if (line.indexOf('telemt_accumulated_tx') > -1) { userStats[u].acc_tx = val; totalAccTx += val; }
                }
            }
        }
        window._telemtLastStats = userStats; var totalRx = totalLiveRx + totalAccRx; var totalTx = totalLiveTx + totalAccTx;
        var totalConfiguredUsers = allUserRows.length; var usersOnline = 0;
        allUserRows.forEach(function(statEl) {
            var u = statEl.getAttribute('data-user'); var stat = userStats[u] || { live_rx: 0, live_tx: 0, acc_rx: 0, acc_tx: 0, conns: 0 };
            var finalTx = stat.live_tx + stat.acc_tx; var finalRx = stat.live_rx + stat.acc_rx; if (stat.conns > 0) usersOnline++;
            var c_col = stat.conns > 0 ? "#00a000" : "#888"; var c_cls = stat.conns > 0 ? "telemt-conns-bold" : "";
            var dotUser = "<svg width='10' height='10' style='vertical-align:middle;'><circle cx='5' cy='5' r='5' fill='" + c_col + "'/></svg>";
            statEl.innerHTML = "<div style='display:flex; align-items:center; gap:4px; margin-bottom:2px; flex-wrap:wrap;'><span style='white-space:nowrap; color:#00a000;'>&darr; " + formatMB(finalTx) + "</span> <span class='stat-divider'>/</span> <span style='white-space:nowrap; color:#d35400;'>&uarr; " + formatMB(finalRx) + "</span> <span class='stat-divider'>|</span> <span style='white-space:nowrap; color:" + c_col + ";' class='" + c_cls + "'>" + dotUser + "&nbsp;" + stat.conns + "&nbsp;<small style='font-weight:normal;'>conns</small></span></div>";
        });
        var now = Date.now(); var speedDL = 0, speedUL = 0; 
        if (typeof window._telemtLastTime === 'undefined' || window._telemtLastTime === 0) { window._telemtLastTime = now; window._telemtLastTotalRx = totalRx; window._telemtLastTotalTx = totalTx; } 
        else {
            var diffSec = (now - window._telemtLastTime) / 1000.0;
            if (diffSec > 0) { var dRx = totalRx - window._telemtLastTotalRx; var dTx = totalTx - window._telemtLastTotalTx; if (dRx >= 0) speedUL = (dRx * 8) / 1048576 / diffSec; if (dTx >= 0) speedDL = (dTx * 8) / 1048576 / diffSec; }
            window._telemtLastTime = now; window._telemtLastTotalRx = totalRx; window._telemtLastTotalTx = totalTx;
        }
        var sumEl = document.getElementById('telemt_users_summary_inner');
        if (sumEl) {
            if (txt.trim() === "") sumEl.innerHTML = "<span style='color:#d9534f; font-weight:bold;'>Status: Offline</span><span class='sum-divider'>|</span><span><b style='color:#555;'>Total DL:</b> <span style='color:#00a000;'>&darr; " + formatMB(totalTx) + "</span></span><span class='sum-divider'>|</span><span><b style='color:#555;'>Total UL:</b> <span style='color:#d35400;'>&uarr; " + formatMB(totalRx) + "</span></span><span class='sum-divider'>|</span><span><b style='color:#555;'>Users Online:</b> <b style='color:#888; margin-left:4px;'>0</b>/" + totalConfiguredUsers + "</span>";
            else {
                var dpiColor = globalStatsObj.dpiProbes > 0 ? "#d9534f" : "#888";
                sumEl.innerHTML = "<b style='margin-right:6px;'>Uptime:</b><span style='color:#666;'>" + formatUptime(globalStatsObj.uptime) + "</span><span class='sum-divider'>|</span><span><b style='color:#555;'>Total DL:</b> <span style='color:#00a000;'>&darr; " + formatMB(totalTx) + "</span></span><span class='sum-divider'>|</span><span><b style='color:#555;'>Total UL:</b> <span style='color:#d35400;'>&uarr; " + formatMB(totalRx) + "</span></span><span class='sum-divider'>|</span><span><b style='color:#555;'>Bandwidth:</b> <span style='color:#00a000;'>&darr; " + speedDL.toFixed(2) + "</span> <span style='color:#d35400; margin-left:4px;'>&uarr; " + speedUL.toFixed(2) + "</span> <small>Mbps</small></span><span class='sum-divider'>|</span><span title='DPI/Censorship tampering attempts'><b style='color:#555;'>DPI Probes:</b> <b style='color:" + dpiColor + "; margin-left:4px;'>" + globalStatsObj.dpiProbes + "</b></span><span class='sum-divider'>|</span><span><b style='color:#555;'>Users Online:</b> <b style='color:#00a000; margin-left:4px;'>" + usersOnline + "</b>/" + totalConfiguredUsers + "</span>";
            }
        }
    }).catch(() => { window._telemtFetching = false; });
}

function getEffectiveIP() {
    var m1 = document.querySelector('input[name*="cbid.telemt.general.external_ip"]'); var m2 = document.getElementById('telemt_mirror_ip');
    if (m2 && m2.offsetParent !== null) return m2.value.trim(); if (m1) return m1.value.trim(); return "0.0.0.0";
}

function updateLinks() {
    var d = document.querySelector('input[name*="domain"]'); var p = document.querySelector('input[name*="port"]'); var modeSelect = document.querySelector('select[name*="mode"]'); var fmtSelect = document.querySelector('select[name*="_link_fmt"]');
    var ip = getEffectiveIP(); var port = p ? p.value.trim() : "4443"; var domain = d ? d.value.trim() : ""; var mode = modeSelect ? modeSelect.value : "tls";
    var effectiveFmt = mode; if (mode === 'all' && fmtSelect) effectiveFmt = fmtSelect.value;
    if(!ip || !port) return;
    var hd = ""; if (domain && (effectiveFmt === 'tls' || effectiveFmt === 'all')) { for(var n=0; n<domain.length; n++) { var hex = domain.charCodeAt(n).toString(16); hd += (hex.length < 2 ? "0" + hex : hex); } }
    document.querySelectorAll('#cbi-telemt-user .cbi-section-table-row:not(.cbi-row-template)').forEach(function(row) {
        var secInp = row.querySelector('input[name*="secret"]'); var linkOut = row.querySelector('.user-link-out');
        if(secInp && linkOut) {
            var val = secInp.value.trim();
            if(/^[0-9a-fA-F]{32}$/.test(val)) { var finalSecret = (effectiveFmt === 'tls' || effectiveFmt === 'all') ? "ee" + val + hd : ((effectiveFmt === 'dd') ? "dd" + val : val); linkOut.value = "tg://proxy?server=" + ip + "&port=" + port + "&secret=" + finalSecret; linkOut.classList.remove('user-link-err'); } 
            else { linkOut.value = "Error: 32 hex chars required!"; linkOut.classList.add('user-link-err'); }
        }
    });
}

function genRandHex() { var arr = new Uint8Array(16); (window.crypto || window.msCrypto).getRandomValues(arr); var h = ""; for(var i=0; i<16; i++) { var hex = arr[i].toString(16); if(hex.length < 2) hex = "0" + hex; h += hex; } return h; }

function fetchIPViaWget(btn) {
    var oldVal = btn.value; btn.value = '...';
    fetch(lu_current_url.split('#')[0] + (lu_current_url.indexOf('?') > -1 ? '&' : '?') + 'get_wan_ip=1&_t=' + Date.now()).then(r => r.text()).then(txt => {
        var match = txt.match(/\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/);
        if (match) { var master = document.querySelector('input[name*="cbid.telemt.general.external_ip"]'); var mirror = document.getElementById('telemt_mirror_ip'); if(master) master.value = match[0]; if(mirror) mirror.value = match[0]; updateLinks(); }
        btn.value = oldVal;
    }).catch(() => { btn.value = oldVal; });
}

function closeModals() { document.querySelectorAll('.qr-modal-overlay').forEach(function(m) { m.classList.remove('active'); }); }
function showQRModal(link) {
    if (!link || link.indexOf('Error') === 0) return;
    var overlay = document.getElementById('qr-modal');
    if (!overlay) {
        overlay = document.createElement('div'); overlay.id = 'qr-modal'; overlay.className = 'qr-modal-overlay';
        var content = document.createElement('div'); content.className = 'custom-modal-content';
        var body = document.createElement('div'); body.id = 'qr-modal-body'; content.appendChild(body);
        var clsBtn = document.createElement('button'); clsBtn.className = 'cbi-button cbi-button-reset'; clsBtn.style.cssText = 'margin-top:15px; width:100%;'; clsBtn.innerText = 'Close';
        clsBtn.addEventListener('click', closeModals); content.appendChild(clsBtn); overlay.appendChild(content);
        document.body.appendChild(overlay); overlay.addEventListener('click', function(e) { if (e.target === overlay) closeModals(); });
    }
    var body = document.getElementById('qr-modal-body'); body.innerHTML = 'Generating...'; overlay.classList.add('active');
    fetch(lu_current_url.split('#')[0] + (lu_current_url.indexOf('?') > -1 ? '&' : '?') + 'get_qr=1&link=' + encodeURIComponent(link) + '&_t=' + Date.now()).then(r => r.text()).then(txt => {
        if (txt.indexOf('error: qrencode_missing') > -1) body.innerHTML = '<div style="color:#d9534f; font-weight:bold; margin-bottom:10px;">Install qrencode</div>';
        else if (txt.indexOf('error: invalid_link') > -1) body.innerHTML = '<div style="color:#d9534f; font-weight:bold;">Invalid Link Format</div>';
        else { var svgMatch = txt.match(/<svg[\s\S]*?<\/svg>/i); body.innerHTML = svgMatch ? svgMatch[0] : 'Error'; }
    }).catch(() => { body.innerHTML = 'Connection error.'; });
}

function doExportStats() {
    if (!window._telemtLastStats) { alert("Live stats not loaded yet. Wait a few seconds."); return; } logToRouter("Exporting Live Stats");
    var csv = "username,total_dl_bytes,total_ul_bytes,active_connections\n"; var grandTx = 0, grandRx = 0, grandConns = 0;
    for (var u in window._telemtLastStats) { if (window._telemtLastStats.hasOwnProperty(u)) { var s = window._telemtLastStats[u]; var tx = (s.live_tx || 0) + (s.acc_tx || 0); var rx = (s.live_rx || 0) + (s.acc_rx || 0); var c = (s.conns || 0); csv += u + "," + tx + "," + rx + "," + c + "\n"; grandTx += tx; grandRx += rx; grandConns += c; } }
    csv += "TOTAL_ALL_USERS," + grandTx + "," + grandRx + "," + grandConns + "\n";
    var blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' }); var link = document.createElement("a"); link.setAttribute("href", URL.createObjectURL(blob)); link.setAttribute("download", "telemt_traffic_stats.csv"); link.style.visibility = 'hidden'; document.body.appendChild(link); link.click(); document.body.removeChild(link);
}

function doExportCSV() { logToRouter("Exporting Users to CSV"); var csvData = "]] .. clean_csv .. [["; var blob = new Blob([csvData], { type: 'text/csv;charset=utf-8;' }); var link = document.createElement("a"); link.setAttribute("href", URL.createObjectURL(blob)); link.setAttribute("download", "telemt_users.csv"); link.style.visibility = 'hidden'; document.body.appendChild(link); link.click(); document.body.removeChild(link); }
function readCSVFile(input) { var file = input.files[0]; var displaySpan = document.getElementById('csv_file_name_display'); if (!file) { displaySpan.innerText = "No file selected"; return; } displaySpan.innerText = file.name; var reader = new FileReader(); reader.onload = function(e) { document.getElementById('csv_text_area').value = e.target.result; }; reader.readAsText(file); }
function submitImport() {
    logToRouter("Executing Users Import"); var csv = document.getElementById('csv_text_area').value; var radioBtn = document.querySelector('input[name="import_mode"]:checked'); var mode = radioBtn ? radioBtn.value : 'replace';
    var form = document.createElement('form'); form.method = 'POST'; form.action = lu_current_url.split('#')[0]; var inputs = { 'import_users': '1', 'csv_data': csv, 'import_mode': mode };
    for (var key in inputs) { var el = document.createElement(key === 'csv_data' ? 'textarea' : 'input'); if (key !== 'csv_data') el.type = 'hidden'; el.name = key; el.value = inputs[key]; form.appendChild(el); }
    var tokenVal = ''; var tokenNode = document.querySelector('input[name="token"]');
    if (tokenNode) { tokenVal = tokenNode.value; } else if (typeof L !== 'undefined' && L.env && L.env.token) { tokenVal = L.env.token; } else { var match = document.cookie.match(/(?:^|;)\s*sysauth_http=([^;]+)/) || document.cookie.match(/(?:^|;)\s*sysauth=([^;]+)/); if (match) tokenVal = match[1]; }
    if (tokenVal) { var t = document.createElement('input'); t.type = 'hidden'; t.name = 'token'; t.value = tokenVal; form.appendChild(t); }
    document.body.appendChild(form); form.submit(); 
}
function showImportModal() {
    var m = document.getElementById('import-modal');
    if (!m) {
        m = document.createElement('div'); m.id = 'import-modal'; m.className = 'qr-modal-overlay';
        m.innerHTML = '<div class="custom-modal-content" style="text-align:left;"><h3 style="margin-top:0; margin-bottom:10px;">Import Users (CSV)</h3><p style="font-size:12px; opacity:0.8; line-height:1.4; margin-top:0;">Format: <b>username,secret,max_tcp_conns,max_unique_ips,data_quota,expire_date</b></p><div style="margin-bottom:15px; display:flex; gap:10px; align-items:center;"><input type="file" id="csv_file_input" accept=".csv" style="display:none;"><input type="button" class="cbi-button cbi-button-action" id="btn_csv_choose" value="Choose File..."><span id="csv_file_name_display" style="font-size:12px; opacity:0.8;">No file selected</span></div><textarea id="csv_text_area" placeholder="user1,164f44a...,50,5,1.5,31.12.2026 23:59\nuser2,..."></textarea><div style="margin-bottom:20px; font-size:13px;"><label style="display:flex; align-items:center; gap:5px; margin-bottom:8px;"><input type="radio" name="import_mode" value="replace" checked> <span><b>Replace</b> (Delete existing users)</span></label><label style="display:flex; align-items:center; gap:5px;"><input type="radio" name="import_mode" value="merge"> <span><b>Merge</b> (Keep existing, overwrite duplicates)</span></label></div><div style="display:flex; gap:10px;"><input type="button" class="cbi-button cbi-button-apply" id="btn_csv_import" style="flex:1;" value="Import & Save"><input type="button" class="cbi-button cbi-button-reset" id="btn_csv_cancel" style="flex:1;" value="Cancel"></div></div>';
        document.body.appendChild(m); m.addEventListener('click', function(e) { if (e.target === m) closeModals(); });
        document.getElementById('btn_csv_choose').addEventListener('click', function() { document.getElementById('csv_file_input').click(); });
        document.getElementById('csv_file_input').addEventListener('change', function(e) { readCSVFile(e.target); });
        document.getElementById('btn_csv_import').addEventListener('click', submitImport); document.getElementById('btn_csv_cancel').addEventListener('click', closeModals);
    }
    document.getElementById('csv_file_input').value = ""; document.getElementById('csv_file_name_display').innerText = "No file selected"; document.getElementById('csv_text_area').value = "";
    m.classList.add('active');
}

function fixTabs() {
    // 1. Upstreams Tab setup
    var upSec = document.getElementById('cbi-telemt-upstream'); var upAnchor = document.getElementById('upstreams_tab_anchor');
    if (upSec && upAnchor) { var tA = upAnchor.closest('.cbi-tab') || upAnchor.parentNode; if(tA && upSec.parentNode !== tA) { upAnchor.style.display = 'none'; tA.appendChild(upSec); } }
    
    // 2. Users Tab Dashboard setup
    var usTable = document.getElementById('cbi-telemt-user'); var usAnchor = document.getElementById('users_tab_anchor');
    if (usTable && usAnchor) { 
        var tU = usAnchor.closest('.cbi-tab') || usAnchor.parentNode; 
        if(tU && usTable.parentNode !== tU) {
            usAnchor.style.display = 'none'; tU.appendChild(usTable);
            if (!document.getElementById('telemt_users_dashboard_panel')) {
                var dash = document.createElement('div'); dash.id = 'telemt_users_dashboard_panel';
                var topRow = document.createElement('div'); topRow.className = 'telemt-dash-top-row';
                var sumInner = document.createElement('div'); sumInner.id = 'telemt_users_summary_inner'; sumInner.className = 'telemt-dash-summary'; topRow.appendChild(sumInner);
                var btnsTop = document.createElement('div'); btnsTop.className = 'telemt-dash-btns';
                var btnExpStat = document.createElement('input'); btnExpStat.type = 'button'; btnExpStat.className = 'cbi-button cbi-button-apply'; btnExpStat.value = 'Export Stats'; btnExpStat.onclick = doExportStats; btnsTop.appendChild(btnExpStat);
                var btnRstStat = document.createElement('input'); btnRstStat.type = 'button'; btnRstStat.className = 'cbi-button cbi-button-remove telemt-btn-cross'; btnRstStat.value = 'Reset Stats'; btnRstStat.onclick = function(){ if(confirm('Clear RAM stats?')){ postAction('reset_stats'); } }; btnsTop.appendChild(btnRstStat);
                topRow.appendChild(btnsTop); dash.appendChild(topRow);

                var botRow = document.createElement('div'); botRow.className = 'telemt-dash-bot-row';
                var ipWrap = document.getElementById('telemt_mirror_ip_wrapper'); if(ipWrap) { ipWrap.style.display = 'block'; botRow.appendChild(ipWrap); }
                var btnsBot = document.createElement('div'); btnsBot.className = 'telemt-action-btns';
                var btnExpCsv = document.createElement('input'); btnExpCsv.type = 'button'; btnExpCsv.className = 'cbi-button cbi-button-action'; btnExpCsv.value = 'Export Users (CSV)'; btnExpCsv.onclick = doExportCSV; btnsBot.appendChild(btnExpCsv);
                var btnImpCsv = document.createElement('input'); btnImpCsv.type = 'button'; btnImpCsv.className = 'cbi-button cbi-button-apply'; btnImpCsv.value = 'Import Users (CSV)'; btnImpCsv.onclick = showImportModal; btnsBot.appendChild(btnImpCsv);
                botRow.appendChild(btnsBot); dash.appendChild(botRow);
                
                tU.insertBefore(dash, usTable);
            }
        }
    }
}

function processCollapsibles() {
    var advDet = document.getElementById('telemt_adv_opts_details'); var advCon = document.getElementById('telemt_adv_opts_content');
    if(advDet && advCon) { ['desync_all_full','mask_proxy_protocol','announce_ip','ad_tag','fake_cert_len','tls_full_cert_ttl_secs','ignore_time_skew'].forEach(function(name){ var el = document.querySelector('.cbi-value[data-name="'+name+'"]'); if(el) { el.style.paddingLeft='15px'; advCon.appendChild(el); } }); }
    
    var tmDet = document.getElementById('telemt_timeouts_details'); var tmCon = document.getElementById('telemt_timeouts_content');
    if(tmDet && tmCon) { ['tm_handshake','tm_connect','tm_keepalive','tm_ack','replay_window_secs'].forEach(function(name){ var el = document.querySelector('.cbi-value[data-name="'+name+'"]'); if(el) { el.style.paddingLeft='15px'; tmCon.appendChild(el); } }); }
}

function injectUI() {
    fixTabs();
    
    // Fix headers & Add User button
    var btnAdd = document.querySelector('#cbi-telemt-user .cbi-button-add'); if (btnAdd && btnAdd.value !== 'Add user') btnAdd.value = 'Add user';
    var newNameInp = document.querySelector('.cbi-section-create-name'); if(newNameInp && !newNameInp.dataset.maxInjected) { newNameInp.dataset.maxInjected = "1"; newNameInp.maxLength = 15; newNameInp.placeholder = "a-z, 0-9, _"; }
    
    if (!is_owrt25) {
        var th = document.querySelector('#cbi-telemt-user .cbi-section-table-titles th:first-child') || document.querySelector('#cbi-telemt-user thead th:first-child');
        if (th && !th.dataset.renamed) { var t = (th.textContent||'').trim().toLowerCase(); if(t==='name'||t==='название'||t==='') { th.textContent = 'User'; th.dataset.renamed="1"; } }
    }
    
    // User Table Injection
    document.querySelectorAll('#cbi-telemt-user .cbi-section-table-row:not(.cbi-row-template):not([data-injected="1"])').forEach(function(row) {
        var secInp = row.querySelector('input[name*=".secret"]'); if(!secInp) return; row.dataset.injected = "1";
        var match = secInp.name.match(/cbid\.telemt\.([^.]+)\.secret/); var uName = match ? match[1] : '?';

        if (is_owrt25) { var sTd = secInp.closest('td'); if (sTd) { var nDiv = document.createElement('div'); nDiv.className = 'telemt-user-col-text'; nDiv.style.marginBottom = '6px'; nDiv.innerText = '[ user: ' + uName + ' ]'; sTd.insertBefore(nDiv, sTd.firstChild); } } 
        else { var fC = row.firstElementChild; if (fC && !fC.contains(secInp)) { fC.innerHTML = "<span class='telemt-user-col-text'>" + uName + "</span>"; } }
        
        if(secInp.value.trim() === "") { secInp.value = genRandHex(); secInp.dispatchEvent(new Event('change', {bubbles: true})); }
        secInp.dataset.prevVal = secInp.value;
        var w = document.createElement('div'); w.className = 'telemt-sec-wrap'; secInp.parentNode.insertBefore(w, secInp); w.appendChild(secInp);
        var grp = document.createElement('div'); grp.className = 'telemt-sec-btns';
        var bG = document.createElement('input'); bG.type = 'button'; bG.className = 'cbi-button cbi-button-apply'; bG.value = 'Gen'; bG.onclick = function(){ secInp.value = genRandHex(); updateLinks(); };
        var bR = document.createElement('input'); bR.type = 'button'; bR.className = 'cbi-button cbi-button-reset'; bR.value = 'Rev'; bR.onclick = function(){ secInp.value = secInp.dataset.prevVal; updateLinks(); };
        grp.appendChild(bG); grp.appendChild(bR); w.appendChild(grp);
        
        var niList = row.querySelectorAll('input[name*="max_tcp_conns"], input[name*="max_unique_ips"], input[name*="data_quota"], input[name*="expire_date"]');
        niList.forEach(function(ni){
            var wrapper = document.createElement('div'); wrapper.className = 'telemt-num-wrap'; ni.parentNode.insertBefore(wrapper, ni); wrapper.appendChild(ni);
            if(ni.name.indexOf('expire_date') !== -1) {
                var calContainer = document.createElement('div'); calContainer.className = 'telemt-cal-wrap';
                var calBtn = document.createElement('input'); calBtn.type = 'button'; calBtn.className = 'cbi-button cbi-button-action telemt-btn-cal'; calBtn.value = ' ';
                var picker = document.createElement('input'); picker.type = 'datetime-local'; picker.className = 'telemt-cal-picker';
                picker.addEventListener('change', function(e) { var val = e.target.value; if(val) { var p = val.split('T'); var dP = p[0].split('-'); if(dP.length === 3) { ni.value = dP[2] + '.' + dP[1] + '.' + dP[0] + ' ' + p[1]; ni.dispatchEvent(new Event('change', {bubbles:true})); } } });
                calContainer.appendChild(calBtn); calContainer.appendChild(picker); wrapper.appendChild(calContainer);
            }
            var bD = document.createElement('input'); bD.type = 'button'; bD.className = 'cbi-button cbi-button-reset telemt-btn-cross'; bD.value = ' '; bD.onclick = function(){ ni.value = ''; ni.dispatchEvent(new Event('change', {bubbles:true})); }; wrapper.appendChild(bD);
        });
        
        var linkWrap = row.querySelector('.link-wrapper');
        if(linkWrap) { 
            var bGrp = document.createElement('div'); bGrp.className = 'link-btn-group'; 
            var bC = document.createElement('input'); bC.type = 'button'; bC.className = 'cbi-button cbi-button-action'; bC.value = 'Copy'; bC.onclick = function(){ var inp = linkWrap.querySelector('.user-link-out'); if(inp){ navigator.clipboard.writeText(inp.value); bC.value='✔'; setTimeout(()=>bC.value='Copy',1500); } }; bGrp.appendChild(bC); 
            var bQ = document.createElement('input'); bQ.type = 'button'; bQ.className = 'cbi-button cbi-button-neural'; bQ.value = 'QR'; bQ.onclick = function(){ showQRModal(linkWrap.querySelector('.user-link-out').value); }; bGrp.appendChild(bQ);
            linkWrap.appendChild(bGrp); 
        }
    });
}

function loadLog() {
    var btn = document.getElementById('btn_load_log'); if(!btn) return; btn.value = 'Loading...';
    fetch(lu_current_url.split('#')[0] + (lu_current_url.indexOf('?') > -1 ? '&' : '?') + 'get_log=1&_t=' + Date.now()).then(r => r.text()).then(txt => { document.getElementById('telemt_log_container').innerHTML = txt || 'No logs found.'; btn.value = 'Refresh Log'; });
}

setInterval(fetchMetrics, 2500);
document.addEventListener('input', function(e) {
    if (e.target && e.target.matches('input, select')) {
        if(e.target.id === 'telemt_mirror_ip') { var master = document.querySelector('input[name*="cbid.telemt.general.external_ip"]'); if(master) { master.value = e.target.value; master.dispatchEvent(new Event('change')); } } 
        else if (e.target.name && e.target.name.indexOf('cbid.telemt.general.external_ip') > -1) { var mirror = document.getElementById('telemt_mirror_ip'); if(mirror) mirror.value = e.target.value; }
        updateLinks();
    }
});

// Run collapsibles exactly once after short delay, then rely on mutation observer for UI injection
document.addEventListener('DOMContentLoaded', function(){ 
    setTimeout(processCollapsibles, 300);
    injectUI(); updateLinks(); 
    setInterval(function(){ injectUI(); updateLinks(); }, 1500); 
});
</script>
]]

return m
