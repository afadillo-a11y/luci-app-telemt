<div align="center">
  <h1>🏗️ Project Architecture & Workflow</h1>
  <p><b>luci-app-telemt v3.3.26</b> | <i>The Micro-Service Era: Web UI, Init System, Bot, and Core Engine</i></p>
</div>

<hr>

<h2>📂 1. Directory & File Structure</h2>
<p>The repository mirrors the OpenWrt root filesystem. When the package is installed, files are placed exactly as structured below:</p>

<pre style="background-color: rgba(27,31,35,0.05); padding: 16px; border-radius: 6px; font-family: monospace; line-height: 1.4;">
📦 luci-app-telemt
 ┣ 📂 root/
 ┃ ┣ 📂 etc/
 ┃ ┃ ┣ 📂 config/
 ┃ ┃ ┃ ┗ 📜 <b>telemt</b>                   <span style="color: #6a737d;">// Default UCI configuration (The Single Source of Truth)</span>
 ┃ ┃ ┣ 📂 init.d/
 ┃ ┃ ┃ ┣ 📜 <b>telemt</b>                   <span style="color: #6a737d;">// ⚙️ Core Engine: Procd script & Atomic TOML Generator</span>
 ┃ ┃ ┃ ┗ 📜 <b>telemt_bot</b>               <span style="color: #6a737d;">// 🤖 Sidecar Engine: Procd script for Telegram Bot</span>
 ┃ ┃ ┗ 📂 uci-defaults/
 ┃ ┃   ┗ 📜 <b>luci-telemt</b>              <span style="color: #6a737d;">// Post-install script (Registers UI menu, sets perms)</span>
 ┃ ┗ 📂 usr/
 ┃   ┣ 📂 lib/lua/luci/model/cbi/
 ┃   ┃ ┗ 📜 <b>telemt.lua</b>               <span style="color: #6a737d;">// 🧠 The Brains: Web UI Controller & AJAX Handler</span>
 ┃   ┗ 📂 bin/
 ┃     ┗ 📜 <b>telemt_bot.sh</b>            <span style="color: #6a737d;">// Telegram Bot execution script (ash/curl)</span>
 ┣ 📜 Makefile                       <span style="color: #6a737d;">// OpenWrt build recipe for .ipk (legacy/stable)</span>
 ┗ 📜 nfpm.yaml                      <span style="color: #6a737d;">// Multi-packager config (generates .ipk and .apk via GitHub Actions)</span>
</pre>

<hr>

<h2>📦 2. Installation Lifecycle (.ipk / .apk)</h2>
<p>Because of the <b>Micro-Service Architecture</b>, the core binary (<code>telemt_wrt</code>) is installed separately from the Web UI (<code>luci-app-telemt</code>). When the UI package is installed via <code>opkg</code> or <code>apk</code>, the following sequence occurs:</p>

<blockquote>
  <b>1. Extraction ➔ 2. Core Dependency Check ➔ 3. Post-Install Hooks ➔ 4. Service Registration</b>
</blockquote>

<ul>
  <li>📥 <b>Extraction:</b> The package manager unpacks the <code>root/</code> directory into the router's root filesystem (<code>/</code>).</li>
  <li>🔍 <b>Soft Dependency Check:</b> The installer checks if <code>/usr/bin/telemt</code> exists. If missing, it warns the user but proceeds, allowing headless/UI separation.</li>
  <li>🔌 <b>Menu Registration:</b> The script in <code>/etc/uci-defaults/</code> tells LuCI to add the "Telemt Proxy" tab to the <i>Services</i> menu.</li>
  <li>🚀 <b>Init Setup:</b> The <code>telemt</code> and <code>telemt_bot</code> init scripts are enabled via <code>rc_procd</code> to run on router boot.</li>
</ul>

<hr>

<h2>🧩 3. Module Responsibilities</h2>

<details open>
  <summary><b><span style="font-size: 1.2em;">🖥️ The Web UI Controller (<code>telemt.lua</code>)</span></b></summary>
  <div style="padding-left: 20px; margin-top: 10px;">
    <ul>
      <li><b>Configuration Binding:</b> Connects HTML form elements directly to the <code>/etc/config/telemt</code> UCI file. Validates strict datatypes (e.g., max_tcp_conns 1-100000).</li>
      <li><b>Zero-Downtime Hot-Reload:</b> When adding users or modifying quotas, the UI bypasses full service restarts, interacting smoothly with the backend to preserve active connections.</li>
      <li><b>Advanced Diagnostics:</b> Parses real-time data to display dual routing badges (<b>TG PATH</b> & <b>EGRESS</b>), unique IP tracking (e.g., <code>14 IP 7/10</code>), and dumps full proxy health to the <i>Runtime Info</i> console.</li>
      <li><b>DOM Mutation (OpenWrt 25+):</b> Detects the strict LuCI2 VDOM. If native columns are dropped by the framework, it dynamically injects <code>[ user: name ]</code> into the Secret cell to prevent layout crashes.</li>
    </ul>
  </div>
</details>

<details open>
  <summary><b><span style="font-size: 1.2em;">⚙️ The Init Script & Lifecycle Manager (<code>init.d/telemt</code>)</span></b></summary>
  <div style="padding-left: 20px; margin-top: 10px;">
    <ul>
      <li><b>Atomic TOML Generation:</b> Reads UCI and writes the config to a temporary file (<code>mktemp</code>), then uses <code>mv -f</code> to overwrite <code>/tmp/telemt.toml</code>. This completely eliminates <i>"File not found"</i> crashes during hot-reloads.</li>
      <li><b>Graceful Shutdowns:</b> Standardized process termination via <code>SIGTERM</code> ➔ 4s wait ➔ <code>SIGKILL</code> fallback.</li>
      <li><b>Bulletproof Stats Preservation:</b> Automatically intercepts termination signals and triggers <code>run_save_stats()</code> to dump RAM metrics to disk <i>before</i> the process dies, guaranteeing zero quota loss.</li>
      <li><b>Smart Fallbacks & NAT:</b> If STUN is disabled, it natively overrides the prober by injecting the Announce IP directly. Sets up RAM-based dynamic firewall rules via Procd.</li>
      <li><b>Bot-Safe PID Detection:</b> Evaluates <code>/proc/pid/cmdline</code> to guarantee it only kills the proxy, never the Telegram bot sidecar.</li>
    </ul>
  </div>
</details>

<details open>
  <summary><b><span style="font-size: 1.2em;">🤖 The Telegram Bot Sidecar (<code>telemt_bot</code>)</span></b></summary>
  <div style="padding-left: 20px; margin-top: 10px;">
    <ul>
      <li><b>Autonomous Daemon:</b> Runs as a completely independent <code>procd</code> service, unaffected by main proxy restarts.</li>
      <li><b>Dual Engine Polling:</b> Interacts with both the REST API v1 (port 9091) and Prometheus metrics (port 9092) to fetch statistics.</li>
      <li><b>Remote Control:</b> Allows admins to create users, assign quotas, view router CPU/RAM load, and monitor DPI scanner activity directly from a smartphone.</li>
    </ul>
  </div>
</details>

<hr>

<h2>🔄 4. Operational Workflow (The Magic)</h2>
<p>The system now has two distinct workflows depending on the type of configuration change.</p>

<h3>A. Full Lifecycle (Core Config Changes)</h3>
<p>Used when modifying ports, STUN settings, ME Proxy parameters, or Upstreams.</p>
<table style="width:100%; text-align:left; border-collapse: collapse;">
  <tr style="background-color: rgba(0, 160, 0, 0.1);">
    <th style="padding: 10px; border: 1px solid #ddd;">Stage</th>
    <th style="padding: 10px; border: 1px solid #ddd;">Action</th>
  </tr>
  <tr>
    <td style="padding: 10px; border: 1px solid #ddd;"><b>1. Save & Terminate</b></td>
    <td style="padding: 10px; border: 1px solid #ddd;">LuCI writes to UCI. OpenWrt calls <code>reload</code>. Init script sends <code>SIGTERM</code>. The binary saves user quotas to disk and exits cleanly.</td>
  </tr>
  <tr>
    <td style="padding: 10px; border: 1px solid #ddd;"><b>2. Atomic Build</b></td>
    <td style="padding: 10px; border: 1px solid #ddd;">Init reads UCI, generates a fresh TOML file in <code>/tmp</code>, and atomically swaps it into <code>/tmp/telemt.toml</code>.</td>
  </tr>
  <tr>
    <td style="padding: 10px; border: 1px solid #ddd;"><b>3. Procd Spawn</b></td>
    <td style="padding: 10px; border: 1px solid #ddd;">Procd spawns the Rust binary with the new TOML. Firewall rules are injected into RAM.</td>
  </tr>
</table>

<br>

<h3>B. Hot-Reload Workflow (Users & Quotas)</h3>
<p>Used when adding/removing users or changing their limits (Zero-Downtime).</p>
<table style="width:100%; text-align:left; border-collapse: collapse;">
  <tr style="background-color: rgba(0, 100, 255, 0.1);">
    <th style="padding: 10px; border: 1px solid #ddd;">Stage</th>
    <th style="padding: 10px; border: 1px solid #ddd;">Action</th>
  </tr>
  <tr>
    <td style="padding: 10px; border: 1px solid #ddd;"><b>1. UI Trigger</b></td>
    <td style="padding: 10px; border: 1px solid #ddd;">User edits a quota or adds a user in the Web UI. Changes are saved to UCI.</td>
  </tr>
  <tr>
    <td style="padding: 10px; border: 1px solid #ddd;"><b>2. Atomic Update</b></td>
    <td style="padding: 10px; border: 1px solid #ddd;">Init script updates the <code>/tmp/telemt.toml</code> file atomically in the background.</td>
  </tr>
  <tr>
    <td style="padding: 10px; border: 1px solid #ddd;"><b>3. Control API</b></td>
    <td style="padding: 10px; border: 1px solid #ddd;">The system signals the Telemt binary via the <b>Control Plane API (Port 9091)</b> to re-read the configuration file.</td>
  </tr>
  <tr>
    <td style="padding: 10px; border: 1px solid #ddd;"><b>4. Seamless Apply</b></td>
    <td style="padding: 10px; border: 1px solid #ddd;">The core binary applies new limits and user keys instantly. <b>Existing traffic flows are never dropped.</b></td>
  </tr>
</table>

<br>
<p align="center">
  Built by vibing bears with tears and honey for OpenWrt ecosystem (21.02 — 25.x) 🐻🍯
</p>
