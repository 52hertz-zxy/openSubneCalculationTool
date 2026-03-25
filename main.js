const { app, BrowserWindow, Menu, ipcMain, dialog, screen } = require("electron");
const path = require("path");
const fs = require("fs");
const { spawn, spawnSync } = require("child_process");
const net = require("net");
const os = require("os");

function isValidIPv4(ip) {
  if (typeof ip !== "string") return false;
  const parts = ip.trim().split(".");
  if (parts.length !== 4) return false;
  for (const p of parts) {
    if (!/^\d{1,3}$/.test(p)) return false;
    const n = Number(p);
    if (!Number.isInteger(n) || n < 0 || n > 255) return false;
  }
  return true;
}

function parsePingRttMs(raw) {
  const s = String(raw || "");
  // Windows 简中：时间=12ms / 时间<1ms；英文：time=12ms / time<1ms
  let m = s.match(/时间\s*[=<＝]\s*(\d+)\s*ms/i);
  if (m) return Number(m[1]);
  if (/时间\s*<\s*1\s*ms/i.test(s)) return 1;
  m = s.match(/time\s*[=<]\s*(\d+)\s*ms/i);
  if (m) return Number(m[1]);
  if (/time\s*<\s*1\s*ms/i.test(s)) return 1;
  // Linux/mac：time=0.123 ms
  m = s.match(/time=([\d.]+)\s*ms/i);
  if (m) return Math.round(Number(m[1]));
  return null;
}

function pingOnceIPv4(ip, timeoutMs) {
  return new Promise((resolve) => {
    const startedAt = Date.now();
    const safeTimeout = Math.max(200, Math.min(10000, Number(timeoutMs) || 1200));
    const platform = process.platform;
    const args =
      platform === "win32"
        ? ["-n", "1", "-w", String(safeTimeout), ip]
        : ["-c", "1", "-W", String(Math.max(1, Math.ceil(safeTimeout / 1000))), ip];
    let settled = false;
    const chunks = [];
    const proc = spawn("ping", args, { windowsHide: true });
    const onData = (d) => {
      chunks.push(Buffer.isBuffer(d) ? d : Buffer.from(String(d)));
    };
    if (proc.stdout) proc.stdout.on("data", onData);
    if (proc.stderr) proc.stderr.on("data", onData);
    const done = (ok, code) => {
      if (settled) return;
      settled = true;
      const wallMs = Date.now() - startedAt;
      const merged = Buffer.concat(chunks);
      let text = merged.toString("utf8");
      if (!/ms/i.test(text) && merged.length) {
        try {
          text = merged.toString("latin1");
        } catch {
          // ignore
        }
      }
      const rttMs = ok ? parsePingRttMs(text) : null;
      resolve({
        ip,
        ok,
        exitCode: typeof code === "number" ? code : null,
        elapsedMs: wallMs,
        rttMs: rttMs != null && Number.isFinite(rttMs) ? rttMs : ok ? wallMs : null,
      });
    };
    proc.on("error", () => done(false, null));
    proc.on("close", (code) => done(code === 0, code));
  });
}

async function runBatchPing(ips, timeoutMs, concurrency) {
  const results = new Array(ips.length);
  const workers = [];
  const safeConcurrency = Math.max(1, Math.min(128, Number(concurrency) || 32));
  let idx = 0;
  const worker = async () => {
    while (true) {
      const cur = idx;
      idx += 1;
      if (cur >= ips.length) return;
      results[cur] = await pingOnceIPv4(ips[cur], timeoutMs);
    }
  };
  for (let i = 0; i < safeConcurrency; i += 1) workers.push(worker());
  await Promise.all(workers);
  return results;
}

const MAX_TCP_PROBE_TASKS = 25000;

function isValidTcpPort(n) {
  const p = Number(n);
  return Number.isInteger(p) && p >= 1 && p <= 65535;
}

/**
 * 轻量 TCP 连接探测：成功建立即视为开放，随后立即关闭（不发送应用层数据）。
 */
function tcpProbeOnce(ip, port, timeoutMs) {
  return new Promise((resolve) => {
    const startedAt = Date.now();
    const t = Math.max(100, Math.min(30000, Number(timeoutMs) || 2000));
    const socket = new net.Socket();
    let settled = false;
    const finish = (open, errKind) => {
      if (settled) return;
      settled = true;
      try {
        socket.destroy();
      } catch {
        // ignore
      }
      resolve({
        ip,
        port,
        open: Boolean(open),
        elapsedMs: Date.now() - startedAt,
        error: open ? null : String(errKind || "unreachable"),
      });
    };
    socket.setTimeout(t);
    socket.once("connect", () => finish(true, null));
    socket.once("timeout", () => finish(false, "timeout"));
    socket.once("error", (e) => finish(false, e && e.code ? e.code : "error"));
    try {
      socket.connect(port, ip);
    } catch (e) {
      finish(false, e && e.code ? e.code : "error");
    }
  });
}

async function runBatchTcpProbe(probes, timeoutMs, concurrency, staggerMs) {
  const results = new Array(probes.length);
  const safeConc = Math.max(1, Math.min(32, Number(concurrency) || 8));
  const stagger = Math.max(0, Math.min(500, Number(staggerMs) || 0));
  let idx = 0;
  const worker = async () => {
    while (true) {
      const cur = idx;
      idx += 1;
      if (cur >= probes.length) return;
      if (stagger > 0) {
        await new Promise((r) => setTimeout(r, stagger));
      }
      const p = probes[cur];
      results[cur] = await tcpProbeOnce(p.ip, p.port, timeoutMs);
    }
  };
  const workers = [];
  for (let i = 0; i < safeConc; i += 1) workers.push(worker());
  await Promise.all(workers);
  return results;
}

function buildChineseMenu() {
  const template = [
    {
      label: "文件",
      submenu: [
        { role: "reload", label: "重新加载" },
        { role: "toggleDevTools", label: "开发者工具" },
        { type: "separator" },
        { role: "quit", label: "退出" },
      ],
    },
    {
      label: "编辑",
      submenu: [
        { role: "undo", label: "撤销" },
        { role: "redo", label: "重做" },
        { type: "separator" },
        { role: "cut", label: "剪切" },
        { role: "copy", label: "复制" },
        { role: "paste", label: "粘贴" },
        { role: "selectAll", label: "全选" },
      ],
    },
    {
      label: "视图",
      submenu: [
        { role: "resetZoom", label: "实际大小" },
        { role: "zoomIn", label: "放大" },
        { role: "zoomOut", label: "缩小" },
        { type: "separator" },
        { role: "togglefullscreen", label: "全屏" },
      ],
    },
    {
      label: "窗口",
      submenu: [
        { role: "minimize", label: "最小化" },
        { role: "close", label: "关闭窗口" },
      ],
    },
    {
      label: "帮助",
      submenu: [
        {
          label: "关于子网计算工具",
          click: () => {
            const focused = BrowserWindow.getFocusedWindow();
            if (focused) {
              focused.webContents.executeJavaScript(`
                alert("子网计算工具（IPv4/IPv6）\\n绿色版：解压即用\\n离线运行，不上传数据。");
              `);
            }
          },
        },
      ],
    },
  ];
  return Menu.buildFromTemplate(template);
}

function collectNodeNetworkInterfaces() {
  const list = [];
  const raw = os.networkInterfaces();
  for (const [name, infos] of Object.entries(raw)) {
    if (!infos || !infos.length) continue;
    const entry = {
      name,
      mac: "",
      internal: infos.every((x) => x.internal),
      addresses: [],
    };
    for (const a of infos) {
      if (!a.internal) entry.internal = false;
      const fam = a.family;
      const isV4 = fam === "IPv4" || fam === 4;
      if (a.mac && a.mac !== "00:00:00:00:00:00") entry.mac = a.mac;
      entry.addresses.push({
        family: isV4 ? "IPv4" : "IPv6",
        address: a.address,
        netmask: a.netmask || "",
        cidr: a.cidr || "",
      });
    }
    list.push(entry);
  }
  return list;
}

function getWindowsAdapterDetails() {
  if (process.platform !== "win32") return { ok: true, adapters: [], note: null };
  // 使用 UTF-8（带 BOM）临时 .ps1 + -File，避免 -EncodedCommand 与 execSync 在中文系统下编码错乱、错误流混入乱码
  const psLines = [
    "$ErrorActionPreference = 'SilentlyContinue'",
    "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8",
    "$OutputEncoding = [System.Text.Encoding]::UTF8",
    "$rows = @()",
    "Get-NetIPConfiguration -ErrorAction SilentlyContinue | ForEach-Object {",
    "  $c = $_",
    "  $i = $c.InterfaceIndex",
    "  $dns4 = @(",
    "    Get-DnsClientServerAddress -InterfaceIndex $i -AddressFamily IPv4 -ErrorAction SilentlyContinue | ForEach-Object { $_.ServerAddresses }",
    "  ) -join ';'",
    "  $dns6 = @(",
    "    Get-DnsClientServerAddress -InterfaceIndex $i -AddressFamily IPv6 -ErrorAction SilentlyContinue | ForEach-Object { $_.ServerAddresses }",
    "  ) -join ';'",
    "  $g4 = @($c.IPv4DefaultGateway | ForEach-Object { $_.NextHop }) -join ','",
    "  $g6 = @($c.IPv6DefaultGateway | ForEach-Object { $_.NextHop }) -join ','",
    "  $a4 = @($c.IPv4Address | ForEach-Object { $_.IPAddress }) -join ','",
    "  $a6 = @($c.IPv6Address | ForEach-Object { $_.IPAddress }) -join ','",
    "  $rows += [PSCustomObject]@{ Name = $c.InterfaceAlias; IPv4 = $a4; IPv6 = $a6; Gateway4 = $g4; Gateway6 = $g6; DNS4 = $dns4; DNS6 = $dns6 }",
    "}",
    "if ($rows.Count -eq 0) { Write-Output '[]' } else { $rows | ConvertTo-Json -Depth 6 -Compress }",
  ];
  const psBody = psLines.join("\r\n");
  const tmp = path.join(os.tmpdir(), `subnet-netinfo-${process.pid}-${Date.now()}.ps1`);
  try {
    fs.writeFileSync(tmp, `\uFEFF${psBody}`, { encoding: "utf8" });
    const spawned = spawnSync(
      process.env.SystemRoot
        ? path.join(process.env.SystemRoot, "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
        : "powershell.exe",
      ["-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", tmp],
      {
        encoding: "utf8",
        windowsHide: true,
        maxBuffer: 10 * 1024 * 1024,
        timeout: 25000,
      },
    );
    try {
      fs.unlinkSync(tmp);
    } catch {
      // ignore
    }
    if (spawned.error) {
      return { ok: false, adapters: [], note: spawned.error.message || "无法启动 PowerShell" };
    }
    const stderr = String(spawned.stderr || "").trim();
    let stdout = String(spawned.stdout || "").trim().replace(/^\uFEFF/, "");
    if (spawned.status !== 0) {
      const hint = stderr.slice(0, 280) || stdout.slice(0, 280) || `PowerShell 退出码 ${spawned.status}`;
      return { ok: false, adapters: [], note: hint };
    }
    if (!stdout) return { ok: true, adapters: [], note: stderr || null };
    try {
      const parsed = JSON.parse(stdout);
      const adapters = Array.isArray(parsed) ? parsed : [parsed];
      return { ok: true, adapters, note: stderr || null };
    } catch {
      return {
        ok: false,
        adapters: [],
        note: "无法解析网关/DNS 数据（请确认已安装 NetTCPIP 模块，或以管理员身份重试）。",
      };
    }
  } catch (e) {
    try {
      fs.unlinkSync(tmp);
    } catch {
      // ignore
    }
    return { ok: false, adapters: [], note: e instanceof Error ? e.message : String(e) };
  }
}

/** 主窗口引用 */
let mainWindow = null;

/** 右下角任务通知小窗 */
let notifyWindow = null;
let pendingNotifyTabId = "";

/** 路由追踪子进程（支持中止 / 暂停） */
let traceRouteChild = null;
let traceRouteAborted = false;
let traceRoutePaused = false;

function stopMainFlash() {
  if (mainWindow && !mainWindow.isDestroyed()) {
    try {
      mainWindow.flashFrame(false);
    } catch {
      // ignore
    }
  }
}

function positionTaskNotifyWindow() {
  if (!notifyWindow || notifyWindow.isDestroyed()) return;
  try {
    const p = screen.getCursorScreenPoint();
    const wa = screen.getDisplayNearestPoint(p).workArea;
    const w = 380;
    const h = 140;
    const x = wa.x + wa.width - w - 14;
    const y = wa.y + wa.height - h - 14;
    notifyWindow.setBounds({ x, y, width: w, height: h });
  } catch {
    // ignore
  }
}

function showTaskNotifyInternal(payload) {
  return new Promise((resolve) => {
    const push = () => {
      if (!notifyWindow || notifyWindow.isDestroyed()) {
        resolve();
        return;
      }
      notifyWindow.webContents.send("notify-payload", payload);
      positionTaskNotifyWindow();
      notifyWindow.show();
      resolve();
    };
    if (!notifyWindow || notifyWindow.isDestroyed()) {
      notifyWindow = new BrowserWindow({
        width: 380,
        height: 140,
        frame: false,
        show: false,
        alwaysOnTop: true,
        skipTaskbar: true,
        resizable: false,
        minimizable: false,
        maximizable: false,
        fullscreenable: false,
        backgroundColor: "#0f1729",
        webPreferences: {
          preload: path.join(__dirname, "task-notify-preload.js"),
          contextIsolation: true,
          nodeIntegration: false,
        },
      });
      notifyWindow.on("closed", () => {
        notifyWindow = null;
      });
      notifyWindow.loadFile(path.join(__dirname, "task-notify.html"));
      notifyWindow.webContents.once("did-finish-load", push);
    } else {
      push();
    }
  });
}

function decodeTraceBuffer(buf) {
  if (!buf || !buf.length) return "";
  if (process.platform !== "win32") {
    const utf8 = buf.toString("utf8");
    return utf8 || buf.toString("latin1");
  }
  // Windows 控制台 tracert 多为系统代码页（简中常见 GBK/cp936），优先按 cp936 解码避免乱码
  try {
    return require("iconv-lite").decode(buf, "cp936");
  } catch {
    const utf8 = buf.toString("utf8");
    return utf8 || buf.toString("latin1");
  }
}

function isLikelyIPv6Target(s) {
  const t = String(s || "").trim();
  return t.includes(":") && !/^\d{1,3}(\.\d{1,3}){3}$/.test(t);
}

function isValidTraceTarget(raw) {
  const s = String(raw || "").trim();
  if (!s || s.length > 253) return false;
  if (/[\r\n\x00;"'`]/.test(s)) return false;
  return true;
}

function parseOneWindowsProbe(token) {
  const t = String(token || "").trim();
  if (!t || t === "*") return null;
  if (/请求超时|timed out|Time-out|General failure/i.test(t)) return null;
  const mLt = t.match(/^<\s*(\d+)\s*ms/i);
  if (mLt) return Number(mLt[1]);
  if (/^<\s*1\s*ms/i.test(t) || /时间\s*<\s*1\s*ms/i.test(t)) return 1;
  const mZh = t.match(/时间\s*[=<＝]\s*(\d+)\s*ms/i);
  if (mZh) return Number(mZh[1]);
  const mEn = t.match(/(\d+(?:\.\d+)?)\s*ms/i);
  if (mEn) return Math.round(Number(mEn[1]));
  return null;
}

function extractHopIp(hostPart) {
  const s = String(hostPart || "").trim();
  const paren = s.match(/\(([^)]+)\)\s*$/);
  if (paren) return paren[1].trim();
  if (/^[\d.]+$/.test(s)) return s;
  if (/^[0-9a-fA-F:]+(%[^]\s]+)?$/.test(s)) return s.split(/\s+/)[0];
  const ip4 = s.match(/\b(\d{1,3}(?:\.\d{1,3}){3})\b/);
  if (ip4) return ip4[1];
  return "";
}

function parseWindowsTracert(stdout) {
  const text = String(stdout || "").replace(/^\uFEFF/, "");
  const lines = text.split(/\r?\n/);
  const hops = [];
  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i];
    const hm = line.match(/^\s*(\d+)\s+(.+?)\s*$/);
    if (!hm) continue;
    let rest = hm[2].trim();
    let j = i + 1;
    while (j < lines.length && /^\s{4,}\S/.test(lines[j]) && !/^\s*\d+\s+/.test(lines[j])) {
      rest += ` ${lines[j].trim()}`;
      j += 1;
    }
    if (j > i + 1) i = j - 1;
    const segments = rest.split(/\s{2,}/).map((s) => s.trim()).filter(Boolean);
    if (segments.length < 2) continue;
    const hostPart = segments[segments.length - 1];
    let probeSegs = segments.slice(0, -1);
    while (probeSegs.length < 3) probeSegs.unshift("*");
    const three = probeSegs.slice(-3);
    const rtts = three.map(parseOneWindowsProbe);
    const timeouts = rtts.filter((x) => x == null).length;
    const lossPct = (timeouts / 3) * 100;
    const nums = rtts.filter((x) => x != null);
    const avgMs = nums.length ? Math.round(nums.reduce((a, b) => a + b, 0) / nums.length) : null;
    hops.push({
      hop: Number(hm[1]),
      host: hostPart.replace(/\s+/g, " ").trim(),
      ip: extractHopIp(hostPart),
      avgMs,
      lossPct: Math.round(lossPct * 10) / 10,
      probes: rtts,
    });
  }
  return hops;
}

function extractUnixLastProbes(rest) {
  const count = 3;
  const probes = [];
  let s = String(rest).trimEnd();
  for (let i = 0; i < count; i += 1) {
    if (/\*\s*$/.test(s)) {
      s = s.replace(/\*\s*$/, "").trimEnd();
      probes.push(null);
    } else {
      const mm = s.match(/(\d+(?:\.\d+)?)\s*ms\s*$/i);
      if (mm) {
        s = s.slice(0, mm.index).trimEnd();
        probes.push(Math.round(Number(mm[1])));
      } else {
        break;
      }
    }
  }
  while (probes.length < count) probes.push(null);
  probes.reverse();
  return { restHost: s.trim(), probes };
}

function parseUnixTraceroute(stdout) {
  const hops = [];
  for (const line of String(stdout).split(/\r?\n/)) {
    const m = line.match(/^\s*(\d+)\s+(.+)$/);
    if (!m) continue;
    const hop = Number(m[1]);
    const { restHost, probes } = extractUnixLastProbes(m[2]);
    const three = probes;
    const timeouts = three.filter((x) => x == null).length;
    const lossPct = (timeouts / 3) * 100;
    const nums = three.filter((x) => x != null);
    const avgMs = nums.length ? Math.round(nums.reduce((a, b) => a + b, 0) / nums.length) : null;
    hops.push({
      hop,
      host: restHost.replace(/\s+/g, " ").trim(),
      ip: extractHopIp(restHost),
      avgMs,
      lossPct: Math.round(lossPct * 10) / 10,
      probes: three,
    });
  }
  return hops;
}

function runTraceRoute(target, maxHops, waitMs) {
  return new Promise((resolve, reject) => {
    if (!isValidTraceTarget(target)) {
      reject(new Error("目标不合法或过长，请输入域名或 IP。"));
      return;
    }
    if (traceRouteChild) {
      try {
        traceRouteChild.kill();
      } catch {
        // ignore
      }
      traceRouteChild = null;
    }
    traceRouteAborted = false;
    traceRoutePaused = false;
    const mh = Math.max(1, Math.min(128, Number(maxHops) || 30));
    const w = Math.max(100, Math.min(8000, Number(waitMs) || 4000));
    let cmd;
    let args;
    if (process.platform === "win32") {
      cmd = "tracert";
      const ipv6 = isLikelyIPv6Target(target);
      args = ipv6
        ? ["-6", "-d", "-h", String(mh), "-w", String(w), target]
        : ["-d", "-h", String(mh), "-w", String(w), target];
    } else {
      cmd = "traceroute";
      const sec = Math.max(1, Math.ceil(w / 1000));
      args = ["-n", "-m", String(mh), "-w", String(sec), target];
      if (isLikelyIPv6Target(target)) {
        args = ["-n", "-6", "-m", String(mh), "-w", String(sec), target];
      }
    }
    const chunks = [];
    const errChunks = [];
    const child = spawn(cmd, args, { windowsHide: true });
    traceRouteChild = child;
    const onOut = (d) => chunks.push(Buffer.isBuffer(d) ? d : Buffer.from(String(d)));
    if (child.stdout) child.stdout.on("data", onOut);
    if (child.stderr) child.stderr.on("data", (d) => errChunks.push(Buffer.isBuffer(d) ? d : Buffer.from(String(d))));
    const deadline = setTimeout(() => {
      traceRouteAborted = true;
      try {
        child.kill("SIGTERM");
      } catch {
        // ignore
      }
    }, 180000);
    child.on("error", (e) => {
      clearTimeout(deadline);
      traceRouteChild = null;
      traceRoutePaused = false;
      reject(e);
    });
    child.on("close", (code) => {
      clearTimeout(deadline);
      traceRouteChild = null;
      traceRoutePaused = false;
      const merged = Buffer.concat(chunks);
      const text = decodeTraceBuffer(merged);
      const errMerged = Buffer.concat(errChunks);
      const errText =
        process.platform === "win32"
          ? decodeTraceBuffer(errMerged).trim()
          : errMerged.toString("utf8").trim();
      const hops =
        process.platform === "win32" ? parseWindowsTracert(text) : parseUnixTraceroute(text);
      resolve({
        target,
        platform: process.platform,
        exitCode: code,
        raw: text,
        stderr: String(errText || "").trim(),
        hops,
        aborted: traceRouteAborted,
        parseNote:
          hops.length === 0 && text.trim()
            ? "未能解析路由行，已返回原始输出供参考。"
            : null,
      });
      traceRouteAborted = false;
    });
  });
}

function getLocalNetworkInfoPayload() {
  const nodeInterfaces = collectNodeNetworkInterfaces();
  const win = getWindowsAdapterDetails();
  return {
    platform: process.platform,
    nodeInterfaces,
    windowsAdapters: win.adapters,
    windowsDetailOk: win.ok,
    windowsDetailNote: win.note,
  };
}

function createWindow() {
  const iconPath = path.join(__dirname, "build", "icon.ico");
  const win = new BrowserWindow({
    width: 1200,
    height: 820,
    show: true,
    ...(fs.existsSync(iconPath) ? { icon: iconPath } : {}),
    webPreferences: {
      preload: path.join(__dirname, "preload.js"),
      nodeIntegration: false,
      contextIsolation: true,
    },
  });
  mainWindow = win;
  win.on("closed", () => {
    if (mainWindow === win) mainWindow = null;
  });
  win.on("focus", () => stopMainFlash());

  // 加载离线资源（与 index.html 同级放置）
  win.loadFile(path.join(__dirname, "index.html"));
}

/** Windows：首次成功启动时提示一次「智能应用控制」类拦截的常见原因（被拦时进程未启动，无法由此弹窗）。 */
function maybeShowWindowsSmartAppControlHintOnce() {
  if (process.platform !== "win32") return;
  const flag = path.join(app.getPath("userData"), ".smart-app-control-hint-shown-v1");
  if (fs.existsSync(flag)) return;
  setTimeout(() => {
    dialog
      .showMessageBox({
        type: "info",
        title: "关于 Windows 安全提示",
        message: "若双击 exe 时曾出现「智能应用控制已阻止可能不安全的应用」等提示：",
        detail:
          "多为便携版未使用商业代码签名，系统无法确认发布者所致，一般不是程序损坏。\n\n" +
          "可尝试：右键 exe → 属性 → 勾选「解除锁定」后重试；仍被拦时可在「Windows 安全中心 → 应用和浏览器控制」中调整智能应用控制（会降低对未知应用的防护，请自行权衡）。\n\n" +
          "完整说明见与 exe 同目录的《若无法运行-请先阅读.txt》或项目 README。",
        buttons: ["知道了"],
        defaultId: 0,
        noLink: true,
      })
      .then(() => {
        try {
          fs.writeFileSync(flag, "1", "utf8");
        } catch {
          // ignore
        }
      })
      .catch(() => {});
  }, 700);
}

app.whenReady().then(() => {
  ipcMain.handle("batch-ping", async (_event, payload) => {
    const ipList = Array.isArray(payload?.ips) ? payload.ips.map((x) => String(x).trim()) : [];
    const filtered = ipList.filter((ip) => isValidIPv4(ip));
    if (!filtered.length) return [];
    const unique = [...new Set(filtered)];
    const timeoutMs = Number(payload?.timeoutMs) || 1200;
    const concurrency = Number(payload?.concurrency) || 32;
    return await runBatchPing(unique, timeoutMs, concurrency);
  });

  ipcMain.handle("tcp-port-scan", async (_event, payload) => {
    const raw = Array.isArray(payload?.probes) ? payload.probes : [];
    const timeoutMs = Number(payload?.timeoutMs) || 2000;
    const concurrency = Number(payload?.concurrency) || 8;
    const staggerMs = Number(payload?.staggerMs) || 0;
    const probes = [];
    for (const item of raw) {
      const ip = String(item?.ip || "").trim();
      const port = item?.port;
      if (!isValidIPv4(ip) || !isValidTcpPort(port)) continue;
      probes.push({ ip, port: Number(port) });
    }
    if (!probes.length) return [];
    if (probes.length > MAX_TCP_PROBE_TASKS) {
      throw new Error(`探测任务数 ${probes.length} 超过上限 ${MAX_TCP_PROBE_TASKS}，请减少地址数或端口数。`);
    }
    return await runBatchTcpProbe(probes, timeoutMs, concurrency, staggerMs);
  });

  ipcMain.handle("local-network-info", async () => getLocalNetworkInfoPayload());

  ipcMain.handle("show-native-message-box", async (_event, payload) => {
    const title = String(payload?.title || "提示");
    const message = String(payload?.message || "");
    const isErr = Boolean(payload?.variant === "error");
    const parent = mainWindow && !mainWindow.isDestroyed() ? mainWindow : undefined;
    await dialog.showMessageBox(parent, {
      type: isErr ? "error" : "info",
      title,
      message,
      buttons: ["确定"],
      defaultId: 0,
      noLink: true,
    });
    return { ok: true };
  });

  ipcMain.handle("show-task-notification", async (_event, payload) => {
    const title = String(payload?.title || "提示");
    const message = String(payload?.message || "");
    const variant = payload?.variant === "error" ? "error" : "info";
    const theme = payload?.theme === "light" ? "light" : "dark";
    pendingNotifyTabId = String(payload?.tabId || "");
    if (mainWindow && !mainWindow.isDestroyed()) {
      try {
        mainWindow.flashFrame(true);
      } catch {
        // ignore
      }
    }
    await showTaskNotifyInternal({ title, message, variant, theme });
    return { ok: true };
  });

  ipcMain.on("task-notify-activate", () => {
    stopMainFlash();
    if (notifyWindow && !notifyWindow.isDestroyed()) {
      try {
        notifyWindow.close();
      } catch {
        // ignore
      }
    }
    const tabId = pendingNotifyTabId;
    pendingNotifyTabId = "";
    if (mainWindow && !mainWindow.isDestroyed()) {
      if (mainWindow.isMinimized()) mainWindow.restore();
      mainWindow.show();
      mainWindow.focus();
      mainWindow.webContents.send("app-navigate-tab", tabId);
    }
  });

  ipcMain.on("task-notify-dismiss", () => {
    stopMainFlash();
    if (notifyWindow && !notifyWindow.isDestroyed()) {
      try {
        notifyWindow.close();
      } catch {
        // ignore
      }
    }
    pendingNotifyTabId = "";
  });

  ipcMain.handle("trace-route-abort", async () => {
    traceRouteAborted = true;
    if (traceRouteChild) {
      try {
        traceRouteChild.kill();
      } catch {
        // ignore
      }
    }
    return { ok: true };
  });

  ipcMain.handle("trace-route-pause-toggle", async () => {
    if (process.platform === "win32") {
      return { ok: false, paused: false, unsupported: true };
    }
    if (!traceRouteChild || !traceRouteChild.pid) {
      return { ok: false, paused: traceRoutePaused };
    }
    try {
      if (traceRoutePaused) {
        process.kill(traceRouteChild.pid, "SIGCONT");
        traceRoutePaused = false;
      } else {
        process.kill(traceRouteChild.pid, "SIGSTOP");
        traceRoutePaused = true;
      }
      return { ok: true, paused: traceRoutePaused };
    } catch {
      return { ok: false, paused: traceRoutePaused };
    }
  });

  ipcMain.handle("trace-route", async (_event, payload) => {
    const target = String(payload?.target || "").trim();
    const maxHops = Number(payload?.maxHops) || 30;
    const waitMs = Number(payload?.waitMs) || 4000;
    return await runTraceRoute(target, maxHops, waitMs);
  });

  Menu.setApplicationMenu(buildChineseMenu());
  createWindow();
  maybeShowWindowsSmartAppControlHintOnce();

  app.on("activate", () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on("window-all-closed", () => {
  // Windows 上直接退出即可
  if (process.platform !== "darwin") app.quit();
});

