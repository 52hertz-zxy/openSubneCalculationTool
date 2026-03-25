import {
  ipv4CoreCompute,
  ipv4ReverseCompute,
  ipv4SplitEqual,
  ipv4VlsmPlan,
  ipv4IntToString,
  ipv4MaskFromPrefix,
  ipv4PrefixFromMask,
  ipv4PrefixForHosts,
  detectIPv4AddressType,
  detectIPv4Class,
  parseIPv4Strict,
  ipv4Aggregate,
  computeOverlapRelations,
  ipv6CoreCompute,
  ipv6VlsmPlan,
  ipv6SplitEqual,
  parseCIDROrSingleToRange,
  nearestValidIpv4MaskString,
  suggestIpv6AddrHint,
  suggestIpv6PrefixHint,
  suggestIpv6CidrHint,
} from "./netcalc.js";

import ipGeoDbDefault from "./ip_geo_db.js";

function $(id) {
  return document.getElementById(id);
}

function escapeHtml(s) {
  return String(s)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

/** 智能纠错：不合法输入时输入框红框闪烁 */
const INPUT_INVALID_FLASH_CLS = "input-invalid-flash";

/** 合成 input 事件，供程序化更新只读框后触发实时校验（如四段联动更新组合 CIDR） */
function dispatchSyntheticInput(el) {
  if (!el) return;
  el.dispatchEvent(new Event("input", { bubbles: true }));
}

/** 对「整段 CIDR / 掩码」输入给出可读的纠错建议（不含自动改写） */
function suggestIpv4CidrFreeText(raw) {
  const s = String(raw || "").trim();
  if (!s) return "";
  if ((s.match(/\//g) || []).length > 1) {
    return "智能提示：只能有一个「/」分隔地址与前缀，请删除多余斜杠。";
  }
  const slash = s.indexOf("/");
  const ipPart = slash >= 0 ? s.slice(0, slash).trim() : s;
  const prefPart = slash >= 0 ? s.slice(slash + 1).trim() : "";
  if (ipPart.includes("/")) {
    return "智能提示：「/」只应出现一次，用于分隔 IPv4 地址与 CIDR 前缀。";
  }
  if (ipPart.includes(".")) {
    const segments = ipPart.split(".");
    if (segments.length > 0 && segments.length !== 4) {
      return `智能提示：点分 IPv4 需要恰好 4 段，当前为 ${segments.length} 段。`;
    }
    for (let i = 0; i < segments.length; i++) {
      const seg = segments[i];
      if (seg === "") return `智能提示：第 ${i + 1} 段为空，请去掉连续的点或补全数字。`;
      if (!/^\d+$/.test(seg)) return `智能提示：第 ${i + 1} 段「${seg}」应为纯数字。`;
    }
  }
  const fourOct = /^(\d{1,3}\.){3}\d{1,3}$/.test(ipPart);
  if (fourOct) {
    const parts = ipPart.split(".");
    let changed = false;
    const fixed = parts.map((p) => {
      if (!/^\d+$/.test(p)) return p;
      const n = Number(p);
      if (n > 255) {
        changed = true;
        return "255";
      }
      return p;
    });
    if (changed) {
      const ip2 = fixed.join(".");
      return `智能提示：某段超出 0-255，建议写成 ${slash >= 0 ? `${ip2}/${prefPart}` : ip2}`;
    }
  }
  if (slash >= 0 && prefPart !== "") {
    if (!/^\d+$/.test(prefPart)) {
      return `智能提示：前缀应为 0～32 的整数，当前「${prefPart}」无效。`;
    }
    const pr = Number(prefPart);
    if (!Number.isInteger(pr) || pr < 0 || pr > 32) {
      return `智能提示：CIDR 前缀应在 0～32 之间，当前为 /${prefPart}`;
    }
  }
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(s) && slash < 0) {
    const near = nearestValidIpv4MaskString(s);
    if (near) {
      return `智能提示：掩码须为「左侧连续 1」的标准子网掩码，建议替换为 ${near}`;
    }
  }
  return "";
}

async function copyTextToClipboard(text) {
  const t = String(text || "");
  if (navigator.clipboard && navigator.clipboard.writeText) {
    await navigator.clipboard.writeText(t);
    return;
  }
  const ta = document.createElement("textarea");
  ta.value = t;
  ta.style.position = "fixed";
  ta.style.left = "-9999px";
  document.body.appendChild(ta);
  ta.select();
  document.execCommand("copy");
  document.body.removeChild(ta);
}

/** 避免将 PowerShell CLIXML / 乱码长串直接显示在页面上 */
function sanitizeWinNote(note) {
  const s = String(note || "").trim();
  if (!s) return "";
  if (s.length > 500 || /<Objs\b/i.test(s) || /<S\s+S=/i.test(s) || /\uFFFD/.test(s)) {
    return "Windows 网关/DNS 扩展信息获取异常，已省略原始输出（仍可查看 Node 网卡列表）。";
  }
  return s;
}

function showNoticeModal(title, message, ok = true) {
  const modal = $("noticeModal");
  const tEl = $("noticeModalTitle");
  const bEl = $("noticeModalBody");
  if (!modal || !tEl || !bEl) {
    window.alert(`${title}\n\n${message}`);
    return;
  }
  tEl.textContent = title || "";
  bEl.textContent = message || "";
  bEl.className = `modal-body ${ok ? "notice-modal-body--ok" : "notice-modal-body--err"}`;
  modal.style.display = "flex";
}

function hideNoticeModal() {
  const modal = $("noticeModal");
  if (modal) modal.style.display = "none";
}

let __toastHideTimer = null;
/** 顶层轻提示（高于本机网络等弹窗） */
function showToast(message, variant = "ok") {
  const el = $("appToast");
  if (!el) return;
  el.textContent = String(message || "");
  el.className = `app-toast app-toast--${variant === "err" ? "err" : "ok"}`;
  el.style.display = "block";
  if (__toastHideTimer) clearTimeout(__toastHideTimer);
  __toastHideTimer = setTimeout(() => {
    el.style.display = "none";
    __toastHideTimer = null;
  }, 1500);
}

/** 群 Ping / 端口扫描 / 路由追踪：右下角通知 + 任务栏闪烁；点击通知进入主窗口并切换标签 */
function showTaskNotice(title, message, ok = true, tabId = "") {
  const theme = document.documentElement.getAttribute("data-theme") || "dark";
  if (window.subnetNative && typeof window.subnetNative.showTaskNotification === "function") {
    window.subnetNative
      .showTaskNotification({
        title: title || "提示",
        message: String(message || ""),
        variant: ok ? "info" : "error",
        tabId: tabId || "",
        theme,
      })
      .catch(() => {});
    return;
  }
  if (window.subnetNative && typeof window.subnetNative.showNativeMessageBox === "function") {
    window.subnetNative
      .showNativeMessageBox({
        title: title || "提示",
        message: String(message || ""),
        variant: ok ? "info" : "error",
      })
      .catch(() => {});
    return;
  }
  showNoticeModal(title, message, ok);
}

function fmtBigInt(bi) {
  try {
    return BigInt(bi).toString();
  } catch {
    return String(bi);
  }
}

function showError(el, err) {
  if (!el) return;
  const msg = err instanceof Error ? err.message : String(err);
  el.textContent = msg;
}

function clearError(el) {
  if (!el) return;
  el.textContent = "";
}

function renderOutputBlock(html) {
  return html;
}

function pct(n) {
  if (!Number.isFinite(n)) return "0%";
  return `${Math.round(n * 100)}%`;
}

function renderIPv4Core(res) {
  return `
    <div class="section-title">网络三元组</div>
    <table>
      <tr><th>网络地址</th><td><span class="hl">${escapeHtml(res.network)}</span></td></tr>
      <tr><th>子网掩码</th><td>
        <div>点分十进制：<span class="hl">${escapeHtml(res.netmask)}</span></div>
        <div>CIDR 前缀：<span class="hl">/${res.prefixLen}</span></div>
        <div>二进制：<span class="hl">${escapeHtml(res.maskBinary)}</span></div>
      </td></tr>
      <tr><th>广播地址</th><td><span class="hl">${escapeHtml(res.broadcast)}</span></td></tr>
    </table>

    <div class="section-title">主机相关参数</div>
    <table>
      <tr><th>第一个可用主机</th><td><span class="hl">${escapeHtml(res.firstUsable)}</span></td></tr>
      <tr><th>最后一个可用主机</th><td><span class="hl">${escapeHtml(res.lastUsable)}</span></td></tr>
      <tr><th>可用主机总数</th><td>${escapeHtml(fmtBigInt(res.usableCount))}</td></tr>
    </table>

    <div class="section-title">位运算参数</div>
    <table>
      <tr><th>子网位数</th><td>${res.subnetBits}</td></tr>
      <tr><th>主机位数</th><td>${res.hostBits}</td></tr>
      <tr><th>总位数</th><td>${res.totalBits}</td></tr>
    </table>

    <div class="section-title">地址属性</div>
    <table>
      <tr><th>地址类别</th><td>${escapeHtml(res.addrClass)}</td></tr>
      <tr><th>地址类型</th><td>${escapeHtml(res.addrType)}</td></tr>
    </table>

    <div class="section-title">网段规模</div>
    <table>
      <tr><th>网段总地址数</th><td>${escapeHtml(fmtBigInt(res.totalAddrs))}</td></tr>
      <tr><th>可用主机数占比（利用率）</th><td>${escapeHtml(pct(res.utilization))}</td></tr>
    </table>
  `;
}

function renderIPv4Reverse(result) {
  if (result.mode === "hosts") {
    const rec = result.recommended;
    return `
      <div class="section-title">推算结果（模式一）</div>
      <table>
        <tr><th>父网段</th><td>${escapeHtml(`${result.parentNetwork}/${result.parentPrefix}`)}</td></tr>
        <tr><th>推荐子网 CIDR 前缀</th><td><span class="hl">/${rec.prefixLen}</span></td></tr>
        <tr><th>父网段可划分子网数量（按推荐前缀）</th><td>${escapeHtml(fmtBigInt(result.availableSubnetCount))}</td></tr>
      </table>
      <div style="margin-top:10px;"></div>
      ${renderIPv4Core(rec)}
    `;
  }

  // subnets
  const p = result.recommended.prefixLen;
  const first = result.previewSubnets[0];
  const parentStr = `${result.parentNetwork}/${result.parentPrefix}`;
  return `
    <div class="section-title">推算结果（模式二）</div>
    <table>
      <tr><th>父网段</th><td>${escapeHtml(parentStr)}</td></tr>
      <tr><th>推荐划分前缀</th><td><span class="hl">/${p}</span></td></tr>
      <tr><th>总可划分子网数</th><td>${escapeHtml(fmtBigInt(result.availableSubnetCount))}</td></tr>
      <tr><th>未使用子网数</th><td>${escapeHtml(fmtBigInt(result.unusedSubnets))}</td></tr>
    </table>

    <div class="section-title">初步划分方案（生成期望数量的子网预览）</div>
    <table>
      <tr><th>子网序号</th><th>网段</th><th>掩码</th><th>地址范围</th><th>广播</th></tr>
      ${result.previewSubnets
        .map((x, idx) => {
          return `<tr>
            <td>${idx + 1}</td>
            <td>${escapeHtml(x.network)}/${x.prefixLen}</td>
            <td>${escapeHtml(x.netmask)}</td>
            <td>${escapeHtml(x.firstUsable)} - ${escapeHtml(x.lastUsable)}</td>
            <td>${escapeHtml(x.broadcast)}</td>
          </tr>`;
        })
        .join("")}
    </table>
  `;
}

function renderIPv4Equal(res) {
  return `
    <div class="section-title">划分汇总</div>
    <table>
      <tr><th>父网段</th><td>${escapeHtml(res.parent)}</td></tr>
      <tr><th>推荐子网前缀</th><td><span class="hl">/${res.newPrefix}</span></td></tr>
      <tr><th>总子网数（含未使用）</th><td>${escapeHtml(fmtBigInt(res.totalSubnets))}</td></tr>
      <tr><th>未使用子网数</th><td>${escapeHtml(fmtBigInt(res.unusedSubnets))}</td></tr>
    </table>

    <div class="section-title">子网明细</div>
    <table>
      <tr>
        <th>子网编号</th>
        <th>网段</th>
        <th>子网掩码</th>
        <th>建议网关</th>
        <th>备选网关</th>
        <th>地址范围</th>
        <th>广播地址</th>
        <th>可用主机数</th>
      </tr>
      ${res.subnets
        .map((s) => {
          return `<tr>
            <td>${escapeHtml(String(s.subnetIndex))}</td>
            <td>${escapeHtml(s.network)}/${s.prefixLen}</td>
            <td>${escapeHtml(s.netmask)}</td>
            <td><span class="hl">${escapeHtml(s.firstUsable)}</span></td>
            <td>${escapeHtml(s.lastUsable)}</td>
            <td>${escapeHtml(s.firstUsable)} - ${escapeHtml(s.lastUsable)}</td>
            <td>${escapeHtml(s.broadcast)}</td>
            <td>${escapeHtml(fmtBigInt(s.usableCount))}</td>
          </tr>`;
        })
        .join("")}
    </table>
  `;
}

function renderVlsm(res) {
  return `
    <div class="section-title">方案汇总</div>
    <div class="table-wrap">
      <table>
        <tr><th>父网段</th><td>${escapeHtml(res.parent)}</td></tr>
        <tr><th>策略</th><td>${escapeHtml(res.strategy)}</td></tr>
        <tr><th>已分配地址块总量</th><td>${escapeHtml(fmtBigInt(res.totalAllocated))}</td></tr>
        <tr><th>对齐造成的额外浪费</th><td>${escapeHtml(fmtBigInt(res.totalWasteAlignment))}</td></tr>
        <tr><th>剩余地址</th><td>${escapeHtml(fmtBigInt(res.freeRemaining))}</td></tr>
        <tr><th>地址利用率</th><td>${escapeHtml(pct(res.utilization))}</td></tr>
      </table>
    </div>

    <div class="section-title">VLSM 拓扑清单</div>
    <div class="table-wrap">
      <table class="vlsm-result-table">
        <tr>
          <th>子网名称</th>
          <th>需求主机数</th>
          <th>推荐前缀</th>
          <th>网段</th>
          <th>掩码</th>
          <th>建议网关</th>
          <th>备选网关</th>
          <th>地址范围</th>
          <th>广播</th>
          <th>可用主机数</th>
        </tr>
        ${res.allocations
          .sort((a, b) => (a.interval.start < b.interval.start ? -1 : 1))
          .map((s) => {
            return `<tr>
              <td>${escapeHtml(s.name)}</td>
              <td>${escapeHtml(String(s.hostsNeed))}</td>
              <td><span class="hl">/${s.prefixLen}</span></td>
              <td>${escapeHtml(s.network)}/${s.prefixLen}</td>
              <td>${escapeHtml(s.netmask)}</td>
              <td><span class="hl">${escapeHtml(s.firstUsable)}</span></td>
              <td>${escapeHtml(s.lastUsable)}</td>
              <td>${escapeHtml(s.firstUsable)} - ${escapeHtml(s.lastUsable)}</td>
              <td>${escapeHtml(s.broadcast)}</td>
              <td>${escapeHtml(fmtBigInt(s.usableCount))}</td>
            </tr>`;
          })
          .join("")}
      </table>
    </div>
  `;
}

function buildIpv6VlsmTable(reqs) {
  const wrap = $("ipv6VlsmTableWrap");
  if (!wrap) return;
  if (!reqs.length) {
    wrap.innerHTML = `<div class="hint" style="margin:0;">暂无需求，请先添加。</div>`;
    return;
  }
  wrap.innerHTML = `
    <div class="table-wrap">
      <table>
        <tr><th>名称</th><th>所需地址数</th><th>备注</th><th>操作</th></tr>
        ${reqs
          .map((r, idx) => {
            return `<tr>
              <td style="min-width:140px;">${escapeHtml(r.name)}</td>
              <td>${escapeHtml(String(r.interfaces))}</td>
              <td>${escapeHtml(r.note || "")}</td>
              <td>
                <div class="cell-actions">
                  <button type="button" class="mini-btn" data-ipv6vlsm-act="edit" data-ipv6vlsm-idx="${idx}">编辑</button>
                  <button type="button" class="mini-btn mini-danger" data-ipv6vlsm-act="del" data-ipv6vlsm-idx="${idx}">删除</button>
                </div>
              </td>
            </tr>`;
          })
          .join("")}
      </table>
    </div>
  `;
}

function renderIpv6Vlsm(res) {
  const rows = res.allocations
    .map((a) => {
      return `<tr>
        <td>${escapeHtml(a.name)}</td>
        <td>${escapeHtml(String(a.interfacesNeed))}</td>
        <td><span class="hl">/${a.prefixLen}</span></td>
        <td>${escapeHtml(a.networkPrefix)}</td>
        <td>${escapeHtml(a.firstAddress)} — ${escapeHtml(a.lastAddress)}</td>
        <td>${escapeHtml(a.addressCount)}</td>
        <td>${escapeHtml(a.interfaceIdBits)}</td>
        <td style="max-width:280px;">${escapeHtml(a.utilizationHint)}</td>
      </tr>`;
    })
    .join("");
  return `
    <div class="section-title">方案汇总</div>
    <div class="table-wrap">
      <table>
        <tr><th>父网段</th><td>${escapeHtml(res.parent)}</td></tr>
        <tr><th>策略</th><td>${escapeHtml(res.strategy)}</td></tr>
        <tr><th>父地址空间（个数）</th><td>${escapeHtml(String(res.parentTotalAddrs))}</td></tr>
        <tr><th>已分配地址数</th><td>${escapeHtml(String(res.totalAllocated))}</td></tr>
        <tr><th>对齐浪费（地址数）</th><td>${escapeHtml(String(res.totalWasteAlignment))}</td></tr>
        <tr><th>剩余空闲地址数</th><td>${escapeHtml(String(res.freeRemaining))}</td></tr>
        <tr><th>空间利用率（约）</th><td>${escapeHtml(res.utilization)}</td></tr>
      </table>
    </div>
    <div class="section-title">子网清单</div>
    <div class="table-wrap">
      <table class="vlsm-result-table">
        <tr>
          <th>名称</th>
          <th>需求地址数</th>
          <th>前缀</th>
          <th>子网（CIDR）</th>
          <th>首地址 — 末地址</th>
          <th>块内地址数</th>
          <th>主机位（位）</th>
          <th>前缀 / 接口 ID 建议</th>
        </tr>
        ${rows}
      </table>
    </div>
  `;
}

function renderIpv6EqualSplit(res) {
  const rows = res.subnets
    .map((s, idx) => {
      return `<tr>
        <td>${idx + 1}</td>
        <td><span class="hl">${escapeHtml(s.networkPrefix)}</span></td>
        <td>${escapeHtml(s.prefixRange.first)} — ${escapeHtml(s.prefixRange.last)}</td>
        <td>${escapeHtml(s.interfaceId)}</td>
      </tr>`;
    })
    .join("");
  return `
    <div class="section-title">等长划分结果</div>
    <div class="table-wrap">
      <table>
        <tr><th>父网段</th><td>${escapeHtml(res.parent)}</td></tr>
        <tr><th>新子网前缀</th><td>/${escapeHtml(String(res.newPrefix))}</td></tr>
        <tr><th>划分数量</th><td>${escapeHtml(String(res.desiredSubnets))}</td></tr>
        <tr><th>理论可划分数</th><td>${escapeHtml(fmtBigInt(res.totalPossible))}</td></tr>
        <tr><th>未使用子网槽位</th><td>${escapeHtml(fmtBigInt(res.unusedSubnets))}</td></tr>
      </table>
    </div>
    <div class="table-wrap" style="margin-top:10px;">
      <table>
        <tr><th>#</th><th>子网前缀</th><th>前缀下地址范围</th><th>接口 ID（示例输入）</th></tr>
        ${rows}
      </table>
    </div>
  `;
}

function matchWindowsAdapter(adapters, niName) {
  if (!adapters || !adapters.length) return null;
  const n = String(niName || "");
  let hit = adapters.find((w) => String(w.Name || "") === n);
  if (hit) return hit;
  hit = adapters.find((w) => {
    const k = String(w.Name || "");
    return k && (n.includes(k) || k.includes(n));
  });
  return hit || null;
}

function formatLocalNetworkPlain(data) {
  if (!data) return "";
  const lines = [];
  lines.push(`采集时间: ${new Date().toLocaleString()}`);
  lines.push(`平台: ${data.platform}`);
  lines.push("");
  lines.push("--- Node.js os.networkInterfaces ---");
  for (const ni of data.nodeInterfaces || []) {
    lines.push(`[${ni.name}] MAC=${ni.mac || ""} internal=${ni.internal}`);
    for (const a of ni.addresses || []) {
      lines.push(
        `  ${a.family} ${a.address} netmask=${a.netmask || ""} cidr=${a.cidr || ""}`,
      );
    }
  }
  if ((data.windowsAdapters || []).length) {
    lines.push("");
    lines.push("--- Windows（网关/DNS，Get-NetIPConfiguration）---");
    for (const w of data.windowsAdapters) {
      lines.push(`[${w.Name || ""}]`);
      lines.push(`  IPv4: ${w.IPv4 || "—"}`);
      lines.push(`  IPv6: ${w.IPv6 || "—"}`);
      lines.push(`  网关 IPv4: ${w.Gateway4 || "—"}`);
      lines.push(`  网关 IPv6: ${w.Gateway6 || "—"}`);
      lines.push(`  DNS IPv4: ${w.DNS4 || "—"}`);
      lines.push(`  DNS IPv6: ${w.DNS6 || "—"}`);
    }
  }
  const wNote = sanitizeWinNote(data.windowsDetailNote);
  if (wNote && !(data.windowsAdapters || []).length) lines.push(`\n(Windows: ${wNote})`);
  return lines.join("\n");
}

function renderTraceRouteHtml(data) {
  if (!data) return `<div class="hint">无数据。</div>`;
  const hops = Array.isArray(data.hops) ? data.hops : [];
  const rows = hops
    .map((h) => {
      const ip = h.ip ? escapeHtml(String(h.ip)) : `<span class="muted">—</span>`;
      const lat = h.avgMs != null ? escapeHtml(String(h.avgMs)) : `<span class="muted">—</span>`;
      const loss = escapeHtml(String(h.lossPct != null ? `${h.lossPct}%` : "—"));
      const probes = Array.isArray(h.probes)
        ? escapeHtml(h.probes.map((p) => (p == null ? "*" : String(p))).join(" / "))
        : "—";
      return `<tr>
        <td>${escapeHtml(String(h.hop))}</td>
        <td>${ip}</td>
        <td>${escapeHtml(String(h.host || ""))}</td>
        <td>${lat}</td>
        <td>${loss}</td>
        <td>${probes}</td>
      </tr>`;
    })
    .join("");
  const note = data.parseNote
    ? `<div class="hint" style="margin-bottom:8px;">${escapeHtml(String(data.parseNote))}</div>`
    : "";
  const stderr = data.stderr
    ? `<div class="hint" style="margin-bottom:8px;">${escapeHtml(String(data.stderr).slice(0, 600))}</div>`
    : "";
  const exit =
    data.exitCode != null
      ? `<div class="hint">进程退出码：${escapeHtml(String(data.exitCode))}</div>`
      : "";
  const raw = String(data.raw || "");
  return `${note}${stderr}${exit}
    <div class="section-title">逐跳摘要</div>
    <div class="table-wrap"><table>
      <tr><th>跳</th><th>IP</th><th>节点</th><th>平均延迟(ms)</th><th>丢包率</th><th>三次探测(ms)</th></tr>
      ${rows || `<tr><td colspan="6">无解析结果，请查看下方原始输出。</td></tr>`}
    </table></div>
    <div class="section-title" style="margin-top:12px;">原始输出</div>
    <pre class="trace-raw-pre">${escapeHtml(raw.slice(0, 150000))}</pre>`;
}

function formatTracePlain(data) {
  if (!data) return "";
  const lines = [];
  lines.push(`目标: ${data.target}`);
  lines.push(`退出码: ${data.exitCode}`);
  lines.push("");
  for (const h of data.hops || []) {
    const ps = (h.probes || []).map((p) => (p == null ? "*" : String(p))).join(",");
    lines.push(
      `${h.hop}\t${h.ip || ""}\t${h.host || ""}\tavgMs=${h.avgMs ?? ""}\tloss=${h.lossPct ?? ""}%\tprobes=${ps}`,
    );
  }
  lines.push("");
  lines.push("--- raw ---");
  lines.push(String(data.raw || ""));
  return lines.join("\n");
}

function renderLocalNetworkHtml(data, idPrefix = "ln") {
  if (!data || !(data.nodeInterfaces || []).length) {
    return `<div class="hint">未获取到网卡信息。</div>`;
  }
  let html = "";
  if (data.platform === "win32" && data.windowsDetailOk === false) {
    const sn = sanitizeWinNote(data.windowsDetailNote);
    if (sn) {
      html += `<div class="hint" style="margin-bottom:10px;">${escapeHtml(sn)}</div>`;
    }
  } else if (data.windowsDetailNote && !(data.windowsAdapters || []).length) {
    const sn = sanitizeWinNote(data.windowsDetailNote);
    if (sn) {
      html += `<div class="hint" style="margin-bottom:10px;">${escapeHtml(sn)}</div>`;
    }
  }
  const pid = String(idPrefix || "ln").replace(/[^a-zA-Z0-9_-]/g, "");
  (data.nodeInterfaces || []).forEach((ni, idx) => {
    const w = matchWindowsAdapter(data.windowsAdapters, ni.name);
    html += `<div class="localnet-card">`;
    html += `<h4>${escapeHtml(ni.name)}${ni.internal ? ` <span class="hint">(内部)</span>` : ""}</h4>`;
    const mac = ni.mac || "—";
    const idMac = `${pid}-${idx}-mac`;
    html += `<div class="localnet-row"><span class="localnet-k">MAC</span><span class="localnet-v" id="${idMac}">${escapeHtml(
      mac,
    )}</span><button type="button" class="mini-btn" data-ln-copy="${idMac}">复制</button></div>`;
    (ni.addresses || []).forEach((a, aidx) => {
      const idv = `${pid}-${idx}-a-${aidx}`;
      const line = `${a.family} ${a.address}  掩码:${a.netmask || "—"}  CIDR:${a.cidr || "—"}`;
      html += `<div class="localnet-row"><span class="localnet-k">${escapeHtml(a.family)}</span><span class="localnet-v" id="${idv}">${escapeHtml(
        line,
      )}</span><button type="button" class="mini-btn" data-ln-copy="${idv}">复制</button></div>`;
    });
    if (w) {
      html += `<div class="section-title" style="margin-top:10px;font-size:13px;">Windows 网关 / DNS（已按名称匹配）</div>`;
      const rows = [
        ["网关 IPv4", w.Gateway4 || "—", `${pid}-${idx}-gw4`],
        ["网关 IPv6", w.Gateway6 || "—", `${pid}-${idx}-gw6`],
        ["DNS IPv4", w.DNS4 || "—", `${pid}-${idx}-dns4`],
        ["DNS IPv6", w.DNS6 || "—", `${pid}-${idx}-dns6`],
      ];
      for (const [lab, val, eid] of rows) {
        html += `<div class="localnet-row"><span class="localnet-k">${escapeHtml(lab)}</span><span class="localnet-v" id="${eid}">${escapeHtml(
          val,
        )}</span><button type="button" class="mini-btn" data-ln-copy="${eid}">复制</button></div>`;
      }
    } else if (data.platform === "win32") {
      html += `<div class="hint" style="margin-top:6px;">未匹配到同名 Windows 适配器行，网关/DNS 可能仍在列表其他项中。</div>`;
    }
    html += `<div class="localnet-row" style="margin-top:8px;"><button type="button" class="mini-btn" data-ln-copy-card="1">复制本卡全部文本</button></div>`;
    html += `</div>`;
  });
  return html;
}

function renderAggregate(res) {
  return `
    <div class="section-title">汇总前网段列表（输入）</div>
    <div class="bar-viz">
      <div class="hint" style="margin:0 0 8px;">输入网段数：${escapeHtml(String(res.before.length))}</div>
      <div style="font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, 'Liberation Mono', 'Courier New', monospace;">
        ${res.before.map((x) => `<div>${escapeHtml(x)}</div>`).join("")}
      </div>
    </div>

    <div style="height:12px;"></div>
    <div class="section-title">汇总后超网列表（输出）</div>
    <table>
      <tr><th>序号</th><th>超网</th></tr>
      ${res.after.map((x, idx) => `<tr><td>${idx + 1}</td><td><span class="hl">${escapeHtml(x)}</span></td></tr>`).join("")}
    </table>

    <div style="height:12px;"></div>
    <div class="section-title">减少路由条目数量</div>
    <div class="hint" style="margin:0;">
      减少：${escapeHtml(String(res.reducedRoutes))}（${escapeHtml(String(res.before.length))} -> ${escapeHtml(String(res.after.length))}）
    </div>
    <div class="hint" style="margin-top:6px;">
      说明：当前实现使用“仅在可严格合并相邻块时”汇总，因此不会引入超出输入并集的地址空洞。
    </div>
  `;
}

function renderConflict(res, inputRanges) {
  const has = res.length > 0;
  const rows = has
    ? res
        .sort((a, b) => (a.version < b.version ? -1 : 1))
        .map((r) => {
          return `<tr>
            <td>${escapeHtml(r.version)}</td>
            <td><span class="hl">${escapeHtml(r.type)}</span></td>
            <td>${escapeHtml(r.left)}</td>
            <td>${escapeHtml(r.right)}</td>
            <td style="font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, 'Liberation Mono', 'Courier New', monospace;">${escapeHtml(r.overlapText)}</td>
            <td>${escapeHtml(r.detail)}</td>
          </tr>`;
        })
        .join("")
    : `<tr><td colspan="6">未检测到冲突/重叠。</td></tr>`;

  // IPv4 可视化（简单条带）
  const ipv4Ranges = inputRanges.filter((x) => x.version === "IPv4");
  let vizHtml = "";
  if (ipv4Ranges.length > 0) {
    vizHtml = `
      <div class="section-title">IPv4 简易可视化（地址区间）</div>
      <div class="bar-viz">
        <div class="hint" style="margin:0 0 8px;">说明：条带为范围相对位置示意（0 - 2^32-1 缩放）。</div>
        <div class="bar-track">
          ${ipv4Ranges
            .map((r, idx) => {
              const start = Number(r.start);
              const end = Number(r.end);
              const total = 2 ** 32;
              const leftPct = (start / total) * 100;
              const sizePct = ((end - start + 1) / total) * 100;
              const color = idx % 2 === 0 ? "rgba(78,161,255,.35)" : "rgba(52,211,153,.35)";
              return `<div class="bar-range" style="left:${leftPct}%; width:${sizePct}%; background:${color}; border-color:${color};">
                ${escapeHtml(r.original)}
              </div>`;
            })
            .join("")}
        </div>
      </div>
    `;
  }

  return `
    ${vizHtml}
    <div class="section-title">冲突报告</div>
    <table>
      <tr>
        <th>IP 版本</th>
        <th>关系类型</th>
        <th>网段 A</th>
        <th>网段 B</th>
        <th>交集范围</th>
        <th>说明</th>
      </tr>
      ${rows}
    </table>
    <div class="hint" style="margin-top:10px;">
      仅输出存在交集的两两关系（完全重叠/部分重叠/包含关系）。
    </div>
  `;
}

function tokenizeInput(text) {
  return normalize(text)
    .split(/[\s,]+/)
    .map((x) => x.trim())
    .filter(Boolean);
}

function normalize(s) {
  return String(s || "")
    .replace(/\r\n/g, "\n")
    .replace(/\u3000/g, " ")
    .trim();
}

function renderOctRowWithHints(octIds, octets = ["192", "168", "1", "0"]) {
  const o = octets;
  const bits = [];
  for (let i = 0; i < 4; i++) {
    bits.push(
      `<span class="oct-with-hint"><input id="${octIds[i]}" class="text-input ipv4-oct-input" type="text" inputmode="numeric" maxlength="3" placeholder="${o[i] ?? "0"}" style="width:80px;height:50px;min-height:50px;max-height:50px;box-sizing:border-box;" /><div class="oct-smart-hint hint smart-correct-hint" aria-live="polite"></div></span>`,
    );
    if (i < 3) bits.push('<span class="oct-sep">.</span>');
  }
  return `<div class="row ipv4-oct-row" style="justify-content:flex-start;align-items:flex-start;flex-wrap:wrap;gap:4px 6px;">${bits.join("")}</div>`;
}

function renderIPv4TemplateBlock(cfg) {
  const o = cfg.octets || ["192", "168", "1", "0"];
  const readonly = cfg.outputReadonly === false ? "" : "readonly";
  const errorHtml = cfg.errorId ? `<div id="${cfg.errorId}" class="error"></div>` : "";
  return `
    ${renderOctRowWithHints(cfg.octIds, o)}
    <div class="row" style="justify-content:flex-start;align-items:flex-start;flex-wrap:wrap;gap:8px;">
      <input id="${cfg.prefixId}" class="text-input" type="number" min="0" max="32" value="${cfg.prefixValue ?? 24}" style="max-width:120px;" />
      <span class="mask-with-hint" style="flex:1;min-width:200px;">
        <input id="${cfg.maskId}" class="text-input" type="text" value="${cfg.maskValue ?? "255.255.255.0"}" style="max-width:220px;" />
        <div class="mask-smart-hint hint smart-correct-hint" aria-live="polite"></div>
      </span>
    </div>
    <input id="${cfg.outputId}" class="text-input" type="text" ${readonly} />
    ${errorHtml}
  `;
}

function renderIPv4AddressTemplateBlock(cfg) {
  const o = cfg.octets || ["192", "168", "1", "10"];
  const errorHtml = cfg.errorId ? `<div id="${cfg.errorId}" class="error"></div>` : "";
  return `
    ${renderOctRowWithHints(cfg.octIds, o)}
    ${errorHtml}
  `;
}

function mountSharedTemplates() {
  const renderButtons = (buttons) =>
    buttons
      .map((b) => `<button id="${b.id}" class="${b.className}"${b.type ? ` type="${b.type}"` : ""}>${escapeHtml(b.label)}</button>`)
      .join("");
  const mountButtons = (mountId, buttons) => {
    const el = $(mountId);
    if (el) el.innerHTML = renderButtons(buttons);
  };
  const tabs = $("tabsTemplate");
  if (tabs) {
    const tabDefs = [
      { id: "tab-ipv4-core", label: "IPv4 计算", active: true },
      { id: "tab-ipv6-core", label: "IPv6 计算" },
      { id: "tab-ipv6-plan", label: "IPv6 子网规划" },
      { id: "tab-ping", label: "群 Ping 检测" },
      { id: "tab-portscan", label: "端口扫描" },
      { id: "tab-trace", label: "路由追踪" },
      { id: "tab-equal", label: "等长子网规划" },
      { id: "tab-vlsm", label: "可变长子网规划" },
      { id: "tab-aggregate", label: "CIDR 汇总" },
      { id: "tab-conflict", label: "冲突/包含检查" },
      { id: "tab-dual", label: "双栈对比" },
      { id: "tab-address-validate", label: "地址验证/归属查询" },
    ];
    tabs.innerHTML = tabDefs
      .map((t) => `<button class="tab-button${t.active ? " is-active" : ""}" data-tab="${t.id}">${escapeHtml(t.label)}</button>`)
      .join("");
  }
  const menuButtons = $("menuButtonsTemplate");
  if (menuButtons) {
    menuButtons.innerHTML = `
      ${renderButtons([
        { id: "menuLocalNetBtn", className: "mini-btn", label: "本机网络" },
        { id: "menuExportCsv", className: "mini-btn", label: "导出 CSV" },
        { id: "menuExportTxt", className: "mini-btn", label: "导出 TXT" },
        { id: "menuExportExcel", className: "mini-btn", label: "导出 Excel" },
        { id: "themeToggleBtn", className: "mini-btn", label: "主题：自动", type: "button" },
        { id: "menuHelpBtn", className: "mini-btn", label: "帮助" },
      ])}
    `;
  }
  mountButtons("ipv4MainActions", [
    { id: "ipv4CalcBtn", className: "primary", label: "一键计算" },
    { id: "ipv4SampleBtn", className: "ghost", label: "示例", type: "button" },
  ]);
  mountButtons("ipv4ReverseActions", [{ id: "ipv4ReverseBtn", className: "primary", label: "开始反向推算" }]);
  mountButtons("ipv6MainActions", [
    { id: "ipv6CalcBtn", className: "primary", label: "计算" },
    { id: "ipv6SampleBtn", className: "ghost", label: "示例", type: "button" },
  ]);
  mountButtons("ipv6VlsmMainActions", [
    { id: "ipv6VlsmPlanBtn", className: "primary", label: "生成 IPv6 VLSM 方案" },
  ]);
  mountButtons("ipv6EqualMainActions", [{ id: "ipv6EqualGenBtn", className: "primary", label: "生成等长子网" }]);
  mountButtons("equalMainActions", [
    { id: "equalPreviewBtn", className: "ghost", label: "划分预览" },
    { id: "equalGenBtn", className: "primary", label: "生成所有子网" },
  ]);
  mountButtons("vlsmMainActions", [{ id: "vlsmPlanBtn", className: "primary", label: "生成 VLSM 方案" }]);
  mountButtons("aggMainActions", [{ id: "aggBtn", className: "primary", label: "计算汇总结果" }]);
  mountButtons("conflictMainActions", [{ id: "conflictBtn", className: "primary", label: "批量检查" }]);
  mountButtons("pingMainActions", [
    { id: "batchPingBtn", className: "primary", label: "开始群 Ping" },
    { id: "batchPingExportBtn", className: "ghost", label: "导出 Ping Excel" },
  ]);
  mountButtons("portScanMainActions", [
    { id: "portScanStartBtn", className: "primary", label: "开始端口扫描" },
    { id: "portScanExportBtn", className: "ghost", label: "导出扫描 Excel" },
  ]);
  mountButtons("traceMainActions", [
    { id: "traceStartBtn", className: "primary", label: "开始追踪" },
    { id: "tracePauseBtn", className: "btn-pill-outline", label: "暂停", type: "button" },
    { id: "traceStopBtn", className: "mini-btn mini-danger", label: "停止", type: "button" },
    { id: "traceCopyRawBtn", className: "btn-pill-outline", label: "复制原始输出" },
  ]);
  mountButtons("dualMainActions", [{ id: "dualBtn", className: "primary", label: "对比计算" }]);
  mountButtons("addrMainActions", [
    { id: "addrTypeBtn", className: "primary", label: "判断地址类型" },
    { id: "addrGeoBtn", className: "ghost", label: "查询归属（可选离线库）" },
  ]);

  const templates = [
    {
      mountId: "equalIPv4Template",
      octIds: ["equalOct1", "equalOct2", "equalOct3", "equalOct4"],
      prefixId: "equalPrefixInput",
      maskId: "equalMaskInput",
      outputId: "equalParent",
      errorId: "equalError",
      octets: ["192", "168", "1", "0"],
      prefixValue: 24,
      maskValue: "255.255.255.0",
    },
    {
      mountId: "vlsmIPv4Template",
      octIds: ["vlsmOct1", "vlsmOct2", "vlsmOct3", "vlsmOct4"],
      prefixId: "vlsmPrefixInput",
      maskId: "vlsmMaskInput",
      outputId: "vlsmParent",
      errorId: "vlsmError",
      octets: ["192", "168", "1", "0"],
      prefixValue: 24,
      maskValue: "255.255.255.0",
    },
    {
      mountId: "dualIPv4Template",
      octIds: ["dualOct1", "dualOct2", "dualOct3", "dualOct4"],
      prefixId: "dualPrefixInput",
      maskId: "dualMaskInput",
      outputId: "dualIPv4",
      octets: ["192", "168", "1", "0"],
      prefixValue: 24,
      maskValue: "255.255.255.0",
    },
    {
      mountId: "pingIPv4Template",
      octIds: ["pingOct1", "pingOct2", "pingOct3", "pingOct4"],
      prefixId: "pingPrefixInput",
      maskId: "pingMaskInput",
      outputId: "pingInput",
      octets: ["192", "168", "1", "0"],
      prefixValue: 24,
      maskValue: "255.255.255.0",
    },
    {
      mountId: "portScanIPv4Template",
      octIds: ["scanOct1", "scanOct2", "scanOct3", "scanOct4"],
      prefixId: "scanPrefixInput",
      maskId: "scanMaskInput",
      outputId: "portScanCidr",
      errorId: "portScanCidrError",
      octets: ["192", "168", "1", "0"],
      prefixValue: 24,
      maskValue: "255.255.255.0",
    },
  ];
  templates.forEach((cfg) => {
    const mount = $(cfg.mountId);
    if (mount) mount.innerHTML = renderIPv4TemplateBlock(cfg);
  });

  const addrMount = $("addrIPv4Template");
  if (addrMount) {
    addrMount.innerHTML = renderIPv4AddressTemplateBlock({
      octIds: ["addrOct1", "addrOct2", "addrOct3", "addrOct4"],
      errorId: "addrValidateError",
      octets: ["192", "168", "1", "10"],
    });
  }
}


function buildVlsmTable(reqs) {
  const wrap = $("vlsmTableWrap");
  if (!reqs.length) {
    wrap.innerHTML = `<div class="hint" style="margin:0;">暂无子网需求，先添加一个吧。</div>`;
    return;
  }

  wrap.innerHTML = `
    <div class="table-wrap">
      <table>
        <tr><th>名称</th><th>需求主机数</th><th>备注</th><th>操作</th></tr>
        ${reqs
          .map((r, idx) => {
            return `<tr>
              <td style="min-width:140px;">${escapeHtml(r.name)}</td>
              <td>${escapeHtml(String(r.hosts))}</td>
              <td>${escapeHtml(r.note || "")}</td>
              <td>
                <div class="cell-actions">
                  <button class="mini-btn" data-act="edit" data-idx="${idx}">编辑</button>
                  <button class="mini-btn mini-danger" data-act="del" data-idx="${idx}">删除</button>
                </div>
              </td>
            </tr>`;
          })
          .join("")}
      </table>
    </div>
  `;
}

function setupIPv4VisualInput(cfg) {
  const oct = [$(cfg.oct1), $(cfg.oct2), $(cfg.oct3), $(cfg.oct4)];
  const prefixInput = $(cfg.prefixInput);
  const maskInput = $(cfg.maskInput);
  const outputInput = $(cfg.outputInput);
  const prefixSlider = cfg.prefixSlider ? $(cfg.prefixSlider) : null;
  const prefixSelect = cfg.prefixSelect ? $(cfg.prefixSelect) : null;
  const hostNeedInput = cfg.hostNeedInput ? $(cfg.hostNeedInput) : null;
  const hostHint = cfg.hostHint ? $(cfg.hostHint) : null;
  const defaultPrefix = Number(cfg.defaultPrefix ?? 24);

  const getOctHint = (inp) => (inp && inp.closest(".oct-with-hint")?.querySelector(".oct-smart-hint")) || null;
  const getMaskHint = () => (maskInput && maskInput.closest(".mask-with-hint")?.querySelector(".mask-smart-hint")) || null;

  /** editedIdx/editedRaw：刚编辑的那一段在截断为 255 前的原始数字，用于正确提示「超出 255」 */
  const refreshOctHints = (editedIdx = -1, editedRaw = null) => {
    oct.forEach((el, i) => {
      if (!el) return;
      const rawDigits = String(el.value || "").replace(/\D/g, "").slice(0, 3);
      let rawNum = rawDigits === "" ? null : Number(rawDigits);
      if (i === editedIdx && editedRaw != null) rawNum = editedRaw;
      const h = getOctHint(el);
      if (rawNum != null && rawNum > 255) {
        const oth = oct.map((o, j) => (j === i ? "255" : sanitizeOctet(o.value)));
        if (h) h.textContent = `智能提示：第 ${i + 1} 段超出 0-255（${rawNum}），已按 255 截断；建议写成 ${oth.join(".")}`;
        el.classList.add(INPUT_INVALID_FLASH_CLS);
      } else {
        if (h) h.textContent = "";
        el.classList.remove(INPUT_INVALID_FLASH_CLS);
      }
    });
  };

  const sanitizeOctet = (v) => {
    const digits = String(v || "").replace(/\D/g, "").slice(0, 3);
    if (!digits) return "";
    const n = Math.min(255, Number(digits));
    return String(n);
  };
  const composeIp = () => oct.map((x) => sanitizeOctet(x.value)).join(".");

  /** 掩码框：立即根据当前输入更新提示与红闪（与防抖内逻辑一致） */
  let maskHintTimer = null;
  const runMaskFieldHintImmediate = () => {
    const mh = getMaskHint();
    const v = maskInput.value.trim();
    if (!v) {
      if (mh) mh.textContent = "";
      maskInput.classList.remove(INPUT_INVALID_FLASH_CLS);
      return;
    }
    try {
      ipv4PrefixFromMask(v);
      if (mh) mh.textContent = "";
      maskInput.classList.remove(INPUT_INVALID_FLASH_CLS);
    } catch {
      const near = nearestValidIpv4MaskString(v);
      const tip = near
        ? `智能提示：掩码须为左侧连续 1 的标准子网掩码，建议替换为 ${near}`
        : "智能提示：掩码格式异常，请检查四段数字是否在 0-255";
      if (mh) mh.textContent = tip;
      maskInput.classList.add(INPUT_INVALID_FLASH_CLS);
    }
  };

  const applyPrefix = (pRaw) => {
    const p = Math.max(0, Math.min(32, Number(pRaw)));
    prefixInput.value = String(p);
    if (prefixSlider) prefixSlider.value = String(p);
    if (prefixSelect) prefixSelect.value = String(p);
    maskInput.value = ipv4IntToString(ipv4MaskFromPrefix(p));
    outputInput.value = `${composeIp()}/${p}`;
    if (hostNeedInput && hostHint) {
      const desired = Number(hostNeedInput.value);
      if (Number.isFinite(desired) && desired > 0) {
        const rec = ipv4PrefixForHosts(0, true, desired);
        const usable = String((1n << BigInt(32 - rec)) - (rec <= 30 ? 2n : 0n));
        hostHint.textContent = `推荐最优掩码：/${rec}（可用主机约 ${usable}）`;
      } else {
        hostHint.textContent = "";
      }
    }
    /* 前缀/滑块/下拉 改回合法掩码时：取消待触发的掩码防抖，并立即按新掩码校验（避免仍显示旧错误） */
    clearTimeout(maskHintTimer);
    maskHintTimer = null;
    runMaskFieldHintImmediate();
    dispatchSyntheticInput(outputInput);
  };
  const applyMask = (maskStr) => {
    try {
      const p = ipv4PrefixFromMask(maskStr);
      applyPrefix(p);
    } catch {
      // do nothing while typing invalid mask
    }
  };
  const updateOutputOnly = () => {
    outputInput.value = `${composeIp()}/${prefixInput.value || defaultPrefix}`;
    dispatchSyntheticInput(outputInput);
  };

  oct.forEach((el, idx) => {
    el.addEventListener("keydown", (ev) => {
      // 输入 "." 时：阻止字符写入，并自动跳到下一段（最后一段不跳转，仅过滤）
      if (ev.key === "." || ev.code === "NumpadDecimal") {
        ev.preventDefault();
        if (idx < oct.length - 1) {
          const next = oct[idx + 1];
          next.focus();
          next.select();
        }
      }
    });
    el.addEventListener("input", () => {
      const rawDigitsPre = String(el.value || "").replace(/\D/g, "").slice(0, 3);
      const editedRaw = rawDigitsPre === "" ? null : Number(rawDigitsPre);
      const before = el.value;
      el.value = sanitizeOctet(el.value);
      refreshOctHints(idx, editedRaw);
      if (before.length >= 3 && idx < 3) oct[idx + 1].focus();
      updateOutputOnly();
    });
  });
  prefixInput.addEventListener("input", () => applyPrefix(prefixInput.value || defaultPrefix));
  if (prefixSlider) prefixSlider.addEventListener("input", () => applyPrefix(prefixSlider.value));
  if (prefixSelect) prefixSelect.addEventListener("change", () => applyPrefix(prefixSelect.value));
  maskInput.addEventListener("input", () => {
    applyMask(maskInput.value);
    clearTimeout(maskHintTimer);
    maskHintTimer = setTimeout(runMaskFieldHintImmediate, 280);
  });
  if (hostNeedInput && hostHint) {
    hostNeedInput.addEventListener("input", () => applyPrefix(prefixInput.value || defaultPrefix));
  }

  if (Array.isArray(cfg.defaultIp)) {
    oct.forEach((el, i) => {
      el.value = String(cfg.defaultIp[i] ?? "");
    });
  }
  applyPrefix(defaultPrefix);
}

/** 将两栏 .grid-2 改为可拖拽调整左右宽度 */
function initResizableGrid2Layouts() {
  document.querySelectorAll(".grid-2").forEach((grid) => {
    if (grid.dataset.splitInit === "1") return;
    const cards = Array.from(grid.children).filter((c) => c.classList && c.classList.contains("card"));
    if (cards.length !== 2) return;
    grid.dataset.splitInit = "1";
    grid.classList.add("grid-2--split");
    grid.style.setProperty("--split-left", "38");
    const [a, b] = cards;
    a.classList.add("grid-2-pane", "grid-2-pane--a");
    b.classList.add("grid-2-pane", "grid-2-pane--b");
    const gutter = document.createElement("div");
    gutter.className = "grid-2-gutter";
    gutter.title = "拖拽调整左右栏宽度";
    grid.insertBefore(gutter, b);
    gutter.addEventListener("mousedown", (e) => {
      e.preventDefault();
      const startX = e.clientX;
      const r = grid.getBoundingClientRect();
      const rectW = r.width || 1;
      const startPct = Number(grid.style.getPropertyValue("--split-left")) || 38;
      const onMove = (ev) => {
        const dx = ev.clientX - startX;
        const dPct = (dx / rectW) * 100;
        let p = Math.round(startPct + dPct);
        p = Math.max(22, Math.min(78, p));
        grid.style.setProperty("--split-left", String(p));
      };
      const onUp = () => {
        document.removeEventListener("mousemove", onMove);
        document.removeEventListener("mouseup", onUp);
      };
      document.addEventListener("mousemove", onMove);
      document.addEventListener("mouseup", onUp);
    });
  });
}

export function initUI() {
  mountSharedTemplates();

  const THEME_KEY = "subnetcalc_theme_v1";
  const themeToggleBtn = $("themeToggleBtn");
  const THEME_MODES = ["auto", "light", "dark"];
  const mediaDark = window.matchMedia ? window.matchMedia("(prefers-color-scheme: dark)") : null;
  const normalizeMode = (mode) => (THEME_MODES.includes(mode) ? mode : "auto");
  const resolveTheme = (mode) => {
    if (mode === "light") return "light";
    if (mode === "dark") return "dark";
    return mediaDark && mediaDark.matches ? "dark" : "light";
  };
  const updateThemeButton = (mode, resolved) => {
    if (!themeToggleBtn) return;
    const modeLabel = mode === "auto" ? "自动" : mode === "light" ? "浅色" : "深色";
    const resolvedLabel = resolved === "dark" ? "深色" : "浅色";
    themeToggleBtn.textContent = `主题：${modeLabel}`;
    themeToggleBtn.setAttribute("aria-label", `当前${resolvedLabel}外观（模式：${modeLabel}），点击切换模式`);
    themeToggleBtn.title = `当前显示：${resolvedLabel}；模式：${modeLabel}`;
  };
  const applyTheme = (mode) => {
    const safeMode = normalizeMode(mode);
    const resolved = resolveTheme(safeMode);
    document.documentElement.setAttribute("data-theme", resolved);
    document.documentElement.setAttribute("data-theme-mode", safeMode);
    updateThemeButton(safeMode, resolved);
  };
  const storedMode = normalizeMode(localStorage.getItem(THEME_KEY));
  applyTheme(storedMode);
  if (mediaDark) {
    const onMediaChange = () => {
      const mode = normalizeMode(localStorage.getItem(THEME_KEY));
      if (mode === "auto") applyTheme("auto");
    };
    if (typeof mediaDark.addEventListener === "function") {
      mediaDark.addEventListener("change", onMediaChange);
    } else if (typeof mediaDark.addListener === "function") {
      mediaDark.addListener(onMediaChange);
    }
  }
  if (themeToggleBtn) {
    themeToggleBtn.addEventListener("click", () => {
      const curMode = normalizeMode(document.documentElement.getAttribute("data-theme-mode"));
      const idx = THEME_MODES.indexOf(curMode);
      const nextMode = THEME_MODES[(idx + 1) % THEME_MODES.length];
      localStorage.setItem(THEME_KEY, nextMode);
      applyTheme(nextMode);
    });
  }

  // Tab 切换
  document.querySelectorAll(".tab-button").forEach((btn) => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".tab-button").forEach((b) => b.classList.remove("is-active"));
      document.querySelectorAll(".tab-panel").forEach((p) => p.classList.remove("is-active"));
      btn.classList.add("is-active");
      const id = btn.getAttribute("data-tab");
      $(id).classList.add("is-active");
    });
  });

  function switchToTab(tabId) {
    const id = String(tabId || "").trim();
    if (!id || !$(id)) return;
    document.querySelectorAll(".tab-button").forEach((b) => b.classList.remove("is-active"));
    document.querySelectorAll(".tab-panel").forEach((p) => p.classList.remove("is-active"));
    const bt = document.querySelector(`.tab-button[data-tab="${id}"]`);
    if (bt) bt.classList.add("is-active");
    $(id).classList.add("is-active");
  }
  if (window.subnetNative && typeof window.subnetNative.onNavigateTab === "function") {
    window.subnetNative.onNavigateTab((tid) => switchToTab(tid));
  }

  // ---------- 历史记录 / 导出 / 帮助 ----------
  const HISTORY_KEY = "subnetcalc_history_v1";
  const MAX_HISTORY = 200;
  let historyRecords = [];
  let selectedHistoryId = null;
  let lastRecord = null;
  let geoDbRaw = Array.isArray(ipGeoDbDefault) ? ipGeoDbDefault : [];
  let geoDbNormalized = [];

  const safeStringify = (obj) =>
    JSON.stringify(obj, (_k, v) => {
      if (typeof v === "bigint") return v.toString();
      return v;
    });

  const downloadText = (filename, text, mime) => {
    const blob = new Blob([text], { type: mime || "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  };

  const loadHistory = () => {
    try {
      const raw = localStorage.getItem(HISTORY_KEY);
      if (!raw) return [];
      const parsed = JSON.parse(raw);
      if (!Array.isArray(parsed)) return [];
      return parsed;
    } catch {
      return [];
    }
  };

  const saveHistory = () => {
    localStorage.setItem(HISTORY_KEY, safeStringify(historyRecords));
  };

  const renderHistory = () => {
    const list = $("historyList");
    if (!list) return;
    list.innerHTML = historyRecords
      .slice(0, MAX_HISTORY)
      .map((r) => {
        const active = selectedHistoryId === r.id ? "style=\"outline:2px solid rgba(78,161,255,.65);\"" : "";
        return `<div class="history-item" data-id="${escapeHtml(r.id)}" ${active}>
          <div class="left">
            <div class="title">${escapeHtml(r.title || r.type)}</div>
            <div class="meta">${escapeHtml(new Date(r.createdAt).toLocaleString())}</div>
          </div>
          <div class="actions">
            <button class="btn-pill-outline" data-act="reuse" data-id="${escapeHtml(r.id)}">复用</button>
            <button class="mini-btn mini-danger" data-act="del" data-id="${escapeHtml(r.id)}">删除</button>
          </div>
        </div>`;
      })
      .join("");
  };

  const ensureGeoDbNormalized = () => {
    // 归一化：[{startInt, endInt, prefixLen, org, region, asn}]
    const normalize = (db) => {
      if (!Array.isArray(db)) return [];
      const out = [];
      for (const item of db) {
        try {
          const prefix = String(item.prefix || "").trim();
          const m = prefix.match(/^(.+)\/(\d{1,2})$/);
          if (!m) continue;
          const ip = m[1];
          const p = Number(m[2]);
          if (p < 0 || p > 32) continue;
          const { int: ipInt } = parseIPv4Strict(ip);
          const maskInt = ipv4MaskFromPrefix(p);
          const netInt = ipInt & maskInt;
          const hostBits = 32 - p;
          const endInt = netInt + ((1n << BigInt(hostBits)) - 1n);
          out.push({
            prefixLen: p,
            startInt: netInt,
            endInt,
            org: item.org || "",
            region: item.region || "",
            asn: item.asn || "",
          });
        } catch {
          // ignore bad record
        }
      }
      return out;
    };

    geoDbNormalized = normalize(geoDbRaw);
  };

  const lookupGeo = (ipStr) => {
    if (!Array.isArray(geoDbNormalized) || geoDbNormalized.length === 0) return null;
    const { int: ipInt } = parseIPv4Strict(ipStr);
    let best = null;
    for (const rec of geoDbNormalized) {
      if (ipInt >= rec.startInt && ipInt <= rec.endInt) {
        if (!best || rec.prefixLen > best.prefixLen) best = rec;
      }
    }
    return best;
  };

  const pushHistory = (record) => {
    const rec = { ...record, id: record.id || String(Date.now()) + "_" + Math.random().toString(16).slice(2) };
    // 只存储可 JSON 序列化的数据（BigInt 转字符串）
    const storeRec = JSON.parse(safeStringify(rec));
    historyRecords = [storeRec, ...historyRecords].slice(0, MAX_HISTORY);
    lastRecord = storeRec;
    selectedHistoryId = storeRec.id;
    saveHistory();
    renderHistory();
  };

  const setHelpContent = () => {
    const body = $("helpBody");
    if (!body) return;
    body.innerHTML = `
      <div class="help-doc">
        <div class="help-lead">子网计算工具（离线）使用教程</div>
        <div class="help-block">使用本工具前请阅读页眉下方的<strong>免责声明</strong>；群 Ping、端口扫描等探测仅可在已授权环境中进行。</div>
        <div>1）IPv4/IPv6 核心计算：输入地址与掩码（前缀），点击「计算」。输出为网络地址/广播/可用主机范围等。</div>
        <div>2）等长子网：输入父网段与子网数量，可预览后生成。网关建议使用首/尾可用主机地址。</div>
        <div>3）IPv4 VLSM：输入父网段与多个子网需求，选择分配策略后生成拓扑清单。</div>
        <div>4）IPv6 子网规划：按地址需求做 VLSM，或使用等长划分；输出子网前缀与地址范围。</div>
        <div>5）地址验证/归属查询：判断地址类型（公网/私网、A/B/C/D/E、环回/链路本地等）。归属查询可加载离线 JSON 前缀库。</div>
        <div>6）端口扫描（Electron）：与群 Ping 相同的 IPv4 网段输入，指定端口后做轻量 TCP 连接探测；可选先 Ping 仅扫可达主机。</div>
        <div>7）路由追踪（Electron）：对 IP/域名执行系统 tracert/traceroute；可停止；类 Unix 可暂停/继续；完成提示为右下角通知（可点进主窗口）。Windows 输出按 GBK 解码减少乱码。</div>
        <div>8）本机网络（Electron）：顶部「本机网络」弹窗；10 分钟内重复打开使用缓存；复制成功为顶部轻提示（约 1.5 秒）。</div>
        <div>9）快捷键：Ctrl+Enter 当前标签主操作；Ctrl+S 弹出<strong>导出格式三选一</strong>（CSV/TXT/Excel）；Ctrl+F 全局搜索；历史记录最多 200 条，可导出/导入 JSON。</div>
        <div>10）双栏卡片之间出现竖条时可<strong>拖拽</strong>调整左右宽度（窄屏自动变为上下堆叠）。</div>
        <div class="help-faq-title">公式说明与示例演算</div>
        <div class="help-block"><strong>IPv4 网络地址</strong>：network = IP ∧ mask（按 32 位按位与）。例：192.168.1.100/24 → mask=255.255.255.0 → 网络 192.168.1.0。</div>
        <div class="help-block"><strong>广播地址</strong>：broadcast = network | (~mask)（主机位全 1）。同上例 → 192.168.1.255。</div>
        <div class="help-block"><strong>可用主机数（常规）</strong>：usable = 2^(32−p) − 2（p 为前缀长度；/31、/32 等特例工具内单独处理）。例：/24 → 2^8−2=254 台主机。</div>
        <div class="help-block"><strong>CIDR 与掩码</strong>：前缀 p 对应掩码左侧 p 个二进制 1。例：/26 → 255.255.255.192（最后一段 11000000₂=192）。</div>
        <div class="help-block"><strong>等长子网划分</strong>：新前缀 p′ = p + ⌈log2(N)⌉，N 为子网个数。例：父 /24 划 4 个子网 → log2(4)=2 → 子网 /26。</div>
        <div class="help-block"><strong>IPv6 接口 ID</strong>：通常后 64 位为接口标识；可 SLAAC / 手动规划；工具按前缀长度给出地址范围与主机位说明。</div>
        <div class="help-block"><strong>VLSM 思路</strong>：按需求从大到小（或按策略）在父块内取 2 的幂对齐子块，避免重叠并尽量减少碎片。</div>
        <div class="help-faq-title">智能纠错说明</div>
        <div class="help-block">IPv4 四段式输入若某段 &gt;255，界面会提示建议写成各段≤255 的地址；掩码若非「连续 1」，会提示替换为最近的标准掩码（如 255.255.255.1 → 建议合法邻近掩码）。整段 CIDR 输入框同样会给出简要建议。</div>
        <div class="help-faq-title">FAQ</div>
        <div>Q：为什么显示「超出父网段」？A：通常是地址块对齐/分配顺序导致无法形成连续 CIDR 块。可尝试切换策略。</div>
        <div>Q：Excel 导出是什么格式？A：当前使用 HTML-Excel 方式生成，Excel 会自动打开并保持表格结构。</div>
        <div>Q：历史导入会覆盖吗？A：默认与现有记录<strong>合并</strong>（新导入在前），总量仍不超过 200 条。</div>
      </div>
    `;
  };

  const initMenus = () => {
    const menuExportCsv = $("menuExportCsv");
    const menuExportTxt = $("menuExportTxt");
    const menuExportExcel = $("menuExportExcel");
    const menuHelpBtn = $("menuHelpBtn");
    const helpModal = $("helpModal");
    const helpCloseBtn = $("helpCloseBtn");

    if (menuHelpBtn && helpModal) {
      menuHelpBtn.addEventListener("click", () => {
        setHelpContent();
        helpModal.style.display = "flex";
      });
    }
    if (helpCloseBtn && helpModal) {
      helpCloseBtn.addEventListener("click", () => {
        helpModal.style.display = "none";
      });
    }

    const exportFromRecord = (record, format) => {
      const title = record.title || record.type || "export";
      // 使用 record.outputData（尽量存可序列化的原始结果）生成表格
      if (!record.outputData) {
        alert("该记录没有可导出的结构化数据。");
        return;
      }

      if (format === "txt") {
        const lines = [];
        lines.push(`${title}`);
        lines.push(`时间：${new Date(record.createdAt).toLocaleString()}`);
        lines.push(`类型：${record.type}`);
        lines.push("");
        lines.push(record.exportText || "");
        downloadText(`${title}.txt`, lines.join("\n"), "text/plain;charset=utf-8");
        return;
      }

      if (format === "csv") {
        downloadText(`${title}.csv`, record.exportCsv || "", "text/csv;charset=utf-8");
        return;
      }

      // excel：用 HTML 表格让 Excel 直接打开
      if (format === "excel") {
        const html = record.exportExcelHtml || `<table><tr><td>${escapeHtml(safeStringify(record.outputData).slice(0, 1000))}</td></tr></table>`;
        downloadText(`${title}.xls`, html, "application/vnd.ms-excel;charset=utf-8");
        return;
      }
    };

    const doExport = (format) => {
      if (!lastRecord) {
        alert("当前没有可导出的计算记录。");
        return;
      }
      exportFromRecord(lastRecord, format);
    };

    if (menuExportCsv) menuExportCsv.addEventListener("click", () => doExport("csv"));
    if (menuExportTxt) menuExportTxt.addEventListener("click", () => doExport("txt"));
    if (menuExportExcel) menuExportExcel.addEventListener("click", () => doExport("excel"));

    const closeQuickExport = () => {
      const m = $("quickExportModal");
      if (m) m.style.display = "none";
    };
    const openQuickExport = () => {
      if (!lastRecord) {
        alert("当前没有可导出的计算记录。");
        return;
      }
      const m = $("quickExportModal");
      if (m) m.style.display = "flex";
    };
    const qm = $("quickExportModal");
    if (qm) {
      qm.addEventListener("click", (e) => {
        if (e.target === qm) closeQuickExport();
      });
    }
    $("quickExportClose")?.addEventListener("click", closeQuickExport);
    $("quickExportCsv")?.addEventListener("click", () => {
      doExport("csv");
      closeQuickExport();
    });
    $("quickExportTxt")?.addEventListener("click", () => {
      doExport("txt");
      closeQuickExport();
    });
    $("quickExportExcelPick")?.addEventListener("click", () => {
      doExport("excel");
      closeQuickExport();
    });
    window.__subnetOpenQuickExport = openQuickExport;
  };

  // 菜单初始化
  initMenus();

  let lastLocalNetPayload = null;
  let localNetFetchedAt = 0;
  const LOCAL_NET_CACHE_MS = 10 * 60 * 1000;

  const noticeModalClose = $("noticeModalClose");
  if (noticeModalClose) noticeModalClose.addEventListener("click", hideNoticeModal);
  const noticeModalEl = $("noticeModal");
  if (noticeModalEl) {
    noticeModalEl.addEventListener("click", (e) => {
      if (e.target === noticeModalEl) hideNoticeModal();
    });
  }

  async function loadLocalNetIntoModal(forceRefresh = false) {
    const body = $("localNetModalBody");
    if (!body) return;
    if (!window.subnetNative || typeof window.subnetNative.getLocalNetworkInfo !== "function") {
      body.innerHTML = `<div class="hint">当前为浏览器环境，无法读取系统网卡。请使用 Electron 桌面版打开本工具。</div>`;
      lastLocalNetPayload = null;
      localNetFetchedAt = 0;
      return;
    }
    const cacheValid =
      !forceRefresh &&
      lastLocalNetPayload &&
      localNetFetchedAt > 0 &&
      Date.now() - localNetFetchedAt < LOCAL_NET_CACHE_MS;
    if (cacheValid) {
      const prefix = `lnm${Date.now()}`;
      body.innerHTML = `<div class="hint" style="margin-bottom:10px;">以下为缓存数据（10 分钟内有效），点击「重新获取」可立即刷新。</div>${renderLocalNetworkHtml(lastLocalNetPayload, prefix)}`;
      return;
    }
    body.innerHTML = `<div class="hint">正在读取本机网络信息…</div>`;
    try {
      const data = await window.subnetNative.getLocalNetworkInfo();
      lastLocalNetPayload = data && typeof data === "object" ? data : null;
      localNetFetchedAt = Date.now();
      const prefix = `lnm${Date.now()}`;
      body.innerHTML = renderLocalNetworkHtml(lastLocalNetPayload, prefix);
    } catch (e) {
      lastLocalNetPayload = null;
      localNetFetchedAt = 0;
      body.innerHTML = `<div class="error" style="margin:0;">${escapeHtml(e instanceof Error ? e.message : String(e))}</div>`;
    }
  }

  function openLocalNetModal() {
    const modal = $("localNetModal");
    if (!modal) return;
    modal.style.display = "flex";
    loadLocalNetIntoModal(false);
  }

  const menuLocalNetBtn = $("menuLocalNetBtn");
  if (menuLocalNetBtn) menuLocalNetBtn.addEventListener("click", () => openLocalNetModal());

  const localNetModal = $("localNetModal");
  const localNetModalClose = $("localNetModalClose");
  const localNetModalCopyAll = $("localNetModalCopyAll");
  const localNetModalRefresh = $("localNetModalRefresh");
  if (localNetModalClose && localNetModal) {
    localNetModalClose.addEventListener("click", () => {
      localNetModal.style.display = "none";
    });
  }
  if (localNetModalRefresh) {
    localNetModalRefresh.addEventListener("click", () => loadLocalNetIntoModal(true));
  }
  if (localNetModalCopyAll) {
    localNetModalCopyAll.addEventListener("click", async () => {
      try {
        if (!lastLocalNetPayload) {
          showToast("暂无可复制内容，请等待加载完成。", "err");
          return;
        }
        await copyTextToClipboard(formatLocalNetworkPlain(lastLocalNetPayload));
        showToast("已复制到剪贴板");
      } catch (e) {
        showToast(e instanceof Error ? e.message : String(e), "err");
      }
    });
  }
  if (localNetModal) {
    localNetModal.addEventListener("click", async (e) => {
      if (e.target === localNetModal) {
        localNetModal.style.display = "none";
        return;
      }
      const copyOne = e.target.closest("[data-ln-copy]");
      if (copyOne) {
        const id = copyOne.getAttribute("data-ln-copy");
        const el = id ? document.getElementById(id) : null;
        try {
          if (el) {
            await copyTextToClipboard(el.textContent || "");
            showToast("已复制到剪贴板");
          }
        } catch (err) {
          showToast(err instanceof Error ? err.message : String(err), "err");
        }
        return;
      }
      const copyCard = e.target.closest("[data-ln-copy-card]");
      if (!copyCard) return;
      const card = copyCard.closest(".localnet-card");
      if (!card) return;
      try {
        const bits = [];
        card.querySelectorAll(".localnet-v").forEach((node) => bits.push(node.textContent || ""));
        await copyTextToClipboard(bits.join("\n"));
        showToast("已复制到剪贴板");
      } catch (err) {
        showToast(err instanceof Error ? err.message : String(err), "err");
      }
    });
  }

  // 历史渲染与点击事件
  historyRecords = loadHistory();
  renderHistory();
  const historyClearBtn = $("historyClearBtn");
  if (historyClearBtn) {
    historyClearBtn.addEventListener("click", () => {
      if (!confirm("确定清空历史记录吗？")) return;
      historyRecords = [];
      lastRecord = null;
      selectedHistoryId = null;
      saveHistory();
      renderHistory();
    });
  }

  $("historyExportBtn")?.addEventListener("click", () => {
    try {
      const json = safeStringify(historyRecords);
      downloadText(`subnet_history_${Date.now()}.json`, json, "application/json;charset=utf-8");
    } catch (e) {
      alert(e instanceof Error ? e.message : String(e));
    }
  });
  const historyImportFile = $("historyImportFile");
  $("historyImportBtn")?.addEventListener("click", () => {
    if (historyImportFile) historyImportFile.click();
  });
  if (historyImportFile) {
    historyImportFile.addEventListener("change", async (ev) => {
      const f = ev.target.files && ev.target.files[0];
      ev.target.value = "";
      if (!f) return;
      try {
        const text = await f.text();
        const arr = JSON.parse(text);
        if (!Array.isArray(arr)) throw new Error("文件内容应为 JSON 数组。");
        if (!confirm(`将导入 ${arr.length} 条记录并与现有历史合并（合计最多 ${MAX_HISTORY} 条），确定？`)) return;
        const merged = [...arr, ...historyRecords].filter((x) => x && typeof x === "object");
        historyRecords = merged.slice(0, MAX_HISTORY);
        lastRecord = historyRecords[0] || null;
        selectedHistoryId = lastRecord ? lastRecord.id : null;
        saveHistory();
        renderHistory();
      } catch (e) {
        alert(e instanceof Error ? e.message : String(e));
      }
    });
  }

  const historyList = $("historyList");
  if (historyList) {
    historyList.addEventListener("click", (e) => {
      const btn = e.target.closest("button[data-act]");
      if (!btn) return;
      const act = btn.getAttribute("data-act");
      const id = btn.getAttribute("data-id");
      const rec = historyRecords.find((x) => x.id === id);
      if (!rec) return;
      if (act === "del") {
        historyRecords = historyRecords.filter((x) => x.id !== id);
        if (selectedHistoryId === id) selectedHistoryId = null;
        saveHistory();
        renderHistory();
        return;
      }
      if (act === "reuse") {
        selectedHistoryId = id;
        lastRecord = rec;
        // 直接复用展示
        if (rec.tabId && rec.outputTargetId && rec.outputHtml) {
          document.querySelectorAll(".tab-panel").forEach((p) => p.classList.remove("is-active"));
          document.querySelectorAll(".tab-button").forEach((b) => b.classList.remove("is-active"));
          const btnTab = document.querySelector(`.tab-button[data-tab="${rec.tabId}"]`);
          if (btnTab) btnTab.classList.add("is-active");
          $(rec.tabId).classList.add("is-active");
          $(rec.outputTargetId).innerHTML = rec.outputHtml;
        }
        saveHistory();
        renderHistory();
      }
    });
  }

  // 可选：初始化归属库
  ensureGeoDbNormalized();

  // ---------- 地址验证/归属查询 ----------
  const addrOct1 = $("addrOct1");
  const addrOct2 = $("addrOct2");
  const addrOct3 = $("addrOct3");
  const addrOct4 = $("addrOct4");
  const addrTypeBtn = $("addrTypeBtn");
  const addrGeoBtn = $("addrGeoBtn");
  const addrValidateError = $("addrValidateError");
  const addrOutput = $("addrOutput");
  const geoDbFile = $("geoDbFile");

  const sanitizeOctet = (el) => {
    const digits = String(el.value || "").replace(/\D/g, "").slice(0, 3);
    if (!digits) return "";
    const n = Math.min(255, Number(digits));
    return String(n);
  };

  const getAddrIp = () => {
    const o1 = sanitizeOctet(addrOct1);
    const o2 = sanitizeOctet(addrOct2);
    const o3 = sanitizeOctet(addrOct3);
    const o4 = sanitizeOctet(addrOct4);
    return [o1, o2, o3, o4].join(".");
  };

  const getAddrOctHint = (inp) => inp?.closest(".oct-with-hint")?.querySelector(".oct-smart-hint");
  const addrOctEls = [addrOct1, addrOct2, addrOct3, addrOct4].filter(Boolean);
  const clearAddrOctHints = () => {
    addrOctEls.forEach((o) => {
      const h = getAddrOctHint(o);
      if (h) h.textContent = "";
      o.classList.remove(INPUT_INVALID_FLASH_CLS);
    });
  };
  const refreshAddrOctHints = (editedIdx = -1, editedRaw = null) => {
    addrOctEls.forEach((cel, i) => {
      const rawDigits = String(cel.value || "").replace(/\D/g, "").slice(0, 3);
      let rawNum = rawDigits === "" ? null : Number(rawDigits);
      if (i === editedIdx && editedRaw != null) rawNum = editedRaw;
      const h = getAddrOctHint(cel);
      if (rawNum != null && rawNum > 255) {
        const oth = addrOctEls.map((o, j) => (j === i ? "255" : sanitizeOctet(o)));
        if (h) h.textContent = `智能提示：第 ${i + 1} 段超出 0-255（${rawNum}），显示已截断为 255；建议地址 ${oth.join(".")}`;
        cel.classList.add(INPUT_INVALID_FLASH_CLS);
      } else {
        if (h) h.textContent = "";
        cel.classList.remove(INPUT_INVALID_FLASH_CLS);
      }
    });
  };
  addrOctEls.forEach((el, idx) => {
    el.addEventListener("input", () => {
      const rawDigits = String(el.value || "").replace(/\D/g, "").slice(0, 3);
      const editedRaw = rawDigits === "" ? null : Number(rawDigits);
      el.value = rawDigits === "" ? "" : String(Math.min(255, Number(rawDigits)));
      refreshAddrOctHints(idx, editedRaw);
    });
  });

  const renderAddrType = (ipStr) => {
    const cls = detectIPv4Class(ipStr);
    const type = detectIPv4AddressType(ipStr);
    const privateHint = type.includes("私网") ? "私网/保留范围" : "可能为公网";
    return `
      <div class="section-title">地址类型判断</div>
      <table>
        <tr><th>输入 IP</th><td><span class="hl">${escapeHtml(ipStr)}</span></td></tr>
        <tr><th>地址类别（A/B/C/D/E）</th><td><span class="hl">${escapeHtml(cls)}</span></td></tr>
        <tr><th>地址类型（用途/范围）</th><td>${escapeHtml(type)}</td></tr>
        <tr><th>归类提示</th><td>${escapeHtml(privateHint)}</td></tr>
      </table>
    `;
  };

  if (addrTypeBtn) {
    addrTypeBtn.addEventListener("click", () => {
      try {
        clearError(addrValidateError);
        clearAddrOctHints();
        const ipStr = getAddrIp();
        if (!ipStr || ipStr.includes("..")) throw new Error("请先完整输入 IPv4 四段地址。");
        // 触发严格解析（用于校验）
        parseIPv4Strict(ipStr);
        addrOutput.innerHTML = renderAddrType(ipStr);
      } catch (e) {
        showError(addrValidateError, e);
        addrOutput.innerHTML = "";
      }
    });
  }

  if (addrGeoBtn) {
    addrGeoBtn.addEventListener("click", () => {
      try {
        clearError(addrValidateError);
        clearAddrOctHints();
        const ipStr = getAddrIp();
        if (!ipStr || ipStr.includes("..")) throw new Error("请先完整输入 IPv4 四段地址。");
        parseIPv4Strict(ipStr);

        const type = detectIPv4AddressType(ipStr);
        const isPrivate = type.includes("私网") || type.includes("环回") || type.includes("链路本地") || type.includes("保留") || type.includes("受限广播") || type.includes("组播");
        let geoHtml = "";
        if (isPrivate) {
          geoHtml = `<div class="hint">该 IP 属于保留/私网/特殊地址，归属查询通常不适用。</div>`;
        } else {
          const hit = lookupGeo(ipStr);
          if (!hit) {
            geoHtml = `<div class="hint">未命中离线归属库（当前未加载或前缀覆盖不足）。</div>`;
          } else {
            geoHtml = `
              <div class="section-title">归属查询结果（离线前缀匹配）</div>
              <table>
                <tr><th>运营商/组织</th><td><span class="hl">${escapeHtml(hit.org || "未知")}</span></td></tr>
                <tr><th>地域</th><td>${escapeHtml(hit.region || "未知")}</td></tr>
                <tr><th>ASN</th><td>${escapeHtml(hit.asn || "未知")}</td></tr>
                <tr><th>匹配前缀</th><td><span class="hl">/${hit.prefixLen}</span></td></tr>
              </table>
            `;
          }
        }

        addrOutput.innerHTML = `${renderAddrType(ipStr)}${geoHtml}`;
      } catch (e) {
        showError(addrValidateError, e);
        addrOutput.innerHTML = "";
      }
    });
  }

  if (geoDbFile) {
    geoDbFile.addEventListener("change", async () => {
      try {
        const file = geoDbFile.files && geoDbFile.files[0];
        if (!file) return;
        const text = await new Promise((resolve, reject) => {
          const fr = new FileReader();
          fr.onload = () => resolve(String(fr.result || ""));
          fr.onerror = () => reject(fr.error || new Error("读取失败"));
          fr.readAsText(file);
        });
        const parsed = JSON.parse(text);
        geoDbRaw = parsed;
        ensureGeoDbNormalized();
        addrOutput.innerHTML = `<div class="hint" style="margin-top:0;">已加载离线归属库：${Array.isArray(parsed) ? parsed.length : 0} 条。</div>`;
      } catch (e) {
        showError(addrValidateError, e);
      } finally {
        geoDbFile.value = "";
      }
    });
  }

  // ---------- 导出/历史记录：结构化导出帮助函数 ----------
  const csvEscape = (v) => {
    const s = String(v ?? "");
    if (s.includes('"') || s.includes(",") || s.includes("\n") || s.includes("\r")) return `"${s.replaceAll('"', '""')}"`;
    return s;
  };

  const buildExcelHtml = (headers, rows) => {
    const head = headers.map((h) => `<th>${escapeHtml(h)}</th>`).join("");
    const body = rows
      .map((row) => `<tr>${row.map((c) => `<td>${escapeHtml(c)}</td>`).join("")}</tr>`)
      .join("");
    return `
      <html>
        <head><meta charset="utf-8" /></head>
        <body>
          <table border="1" cellspacing="0" cellpadding="3">
            <tr>${head}</tr>
            ${body}
          </table>
        </body>
      </html>
    `;
  };

  const buildIpv4CoreExport = (res) => {
    const headers = ["参数", "值"];
    const rows = [
      ["网络地址", res.network],
      ["掩码（点分十进制）", res.netmask],
      ["CIDR 前缀", `/${res.prefixLen}`],
      ["广播地址", res.broadcast],
      ["首个可用主机", res.firstUsable],
      ["最后可用主机", res.lastUsable],
      ["可用主机数", String(res.usableCount)],
      ["地址类别", res.addrClass],
      ["地址类型", res.addrType],
      ["利用率", pct(res.utilization)],
    ];
    const txt = rows.map((r) => `${r[0]}：${r[1]}`).join("\n");
    const csv = [headers.map(csvEscape).join(","), ...rows.map((r) => r.map(csvEscape).join(","))].join("\n");
    return { exportText: txt, exportCsv: csv, exportExcelHtml: buildExcelHtml(headers, rows) };
  };

  const buildVlsmExport = (res) => {
    const headers = [
      "子网名称",
      "需求主机数",
      "推荐前缀",
      "网段",
      "掩码",
      "建议网关",
      "备选网关",
      "地址范围",
      "广播",
      "可用主机数",
    ];
    const rows = res.allocations
      .slice()
      .sort((a, b) => (a.interval.start < b.interval.start ? -1 : 1))
      .map((s) => [
        s.name,
        String(s.hostsNeed),
        `/${s.prefixLen}`,
        `${s.network}/${s.prefixLen}`,
        s.netmask,
        s.firstUsable,
        s.lastUsable,
        `${s.firstUsable} - ${s.lastUsable}`,
        s.broadcast,
        String(s.usableCount),
      ]);
    const txtLines = [];
    txtLines.push(`父网段：${res.parent}`);
    txtLines.push(`策略：${res.strategy}`);
    txtLines.push(`地址利用率：${pct(res.utilization)}`);
    txtLines.push("");
    txtLines.push(rows.map((r) => r.join(" | ")).join("\n"));
    const csv = [headers.map(csvEscape).join(","), ...rows.map((r) => r.map(csvEscape).join(","))].join("\n");
    return { exportText: txtLines.join("\n"), exportCsv: csv, exportExcelHtml: buildExcelHtml(headers, rows) };
  };

  const buildEqualExport = (res) => {
    const headers = [
      "子网编号",
      "网段",
      "掩码",
      "建议网关",
      "备选网关",
      "地址范围",
      "广播",
      "可用主机数",
    ];
    const rows = res.subnets.map((s) => [
      String(s.subnetIndex),
      `${s.network}/${s.prefixLen}`,
      s.netmask,
      s.firstUsable,
      s.lastUsable,
      `${s.firstUsable} - ${s.lastUsable}`,
      s.broadcast,
      String(s.usableCount),
    ]);
    const txt = rows.map((r) => r.join(" | ")).join("\n");
    const csv = [headers.map(csvEscape).join(","), ...rows.map((r) => r.map(csvEscape).join(","))].join("\n");
    return { exportText: txt, exportCsv: csv, exportExcelHtml: buildExcelHtml(headers, rows) };
  };

  const buildIpv6CoreExport = (res) => {
    const headers = ["参数", "值"];
    const rows = [
      ["输入地址", res.address],
      ["网络前缀", res.networkPrefix],
      ["接口 ID", res.interfaceId],
      ["地址类型", res.addressType],
      ["前缀范围起始", res.prefixRange.first],
      ["前缀范围结束", res.prefixRange.last],
    ];
    const txt = rows.map((r) => `${r[0]}：${r[1]}`).join("\n");
    const csv = [headers.map(csvEscape).join(","), ...rows.map((r) => r.map(csvEscape).join(","))].join("\n");
    return { exportText: txt, exportCsv: csv, exportExcelHtml: buildExcelHtml(headers, rows) };
  };

  // ---------- 可视化 IPv4 输入（核心/等长/VLSM/双栈） ----------
  const initIPv4VisualInputs = (configs) => configs.forEach((cfg) => setupIPv4VisualInput(cfg));
  initIPv4VisualInputs([
    {
      oct1: "ipv4Oct1",
      oct2: "ipv4Oct2",
      oct3: "ipv4Oct3",
      oct4: "ipv4Oct4",
      prefixInput: "ipv4PrefixInput",
      maskInput: "ipv4MaskInput",
      outputInput: "ipv4Input",
      prefixSlider: "ipv4PrefixSlider",
      prefixSelect: "ipv4PrefixSelect",
      hostNeedInput: "ipv4HostNeedRecommend",
      hostHint: "ipv4RecommendHint",
      defaultIp: [192, 168, 1, 10],
      defaultPrefix: 24,
    },
    {
      oct1: "equalOct1",
      oct2: "equalOct2",
      oct3: "equalOct3",
      oct4: "equalOct4",
      prefixInput: "equalPrefixInput",
      maskInput: "equalMaskInput",
      outputInput: "equalParent",
      defaultIp: [192, 168, 1, 0],
      defaultPrefix: 24,
    },
    {
      oct1: "vlsmOct1",
      oct2: "vlsmOct2",
      oct3: "vlsmOct3",
      oct4: "vlsmOct4",
      prefixInput: "vlsmPrefixInput",
      maskInput: "vlsmMaskInput",
      outputInput: "vlsmParent",
      defaultIp: [192, 168, 1, 0],
      defaultPrefix: 24,
    },
    {
      oct1: "dualOct1",
      oct2: "dualOct2",
      oct3: "dualOct3",
      oct4: "dualOct4",
      prefixInput: "dualPrefixInput",
      maskInput: "dualMaskInput",
      outputInput: "dualIPv4",
      defaultIp: [192, 168, 1, 0],
      defaultPrefix: 24,
    },
    {
      oct1: "pingOct1",
      oct2: "pingOct2",
      oct3: "pingOct3",
      oct4: "pingOct4",
      prefixInput: "pingPrefixInput",
      maskInput: "pingMaskInput",
      outputInput: "pingInput",
      defaultIp: [192, 168, 1, 0],
      defaultPrefix: 24,
    },
    {
      oct1: "scanOct1",
      oct2: "scanOct2",
      oct3: "scanOct3",
      oct4: "scanOct4",
      prefixInput: "scanPrefixInput",
      maskInput: "scanMaskInput",
      outputInput: "portScanCidr",
      defaultIp: [192, 168, 1, 0],
      defaultPrefix: 24,
    },
  ]);

  // ---------- IPv4 核心计算 ----------
  const ipv4Input = $("ipv4Input");
  const ipv4CalcBtn = $("ipv4CalcBtn");
  const ipv4Output = $("ipv4Output");
  const ipv4Error = $("ipv4Error");
  const ipv4SubtractNB = $("ipv4SubtractNB");
  const ipv4CidrSmartHint = $("ipv4CidrSmartHint");

  // 实时校验（仅校验格式，不自动刷新完整输出）
  let ipv4Timer = null;
  ipv4Input.addEventListener("input", () => {
    clearTimeout(ipv4Timer);
    ipv4Timer = setTimeout(() => {
      try {
        const raw = ipv4Input.value.trim();
        if (!raw) {
          clearError(ipv4Error);
          if (ipv4CidrSmartHint) ipv4CidrSmartHint.textContent = "";
          ipv4Input.classList.remove(INPUT_INVALID_FLASH_CLS);
          return;
        }
        ipv4CoreCompute(raw, { subtractNB: ipv4SubtractNB.checked });
        clearError(ipv4Error);
        if (ipv4CidrSmartHint) ipv4CidrSmartHint.textContent = "";
        ipv4Input.classList.remove(INPUT_INVALID_FLASH_CLS);
      } catch (e) {
        showError(ipv4Error, e);
        if (ipv4CidrSmartHint) {
          const tip = suggestIpv4CidrFreeText(ipv4Input.value.trim());
          ipv4CidrSmartHint.textContent = tip || "";
        }
        ipv4Input.classList.add(INPUT_INVALID_FLASH_CLS);
      }
    }, 250);
  });

  ipv4CalcBtn.addEventListener("click", () => {
    try {
      const raw = ipv4Input.value.trim();
      assertNonEmpty(raw);
      clearError(ipv4Error);
      if (ipv4CidrSmartHint) ipv4CidrSmartHint.textContent = "";
      ipv4Input.classList.remove(INPUT_INVALID_FLASH_CLS);
      const res = ipv4CoreCompute(raw, { subtractNB: ipv4SubtractNB.checked });
      const html = renderOutputBlock(renderIPv4Core(res));
      ipv4Output.innerHTML = html;
      pushHistory({
        type: "ipv4-core",
        title: `IPv4 核心：${raw}`,
        tabId: "tab-ipv4-core",
        outputTargetId: "ipv4Output",
        outputHtml: html,
        createdAt: Date.now(),
        inputs: { cidr: raw, subtractNB: ipv4SubtractNB.checked },
        outputData: res,
        ...buildIpv4CoreExport(res),
      });
    } catch (e) {
      ipv4Output.innerHTML = "";
      showError(ipv4Error, e);
      ipv4Input.classList.add(INPUT_INVALID_FLASH_CLS);
      if (ipv4CidrSmartHint) {
        ipv4CidrSmartHint.textContent = suggestIpv4CidrFreeText(ipv4Input.value.trim()) || "";
      }
    }
  });

  $("ipv4SampleBtn").addEventListener("click", () => {
    $("ipv4Oct1").value = "192";
    $("ipv4Oct2").value = "168";
    $("ipv4Oct3").value = "1";
    $("ipv4Oct4").value = "10";
    $("ipv4PrefixInput").value = "24";
    $("ipv4PrefixInput").dispatchEvent(new Event("input"));
    $("ipv4ReverseMode").value = "hosts";
    $("ipv4ReverseInput").value = "50";
    clearError(ipv4Error);
  });

  function assertNonEmpty(s) {
    if (!s) throw new Error("输入不能为空。");
  }

  // ---------- IPv4 反向计算 ----------
  const ipv4ReverseMode = $("ipv4ReverseMode");
  const ipv4ReverseBtn = $("ipv4ReverseBtn");
  const ipv4ReverseExtraHosts = $("ipv4ReverseExtraHosts");
  const ipv4ReverseExtraSubnets = $("ipv4ReverseExtraSubnets");
  const ipv4ReverseStrategy = $("ipv4ReverseStrategy");
  const ipv4ReverseInput = $("ipv4ReverseInput");
  const ipv4ReverseInput2 = $("ipv4ReverseInput2");

  function updateReverseModeUI() {
    const mode = ipv4ReverseMode.value;
    if (mode === "hosts") {
      ipv4ReverseExtraHosts.style.display = "";
      ipv4ReverseExtraSubnets.style.display = "none";
    } else {
      ipv4ReverseExtraHosts.style.display = "none";
      ipv4ReverseExtraSubnets.style.display = "";
    }
  }
  ipv4ReverseMode.addEventListener("change", updateReverseModeUI);
  updateReverseModeUI();

  ipv4ReverseBtn.addEventListener("click", () => {
    try {
      const parentCIDR = ipv4Input.value.trim();
      assertNonEmpty(parentCIDR);
      clearError(ipv4Error);
      const mode = ipv4ReverseMode.value;
      const strategy = ipv4ReverseStrategy.value;
      const subtractNB = ipv4SubtractNB.checked;

      let result;
      if (mode === "hosts") {
        result = ipv4ReverseCompute(parentCIDR, "hosts", {
          subtractNB,
          strategy,
          desiredHosts: ipv4ReverseInput.value,
        });
      } else {
        result = ipv4ReverseCompute(parentCIDR, "subnets", {
          subtractNB,
          strategy,
          desiredSubnets: ipv4ReverseInput2.value,
        });
      }
      const html = renderOutputBlock(renderIPv4Reverse(result));
      ipv4Output.innerHTML = html;
      const exportText = safeStringify(result);
      pushHistory({
        type: "ipv4-reverse",
        title: `IPv4 反向：${parentCIDR} / ${mode === "hosts" ? ipv4ReverseInput.value : ipv4ReverseInput2.value}`,
        tabId: "tab-ipv4-core",
        outputTargetId: "ipv4Output",
        outputHtml: html,
        createdAt: Date.now(),
        inputs: { parentCIDR, mode, strategy, subtractNB },
        outputData: result,
        exportText,
        exportCsv: "",
        exportExcelHtml: "",
      });
    } catch (e) {
      showError(ipv4Error, e);
    }
  });

  // ---------- IPv6 ----------
  const ipv6Input = $("ipv6Input");
  const ipv6PrefixInput = $("ipv6PrefixInput");
  const ipv6CalcBtn = $("ipv6CalcBtn");
  const ipv6Output = $("ipv6Output");
  const ipv6Error = $("ipv6Error");
  const ipv6ShowExpanded = $("ipv6ShowExpanded");
  const ipv6AddrSmartHint = $("ipv6AddrSmartHint");
  const ipv6PrefixSmartHint = $("ipv6PrefixSmartHint");
  const ipv6PrefixSlider = $("ipv6PrefixSlider");
  const ipv6PrefixSelect = $("ipv6PrefixSelect");

  const syncIPv6Prefix = (v) => {
    const p = Math.max(0, Math.min(128, Number(v)));
    ipv6PrefixInput.value = String(p);
    if (ipv6PrefixSlider) ipv6PrefixSlider.value = String(p);
    if (ipv6PrefixSelect) ipv6PrefixSelect.value = String(p);
  };

  let ipv6LiveTimer = null;
  function runIpv6LiveValidate() {
    clearTimeout(ipv6LiveTimer);
    ipv6LiveTimer = setTimeout(() => {
      const raw = ipv6Input.value.trim();
      const pStr = String(ipv6PrefixInput.value ?? "").trim();
      const tipA = raw ? suggestIpv6AddrHint(raw) : "";
      const tipP = suggestIpv6PrefixHint(pStr);
      if (ipv6AddrSmartHint) ipv6AddrSmartHint.textContent = tipA;
      if (ipv6PrefixSmartHint) ipv6PrefixSmartHint.textContent = tipP;

      if (!raw && !pStr) {
        clearError(ipv6Error);
        ipv6Input.classList.remove(INPUT_INVALID_FLASH_CLS);
        ipv6PrefixInput.classList.remove(INPUT_INVALID_FLASH_CLS);
        return;
      }
      if (!raw) {
        clearError(ipv6Error);
        ipv6Input.classList.remove(INPUT_INVALID_FLASH_CLS);
        ipv6PrefixInput.classList.toggle(INPUT_INVALID_FLASH_CLS, Boolean(tipP));
        return;
      }
      try {
        const p = Number(pStr);
        if (!Number.isFinite(p)) throw new Error("前缀长度无效。");
        ipv6CoreCompute(raw, p, { showExpanded: ipv6ShowExpanded.checked });
        clearError(ipv6Error);
        ipv6Input.classList.remove(INPUT_INVALID_FLASH_CLS);
        ipv6PrefixInput.classList.remove(INPUT_INVALID_FLASH_CLS);
      } catch (e) {
        showError(ipv6Error, e);
        if (tipA || tipP) {
          ipv6Input.classList.toggle(INPUT_INVALID_FLASH_CLS, Boolean(tipA));
          ipv6PrefixInput.classList.toggle(INPUT_INVALID_FLASH_CLS, Boolean(tipP));
        } else {
          ipv6Input.classList.add(INPUT_INVALID_FLASH_CLS);
          ipv6PrefixInput.classList.add(INPUT_INVALID_FLASH_CLS);
        }
      }
    }, 220);
  }

  if (ipv6PrefixSlider) {
    ipv6PrefixSlider.addEventListener("input", () => {
      syncIPv6Prefix(ipv6PrefixSlider.value);
      runIpv6LiveValidate();
    });
  }
  if (ipv6PrefixSelect) {
    ipv6PrefixSelect.addEventListener("change", () => {
      syncIPv6Prefix(ipv6PrefixSelect.value);
      runIpv6LiveValidate();
    });
  }
  ipv6PrefixInput.addEventListener("input", () => {
    syncIPv6Prefix(ipv6PrefixInput.value);
    runIpv6LiveValidate();
  });
  ipv6Input.addEventListener("input", runIpv6LiveValidate);
  if (ipv6ShowExpanded) ipv6ShowExpanded.addEventListener("change", runIpv6LiveValidate);
  syncIPv6Prefix(ipv6PrefixInput.value || 64);
  runIpv6LiveValidate();

  $("ipv6SampleBtn").addEventListener("click", () => {
    ipv6Input.value = "2001:db8::1";
    ipv6PrefixInput.value = "64";
    syncIPv6Prefix(64);
    clearError(ipv6Error);
    if (ipv6AddrSmartHint) ipv6AddrSmartHint.textContent = "";
    if (ipv6PrefixSmartHint) ipv6PrefixSmartHint.textContent = "";
    ipv6Input.classList.remove(INPUT_INVALID_FLASH_CLS);
    ipv6PrefixInput.classList.remove(INPUT_INVALID_FLASH_CLS);
    runIpv6LiveValidate();
  });

  ipv6CalcBtn.addEventListener("click", () => {
    try {
      const raw = ipv6Input.value.trim();
      assertNonEmpty(raw);
      const p = Number(ipv6PrefixInput.value);
      clearError(ipv6Error);
      if (ipv6AddrSmartHint) ipv6AddrSmartHint.textContent = "";
      if (ipv6PrefixSmartHint) ipv6PrefixSmartHint.textContent = "";
      ipv6Input.classList.remove(INPUT_INVALID_FLASH_CLS);
      ipv6PrefixInput.classList.remove(INPUT_INVALID_FLASH_CLS);
      const res = ipv6CoreCompute(raw, p, { showExpanded: ipv6ShowExpanded.checked });

      const expanded = `
        <div class="section-title">地址格式</div>
        <table>
          <tr><th>输入（${res.prefixLen ? "/" + res.prefixLen : ""}）</th><td>${escapeHtml(res.address)}</td></tr>
          <tr><th>展开形式</th><td>${escapeHtml(res.addressExpanded)}</td></tr>
          <tr><th>压缩形式</th><td>${escapeHtml(res.addressCompressed)}</td></tr>
        </table>
      `;

      const body = `
        <div class="section-title">核心计算</div>
        <table>
          <tr><th>网络前缀</th><td><span class="hl">${escapeHtml(res.networkPrefix)}</span></td></tr>
          <tr><th>接口 ID（去掉前缀位后）</th><td>${escapeHtml(res.interfaceId)}</td></tr>
          <tr><th>地址类型</th><td>${escapeHtml(res.addressType)}</td></tr>
        </table>
        <div class="section-title">前缀范围（该前缀下的地址空间）</div>
        <table>
          <tr><th>起始地址</th><td>${escapeHtml(res.prefixRange.first)}</td></tr>
          <tr><th>结束地址</th><td>${escapeHtml(res.prefixRange.last)}</td></tr>
        </table>
      `;

      const html = expanded + body;
      ipv6Output.innerHTML = html;
      pushHistory({
        type: "ipv6-core",
        title: `IPv6 计算：${raw}/${p}`,
        tabId: "tab-ipv6-core",
        outputTargetId: "ipv6Output",
        outputHtml: html,
        createdAt: Date.now(),
        inputs: { addr: raw, prefixLen: p, showExpanded: ipv6ShowExpanded.checked },
        outputData: res,
        ...buildIpv6CoreExport(res),
      });
    } catch (e) {
      ipv6Output.innerHTML = "";
      showError(ipv6Error, e);
      const pStr = String(ipv6PrefixInput.value ?? "").trim();
      if (ipv6AddrSmartHint) ipv6AddrSmartHint.textContent = suggestIpv6AddrHint(ipv6Input.value.trim());
      if (ipv6PrefixSmartHint) ipv6PrefixSmartHint.textContent = suggestIpv6PrefixHint(pStr);
      ipv6Input.classList.add(INPUT_INVALID_FLASH_CLS);
      ipv6PrefixInput.classList.add(INPUT_INVALID_FLASH_CLS);
    }
  });

  // ---------- IPv6 子网规划（VLSM / 等长） ----------
  const ipv6PlanParent = $("ipv6PlanParent");
  const ipv6PlanParentSmartHint = $("ipv6PlanParentSmartHint");
  const ipv6PlanError = $("ipv6PlanError");
  const ipv6VlsmStrategy = $("ipv6VlsmStrategy");
  const ipv6VlsmName = $("ipv6VlsmName");
  const ipv6VlsmInterfaces = $("ipv6VlsmInterfaces");
  const ipv6VlsmAddBtn = $("ipv6VlsmAddBtn");
  const ipv6VlsmPlanBtn = $("ipv6VlsmPlanBtn");
  const ipv6VlsmTableWrap = $("ipv6VlsmTableWrap");
  const ipv6VlsmOutput = $("ipv6VlsmOutput");
  const ipv6EqualCount = $("ipv6EqualCount");
  const ipv6EqualExpanded = $("ipv6EqualExpanded");
  const ipv6EqualGenBtn = $("ipv6EqualGenBtn");
  const ipv6EqualOutput = $("ipv6EqualOutput");

  const ipv6VlsmTable = [];
  let ipv6VlsmEditingIdx = -1;

  let ipv6PlanHintTimer = null;
  function runIpv6PlanParentHint() {
    clearTimeout(ipv6PlanHintTimer);
    ipv6PlanHintTimer = setTimeout(() => {
      const s = (ipv6PlanParent && ipv6PlanParent.value.trim()) || "";
      const tip = s ? suggestIpv6CidrHint(s) : "";
      if (ipv6PlanParentSmartHint) ipv6PlanParentSmartHint.textContent = tip;
      if (ipv6PlanParent) ipv6PlanParent.classList.toggle(INPUT_INVALID_FLASH_CLS, Boolean(tip) && Boolean(s));
    }, 220);
  }
  if (ipv6PlanParent) ipv6PlanParent.addEventListener("input", runIpv6PlanParentHint);
  runIpv6PlanParentHint();

  function syncIpv6VlsmTable() {
    buildIpv6VlsmTable(ipv6VlsmTable);
  }
  if (ipv6VlsmTableWrap) syncIpv6VlsmTable();

  if (ipv6VlsmAddBtn) {
    ipv6VlsmAddBtn.addEventListener("click", () => {
      try {
        clearError(ipv6PlanError);
        const name = (ipv6VlsmName && ipv6VlsmName.value.trim()) || `Subnet-${ipv6VlsmTable.length + 1}`;
        const interfaces = Number(ipv6VlsmInterfaces && ipv6VlsmInterfaces.value);
        if (!Number.isFinite(interfaces) || interfaces < 1) throw new Error("所需地址数须为 >=1 的整数。");
        if (ipv6VlsmEditingIdx >= 0 && ipv6VlsmEditingIdx < ipv6VlsmTable.length) {
          ipv6VlsmTable[ipv6VlsmEditingIdx] = { ...ipv6VlsmTable[ipv6VlsmEditingIdx], name, interfaces };
          ipv6VlsmEditingIdx = -1;
          ipv6VlsmAddBtn.textContent = "添加需求";
        } else {
          ipv6VlsmTable.push({ name, interfaces, note: "" });
        }
        syncIpv6VlsmTable();
        if (ipv6VlsmName) ipv6VlsmName.value = `Subnet-${ipv6VlsmTable.length + 1}`;
        if (ipv6VlsmInterfaces) ipv6VlsmInterfaces.value = "256";
      } catch (e) {
        showError(ipv6PlanError, e);
      }
    });
  }

  if (ipv6VlsmTableWrap) {
    ipv6VlsmTableWrap.addEventListener("click", (e) => {
      const btn = e.target.closest("[data-ipv6vlsm-act]");
      if (!btn) return;
      const act = btn.getAttribute("data-ipv6vlsm-act");
      const idx = Number(btn.getAttribute("data-ipv6vlsm-idx"));
      if (!Number.isFinite(idx)) return;
      if (act === "del") {
        ipv6VlsmTable.splice(idx, 1);
        if (ipv6VlsmEditingIdx === idx) {
          ipv6VlsmEditingIdx = -1;
          if (ipv6VlsmAddBtn) ipv6VlsmAddBtn.textContent = "添加需求";
        } else if (ipv6VlsmEditingIdx > idx) {
          ipv6VlsmEditingIdx -= 1;
        }
        syncIpv6VlsmTable();
      }
      if (act === "edit") {
        const cur = ipv6VlsmTable[idx];
        if (!cur) return;
        ipv6VlsmEditingIdx = idx;
        if (ipv6VlsmName) ipv6VlsmName.value = cur.name;
        if (ipv6VlsmInterfaces) ipv6VlsmInterfaces.value = String(cur.interfaces);
        if (ipv6VlsmAddBtn) ipv6VlsmAddBtn.textContent = "保存修改";
        if (ipv6VlsmName) ipv6VlsmName.focus();
      }
    });
  }

  if (ipv6VlsmPlanBtn) {
    ipv6VlsmPlanBtn.addEventListener("click", () => {
      try {
        clearError(ipv6PlanError);
        if (ipv6VlsmOutput) ipv6VlsmOutput.innerHTML = "";
        const parent = ipv6PlanParent ? ipv6PlanParent.value.trim() : "";
        if (!parent) throw new Error("请先填写父网段 IPv6 CIDR。");
        if (!ipv6VlsmTable.length) throw new Error("请先添加至少一条地址需求。");
        const strat = ipv6VlsmStrategy ? ipv6VlsmStrategy.value : "maxFirst";
        const reqs = ipv6VlsmTable.map((r) => ({ name: r.name, interfaces: r.interfaces, note: r.note || "" }));
        const res = ipv6VlsmPlan(parent, reqs, strat);
        const html = renderIpv6Vlsm(res);
        if (ipv6VlsmOutput) ipv6VlsmOutput.innerHTML = html;
        pushHistory({
          type: "ipv6-vlsm",
          title: `IPv6 VLSM：${parent}`,
          tabId: "tab-ipv6-plan",
          outputTargetId: "ipv6VlsmOutput",
          outputHtml: html,
          createdAt: Date.now(),
          inputs: { parentCIDR: parent, strategy: strat, requests: reqs },
          outputData: res,
          exportText: safeStringify(res),
        });
      } catch (e) {
        showError(ipv6PlanError, e);
      }
    });
  }

  if (ipv6EqualGenBtn) {
    ipv6EqualGenBtn.addEventListener("click", () => {
      try {
        clearError(ipv6PlanError);
        if (ipv6EqualOutput) ipv6EqualOutput.innerHTML = "";
        const parent = ipv6PlanParent ? ipv6PlanParent.value.trim() : "";
        if (!parent) throw new Error("请先填写父网段 IPv6 CIDR。");
        const cnt = Number(ipv6EqualCount && ipv6EqualCount.value);
        if (!Number.isFinite(cnt) || cnt < 1) throw new Error("子网数量须为 >=1 的整数。");
        const showEx = Boolean(ipv6EqualExpanded && ipv6EqualExpanded.checked);
        const res = ipv6SplitEqual(parent, cnt, { showExpanded: showEx });
        const html = renderIpv6EqualSplit(res);
        if (ipv6EqualOutput) ipv6EqualOutput.innerHTML = html;
        pushHistory({
          type: "ipv6-equal",
          title: `IPv6 等长子网：${parent}（${cnt}）`,
          tabId: "tab-ipv6-plan",
          outputTargetId: "ipv6EqualOutput",
          outputHtml: html,
          createdAt: Date.now(),
          inputs: { parentCIDR: parent, subnetCount: cnt, showExpanded: showEx },
          outputData: res,
          exportText: safeStringify(res),
        });
      } catch (e) {
        showError(ipv6PlanError, e);
      }
    });
  }

  // ---------- 等长子网 ----------
  const equalParent = $("equalParent");
  const equalCount = $("equalCount");
  const equalStartNo = $("equalStartNo");
  const equalSubtractNB = $("equalSubtractNB");
  const equalPreviewBtn = $("equalPreviewBtn");
  const equalGenBtn = $("equalGenBtn");
  const equalError = $("equalError");
  const equalOutput = $("equalOutput");
  const equalPreviewHint = $("equalPreviewHint");

  equalPreviewBtn.addEventListener("click", () => {
    try {
      clearError(equalError);
      const res = ipv4SplitEqual(equalParent.value.trim(), equalCount.value, { subtractNB: equalSubtractNB.checked }, { startNo: Number(equalStartNo.value) });
      const hint = `将推荐前缀 /${res.newPrefix}，子网总数 ${res.totalSubnets.toString()}，其中未使用 ${res.unusedSubnets.toString()}。`;
      equalPreviewHint.textContent = hint;
      equalOutput.innerHTML = "";
    } catch (e) {
      showError(equalError, e);
      equalPreviewHint.textContent = "";
    }
  });

  equalGenBtn.addEventListener("click", () => {
    try {
      clearError(equalError);
      const res = ipv4SplitEqual(equalParent.value.trim(), equalCount.value, { subtractNB: equalSubtractNB.checked }, { startNo: Number(equalStartNo.value) });
      equalPreviewHint.textContent = "";
      const html = renderIPv4Equal(res);
      equalOutput.innerHTML = html;
      pushHistory({
        type: "ipv4-equal",
        title: `等长子网：${equalParent.value.trim()}`,
        tabId: "tab-equal",
        outputTargetId: "equalOutput",
        outputHtml: html,
        createdAt: Date.now(),
        inputs: { parentCIDR: equalParent.value.trim(), subnetCount: equalCount.value, startNo: equalStartNo.value, subtractNB: equalSubtractNB.checked },
        outputData: res,
        ...buildEqualExport(res),
      });
    } catch (e) {
      showError(equalError, e);
    }
  });

  // ---------- VLSM ----------
  const vlsmParent = $("vlsmParent");
  const vlsmStrategy = $("vlsmStrategy");
  const vlsmSubtractNB = $("vlsmSubtractNB");
  const vlsmAddBtn = $("vlsmAddBtn");
  const vlsmPlanBtn = $("vlsmPlanBtn");
  const vlsmTableWrap = $("vlsmTableWrap");
  const vlsmOutput = $("vlsmOutput");
  const vlsmError = $("vlsmError");
  const vlsmHint = $("vlsmHint");
  vlsmOutput.classList.add("vlsm-output");

  const vlsmName = $("vlsmName");
  const vlsmHosts = $("vlsmHosts");
  const vlsmTable = [];
  let vlsmEditingIdx = -1;

  function syncVlsmTable() {
    buildVlsmTable(vlsmTable);
  }
  syncVlsmTable();

  vlsmAddBtn.addEventListener("click", () => {
    try {
      clearError(vlsmError);
      const name = vlsmName.value.trim() || `Subnet-${vlsmTable.length + 1}`;
      const hosts = Number(vlsmHosts.value);
      if (!Number.isFinite(hosts) || hosts < 1) throw new Error("期望主机数必须为正整数。");
      if (vlsmEditingIdx >= 0 && vlsmEditingIdx < vlsmTable.length) {
        vlsmTable[vlsmEditingIdx] = { ...vlsmTable[vlsmEditingIdx], name, hosts };
        vlsmEditingIdx = -1;
        vlsmAddBtn.textContent = "添加子网";
      } else {
        vlsmTable.push({ name, hosts, note: "" });
      }
      syncVlsmTable();
      vlsmHint.textContent = "";
      vlsmName.value = `Subnet-${vlsmTable.length + 1}`;
      vlsmHosts.value = "50";
    } catch (e) {
      showError(vlsmError, e);
    }
  });

  vlsmTableWrap.addEventListener("click", (e) => {
    const btn = e.target.closest("button[data-act]");
    if (!btn) return;
    const act = btn.getAttribute("data-act");
    const idx = Number(btn.getAttribute("data-idx"));
    if (!Number.isFinite(idx)) return;

    if (act === "del") {
      vlsmTable.splice(idx, 1);
      if (vlsmEditingIdx === idx) {
        vlsmEditingIdx = -1;
        vlsmAddBtn.textContent = "添加子网";
      } else if (vlsmEditingIdx > idx) {
        vlsmEditingIdx -= 1;
      }
      syncVlsmTable();
    }
    if (act === "edit") {
      const cur = vlsmTable[idx];
      if (!cur) return;
      vlsmEditingIdx = idx;
      vlsmName.value = cur.name;
      vlsmHosts.value = String(cur.hosts);
      vlsmAddBtn.textContent = "保存修改";
      vlsmName.focus();
      vlsmName.select();
    }
  });

  vlsmPlanBtn.addEventListener("click", () => {
    try {
      clearError(vlsmError);
      vlsmOutput.innerHTML = "";
      vlsmHint.textContent = "";
      const parent = vlsmParent.value.trim();
      if (!parent) throw new Error("请先输入父网段（IPv4 CIDR）。");
      if (!vlsmTable.length) throw new Error("请先添加至少一个子网需求。");
      const strat = vlsmStrategy.value;
      const subtractNB = vlsmSubtractNB.checked;

      const res = ipv4VlsmPlan(parent, vlsmTable, { subtractNB }, strat);
      const html = renderVlsm(res);
      vlsmOutput.innerHTML = html;
      pushHistory({
        type: "vlsm",
        title: `VLSM：${parent}`,
        tabId: "tab-vlsm",
        outputTargetId: "vlsmOutput",
        outputHtml: html,
        createdAt: Date.now(),
        inputs: { parentCIDR: parent, subtractNB, strategy: strat, requests: vlsmTable.slice() },
        outputData: res,
        ...buildVlsmExport(res),
      });
    } catch (e) {
      showError(vlsmError, e);
      vlsmHint.textContent = "提示：可尝试调整分配策略或降低某些子网需求的主机数。";
    }
  });

  // ---------- CIDR 汇总 ----------
  const aggInput = $("aggInput");
  const aggBtn = $("aggBtn");
  const aggError = $("aggError");
  const aggOutput = $("aggOutput");

  aggBtn.addEventListener("click", () => {
    try {
      clearError(aggError);
      const lines = tokenizeInput(aggInput.value);
      if (!lines.length) throw new Error("请输入至少一个 IPv4 CIDR 网段。");
      const res = ipv4Aggregate(lines);
      const html = renderAggregate(res);
      aggOutput.innerHTML = html;
      pushHistory({
        type: "cidr-aggregate",
        title: `CIDR 汇总（${lines.length} 段）`,
        tabId: "tab-aggregate",
        outputTargetId: "aggOutput",
        outputHtml: html,
        createdAt: Date.now(),
        inputs: { cidrs: lines },
        outputData: res,
        exportText: safeStringify(res),
      });
    } catch (e) {
      aggOutput.innerHTML = "";
      showError(aggError, e);
    }
  });

  // ---------- 冲突检查 ----------
  const conflictInput = $("conflictInput");
  const conflictBtn = $("conflictBtn");
  const conflictError = $("conflictError");
  const conflictOutput = $("conflictOutput");

  conflictBtn.addEventListener("click", () => {
    try {
      clearError(conflictError);
      const tokens = tokenizeInput(conflictInput.value);
      if (!tokens.length) throw new Error("请输入网段列表。");
      const ranges = tokens.map((t) => {
        const parsed = parseCIDROrSingleToRange(t);
        return parsed;
      });
      const relations = computeOverlapRelations(ranges);
      const html = renderConflict(relations, ranges);
      conflictOutput.innerHTML = html;
      pushHistory({
        type: "conflict-check",
        title: `冲突/包含检查（${tokens.length} 条）`,
        tabId: "tab-conflict",
        outputTargetId: "conflictOutput",
        outputHtml: html,
        createdAt: Date.now(),
        inputs: { items: tokens },
        outputData: relations,
        exportText: safeStringify(relations),
      });
    } catch (e) {
      conflictOutput.innerHTML = "";
      showError(conflictError, e);
    }
  });

  // ---------- 群 Ping ----------
  const batchPingBtn = $("batchPingBtn");
  const batchPingExportBtn = $("batchPingExportBtn");
  const pingInput = $("pingInput");
  const batchPingTimeout = $("batchPingTimeout");
  const pingStatusFilter = $("pingStatusFilter");
  const pingShowNetwork = $("pingShowNetwork");
  const pingShowBroadcast = $("pingShowBroadcast");
  const pingPageSize = $("pingPageSize");
  const pingPrevPageBtn = $("pingPrevPageBtn");
  const pingNextPageBtn = $("pingNextPageBtn");
  const pingPageInfo = $("pingPageInfo");
  const pingOutput = $("pingOutput");
  const pingHeatmapLegendHost = $("pingHeatmapLegendHost");
  const pingTableHost = $("pingTableHost");
  const pingError = $("pingError");
  const pingSummary = $("pingSummary");
  let lastBatchPingRows = [];
  let lastBatchPingSkipped = [];
  /** 与 batchPing 返回顺序一致，用于色块网格 */
  let lastBatchPingIps = [];
  /** 当前网段的网络地址 / 广播地址（与 CIDR 首尾一致） */
  let lastPingNetworkIp = "";
  let lastPingBroadcastIp = "";
  /** 最近一次成功发起检测时的 CIDR，用于判断结果是否与当前输入一致 */
  let lastPingCidrSnapshot = "";
  let pingCurrentPage = 1;
  let pingCurrentTotalPages = 1;
  if (pingPrevPageBtn) pingPrevPageBtn.disabled = true;
  if (pingNextPageBtn) pingNextPageBtn.disabled = true;

  function ipsShareSameSlash24(ips) {
    if (!ips || !ips.length) return false;
    const first = String(ips[0] || "").split(".");
    if (first.length !== 4) return false;
    const prefix3 = `${first[0]}.${first[1]}.${first[2]}.`;
    return ips.every((ip) => String(ip).startsWith(prefix3));
  }

  function tryGetPingExpand() {
    try {
      const cidr = String(pingInput?.value || "").trim();
      if (!cidr) return null;
      const ips = expandIPv4TargetsFromCIDR(cidr);
      const parsed = parseCIDROrSingleToRange(cidr);
      if (parsed.version !== "IPv4") return null;
      return {
        cidr,
        ips,
        networkIp: ipv4IntToString(BigInt(parsed.start)),
        broadcastIp: ipv4IntToString(BigInt(parsed.end)),
      };
    } catch {
      return null;
    }
  }

  function heatmapUsesStoredResults(orderedIps) {
    if (!lastPingCidrSnapshot || !pingInput) return false;
    const cur = String(pingInput.value || "").trim();
    if (cur !== lastPingCidrSnapshot) return false;
    if (!lastBatchPingRows.length || !lastBatchPingIps.length || !orderedIps.length) return false;
    if (lastBatchPingIps.length !== orderedIps.length) return false;
    for (let i = 0; i < orderedIps.length; i += 1) {
      if (orderedIps[i] !== lastBatchPingIps[i]) return false;
    }
    return true;
  }

  function cellMatchesPingStatusFilter(statusFilter, tier, r, isPreviewMode) {
    const sf = statusFilter || "all";
    if (sf === "all") return true;
    if (sf === "ok") {
      if (tier === "pending") return false;
      if (tier === "timeout") return false;
      if (!r) return false;
      return Boolean(r.ok);
    }
    if (sf === "fail") {
      if (tier === "pending") return false;
      if (tier === "fast" || tier === "mid" || tier === "slow") return false;
      if (tier === "timeout") return true;
      if (tier === "network" || tier === "broadcast") return Boolean(r && !r.ok);
      return false;
    }
    return true;
  }

  function applyPingNbDisplayFilter(rows, networkIp, broadcastIp, showNetwork, showBroadcast) {
    const net = String(networkIp || "");
    const bc = String(broadcastIp || "");
    const sn = Boolean(showNetwork);
    const sb = Boolean(showBroadcast);
    return rows.filter((r) => {
      if (net && bc && net === bc) {
        if (!sn && !sb && r.ip === net) return false;
        return true;
      }
      if (net && r.ip === net && !sn) return false;
      if (bc && r.ip === bc && !sb) return false;
      return true;
    });
  }

  function renderPingHeatmapParts(
    orderedIps,
    resultRows,
    networkIp,
    broadcastIp,
    showNetwork,
    showBroadcast,
    isPreviewMode,
    statusFilter,
  ) {
    const legendHtml = `
      <div class="ping-heat-legend">
        <span class="ping-heat-chip ping-cell--pending">待检测</span>
        <span class="ping-heat-chip ping-cell--fast">&lt;50毫秒</span>
        <span class="ping-heat-chip ping-cell--mid">50–100毫秒</span>
        <span class="ping-heat-chip ping-cell--slow">&gt;100毫秒</span>
        <span class="ping-heat-chip ping-cell--timeout">超时</span>
        <span class="ping-heat-chip ping-cell--network">网络地址</span>
        <span class="ping-heat-chip ping-cell--broadcast">广播地址</span>
      </div>
    `;
    if (!orderedIps || !orderedIps.length) {
      return { legendHtml, bodyHtml: "" };
    }
    const map = new Map();
    if (Array.isArray(resultRows) && resultRows.length) {
      for (const r of resultRows) map.set(r.ip, r);
    }
    const same24 = ipsShareSameSlash24(orderedIps);
    const net = String(networkIp || "");
    const bc = String(broadcastIp || "");
    const sn = Boolean(showNetwork);
    const sb = Boolean(showBroadcast);
    const cells = [];
    for (const ip of orderedIps) {
      if (net && bc && net === bc) {
        if (!sn && !sb && ip === net) continue;
      } else {
        if (net && ip === net && !sn) continue;
        if (bc && ip === bc && !sb) continue;
      }
      const r = map.get(ip);
      let tier = "timeout";
      let tipExtra = "";
      if (net && bc && net === bc && ip === net) {
        tier = sn ? "network" : "broadcast";
        tipExtra = sn ? "（网络地址，同主机地址）" : "（广播地址，同主机地址）";
      } else if (net && ip === net && sn) {
        tier = "network";
        tipExtra = "（网络地址）";
      } else if (bc && ip === bc && sb) {
        tier = "broadcast";
        tipExtra = "（广播地址）";
      } else {
        if (r && r.ok) {
          const ms =
            r.rttMs != null && Number.isFinite(Number(r.rttMs)) ? Number(r.rttMs) : Number(r.elapsedMs);
          if (ms != null && Number.isFinite(ms)) {
            if (ms < 50) tier = "fast";
            else if (ms < 100) tier = "mid";
            else tier = "slow";
          } else {
            tier = isPreviewMode ? "pending" : "timeout";
          }
        } else if (r && !r.ok) {
          tier = "timeout";
        } else {
          tier = "pending";
        }
      }
      const parts = String(ip).split(".");
      const label = same24 && parts.length === 4 ? String(Number(parts[3])) : String(ip);
      let tip = ip;
      if (tier === "network" || tier === "broadcast") {
        tip = `${ip}${tipExtra}`;
        if (r) {
          const ms = r.ok ? (r.rttMs != null && Number.isFinite(Number(r.rttMs)) ? Number(r.rttMs) : Number(r.elapsedMs)) : null;
          tip += r.ok && ms != null ? `，延迟约 ${ms} ms` : "，超时 / 不可达";
        } else if (isPreviewMode) {
          tip += "，待检测";
        }
      } else if (tier === "pending") {
        tip = `${ip}，待检测`;
      } else if (r) {
        const ms = r.ok ? (r.rttMs != null && Number.isFinite(Number(r.rttMs)) ? Number(r.rttMs) : Number(r.elapsedMs)) : null;
        tip = r.ok && ms != null ? `${ip}，延迟约 ${ms} ms` : `${ip}，超时 / 不可达`;
      }
      if (!cellMatchesPingStatusFilter(statusFilter, tier, r, isPreviewMode)) continue;
      cells.push({ tier, label, tip });
    }
    const grid = cells
      .map((c) => `<div class="ping-cell ping-cell--${c.tier}" title="${escapeHtml(c.tip)}">${escapeHtml(c.label)}</div>`)
      .join("");
    const previewHint = isPreviewMode
      ? `<div class="hint" style="margin:0 0 8px;">根据当前 IPv4 网段预排分布；点击「开始群 Ping」后将按延迟着色。</div>`
      : "";
    const emptyFilterHint =
      !cells.length && statusFilter && statusFilter !== "all"
        ? `<div class="hint" style="margin:0 0 8px;">当前「状态筛选」下没有匹配的地址色块，请切换为「全部」或其它条件。</div>`
        : "";
    const bodyHtml = `${previewHint}${emptyFilterHint}<div class="ping-heat-grid">${grid || ""}</div>`;
    return { legendHtml, bodyHtml };
  }

  function expandIPv4TargetsFromCIDR(cidrText) {
    const parsed = parseCIDROrSingleToRange(cidrText);
    if (parsed.version !== "IPv4") throw new Error("仅支持 IPv4。");
    const MAX_TARGETS = 4096;
    const out = [];
    const start = BigInt(parsed.start);
    const end = BigInt(parsed.end);
    const count = end - start + 1n;
    if (count > BigInt(MAX_TARGETS)) {
      throw new Error(`地址数 ${count.toString()} 超出上限 ${MAX_TARGETS}，请缩小网段。`);
    }
    for (let cur = start; cur <= end; cur += 1n) out.push(ipv4IntToString(cur));
    return out;
  }

  const MAX_TCP_PROBE_TASKS_UI = 25000;

  function expandPortScanIpsFromCidr(cidrText, excludeNb) {
    const ips = expandIPv4TargetsFromCIDR(cidrText);
    if (!excludeNb) return ips;
    let net = "";
    let bc = "";
    try {
      const parsed = parseCIDROrSingleToRange(cidrText);
      if (parsed.version === "IPv4") {
        net = ipv4IntToString(BigInt(parsed.start));
        bc = ipv4IntToString(BigInt(parsed.end));
      }
    } catch {
      return ips;
    }
    if (net && bc && net === bc) return ips;
    return ips.filter((ip) => ip !== net && ip !== bc);
  }

  function parseTcpPortList(text) {
    const parts = tokenizeInput(String(text || "").replace(/;/g, " "));
    const ports = [];
    for (const x of parts) {
      const n = Number(x);
      if (!Number.isInteger(n) || n < 1 || n > 65535) {
        throw new Error(`无效端口：${x}（须为 1–65535 的整数）`);
      }
      ports.push(n);
    }
    const unique = [...new Set(ports)];
    if (!unique.length) throw new Error("请至少填写一个端口。");
    if (unique.length > 32) throw new Error("最多同时扫描 32 个端口。");
    return unique;
  }

  function renderBatchPingResult(
    resultRows,
    skipped,
    statusFilter,
    pageSize,
    pageNo,
    networkIp,
    broadcastIp,
    showNetwork,
    showBroadcast,
  ) {
    const rowsSource = Array.isArray(resultRows) ? resultRows : [];
    const nbFiltered = applyPingNbDisplayFilter(rowsSource, networkIp, broadcastIp, showNetwork, showBroadcast);
    const filteredRows =
      statusFilter === "ok"
        ? nbFiltered.filter((r) => r.ok)
        : statusFilter === "fail"
          ? nbFiltered.filter((r) => !r.ok)
          : nbFiltered;
    const safePageSize = [10, 20, 50].includes(Number(pageSize)) ? Number(pageSize) : 10;
    const totalPages = Math.max(1, Math.ceil(filteredRows.length / safePageSize));
    const safePageNo = Math.max(1, Math.min(totalPages, Number(pageNo) || 1));
    const start = (safePageNo - 1) * safePageSize;
    const pagedRows = filteredRows.slice(start, start + safePageSize);
    const okCount = resultRows.filter((r) => r.ok).length;
    const failCount = resultRows.length - okCount;
    const skippedHtml = skipped.length
      ? `<div class="hint" style="margin:0 0 8px;">已跳过：${escapeHtml(skipped.join("；"))}</div>`
      : "";
    const netStr = String(networkIp || "");
    const bcStr = String(broadcastIp || "");
    const rows = pagedRows
      .map((r, idx) => {
        const msCol =
          r.ok && r.rttMs != null && Number.isFinite(Number(r.rttMs))
            ? String(r.rttMs)
            : r.ok
              ? String(r.elapsedMs ?? "")
              : "-";
        let ipCls = r.ok ? "ping-ok" : "ping-fail";
        if (netStr && bcStr && netStr === bcStr && r.ip === netStr) {
          if (showNetwork) ipCls = "ping-ip-network";
          else if (showBroadcast) ipCls = "ping-ip-broadcast";
        } else if (netStr && r.ip === netStr && showNetwork) {
          ipCls = "ping-ip-network";
        } else if (bcStr && r.ip === bcStr && showBroadcast) {
          ipCls = "ping-ip-broadcast";
        }
        return `<tr>
          <td>${start + idx + 1}</td>
          <td class="${ipCls}">${escapeHtml(r.ip)}</td>
          <td class="${r.ok ? "ping-ok" : "ping-fail"}">${r.ok ? "可达" : "不可达"}</td>
          <td>${escapeHtml(msCol)}</td>
        </tr>`;
      })
      .join("");
    const summaryText = `总计：${resultRows.length}，可达 ${okCount}，不可达 ${failCount}，当前显示 ${filteredRows.length}`;
    const tableOnly = `
      <div class="section-title">明细列表</div>
      <table>
        <tr><th>序号</th><th>IP</th><th>状态</th><th>延迟(ms)</th></tr>
        ${rows || `<tr><td colspan="4">没有可显示的目标。</td></tr>`}
      </table>
    `;
    return {
      tableOnlyHtml: `${skippedHtml}${tableOnly}`,
      summaryText,
      totalPages,
      pageNo: safePageNo,
      filteredCount: filteredRows.length,
    };
  }

  function renderPingTableByState() {
    const filterMode = pingStatusFilter ? pingStatusFilter.value : "all";
    const pageSize = pingPageSize ? Number(pingPageSize.value) : 10;
    const showN = Boolean(pingShowNetwork && pingShowNetwork.checked);
    const showB = Boolean(pingShowBroadcast && pingShowBroadcast.checked);

    const expand = tryGetPingExpand();
    const orderedForHeat = expand?.ips || [];
    const netH = expand?.networkIp || "";
    const bcH = expand?.broadcastIp || "";
    const useResults = Boolean(expand && heatmapUsesStoredResults(expand.ips));

    let heatmapLegendHtml = "";
    let heatmapBodyHtml = "";
    if (orderedForHeat.length) {
      const parts = renderPingHeatmapParts(
        orderedForHeat,
        useResults ? lastBatchPingRows : [],
        netH,
        bcH,
        showN,
        showB,
        !useResults,
        filterMode,
      );
      heatmapLegendHtml = parts.legendHtml;
      heatmapBodyHtml = parts.bodyHtml;
    } else {
      heatmapLegendHtml = "";
      heatmapBodyHtml = `<div class="hint">请输入有效 IPv4 网段以预览色块分布。</div>`;
    }

    const skippedHtml = lastBatchPingSkipped.length
      ? `<div class="hint" style="margin:0 0 8px;">已跳过：${escapeHtml(lastBatchPingSkipped.join("；"))}</div>`
      : "";

    let tableBlock = "";
    let summaryText = "";
    let totalPages = 1;
    let pageNo = 1;

    if (useResults) {
      const rendered = renderBatchPingResult(
        lastBatchPingRows,
        lastBatchPingSkipped,
        filterMode,
        pageSize,
        pingCurrentPage,
        lastPingNetworkIp,
        lastPingBroadcastIp,
        showN,
        showB,
      );
      pingCurrentPage = rendered.pageNo;
      pingCurrentTotalPages = rendered.totalPages;
      tableBlock = rendered.tableOnlyHtml;
      summaryText = rendered.summaryText;
      totalPages = rendered.totalPages;
      pageNo = rendered.pageNo;
    } else {
      pingCurrentPage = 1;
      pingCurrentTotalPages = 1;
      tableBlock = `<div class="section-title">明细列表</div>`;
      if (lastBatchPingRows.length && expand && lastPingCidrSnapshot && expand.cidr !== lastPingCidrSnapshot) {
        tableBlock += `<div class="hint">当前网段已与上次检测不一致，请重新点击「开始群 Ping」。色块已为当前网段预览。</div>`;
      } else {
        tableBlock += `<div class="hint">点击「开始群 Ping」后在此显示检测明细与分页。</div>`;
      }
      summaryText = expand ? `预览：${expand.ips.length} 个地址` : "";
      pageNo = 1;
      totalPages = 1;
    }

    if (pingHeatmapLegendHost) pingHeatmapLegendHost.innerHTML = heatmapLegendHtml;
    if (pingOutput) pingOutput.innerHTML = heatmapBodyHtml;
    if (pingTableHost) pingTableHost.innerHTML = skippedHtml + tableBlock;
    if (pingSummary) pingSummary.textContent = summaryText;
    if (pingPageInfo) pingPageInfo.textContent = useResults ? `第 ${pageNo} / ${totalPages} 页` : "—";
    if (pingPrevPageBtn) pingPrevPageBtn.disabled = !useResults || pageNo <= 1;
    if (pingNextPageBtn) pingNextPageBtn.disabled = !useResults || pageNo >= totalPages;
  }

  batchPingBtn.addEventListener("click", async () => {
    try {
      clearError(pingError);
      if (pingSummary) pingSummary.textContent = "";
      const showN0 = Boolean(pingShowNetwork && pingShowNetwork.checked);
      const showB0 = Boolean(pingShowBroadcast && pingShowBroadcast.checked);
      const filterMode0 = pingStatusFilter ? pingStatusFilter.value : "all";
      const expand0 = tryGetPingExpand();
      if (expand0 && expand0.ips.length) {
        const parts0 = renderPingHeatmapParts(
          expand0.ips,
          [],
          expand0.networkIp,
          expand0.broadcastIp,
          showN0,
          showB0,
          true,
          filterMode0,
        );
        if (pingHeatmapLegendHost) pingHeatmapLegendHost.innerHTML = parts0.legendHtml;
        if (pingOutput) {
          pingOutput.innerHTML =
            parts0.bodyHtml + `<div class="hint" style="margin-top:10px;">正在进行群 Ping 检测…</div>`;
        }
        if (pingTableHost) pingTableHost.innerHTML = `<div class="hint">检测完成后显示明细…</div>`;
      } else {
        if (pingHeatmapLegendHost) pingHeatmapLegendHost.innerHTML = "";
        if (pingOutput) pingOutput.innerHTML = `<div class="hint">正在进行群 Ping 检测…</div>`;
        if (pingTableHost) pingTableHost.innerHTML = "";
      }
      const cidr = String((pingInput && pingInput.value) || "").trim();
      if (!cidr) throw new Error("请先输入 IPv4 网段。");
      const ips = expandIPv4TargetsFromCIDR(cidr);
      if (!ips.length) throw new Error("没有可用的 IPv4 目标，请检查输入。");
      try {
        const parsedNb = parseCIDROrSingleToRange(cidr);
        if (parsedNb.version === "IPv4") {
          lastPingNetworkIp = ipv4IntToString(BigInt(parsedNb.start));
          lastPingBroadcastIp = ipv4IntToString(BigInt(parsedNb.end));
        } else {
          lastPingNetworkIp = "";
          lastPingBroadcastIp = "";
        }
      } catch {
        lastPingNetworkIp = "";
        lastPingBroadcastIp = "";
      }
      const timeoutMs = Math.max(200, Math.min(10000, Number(batchPingTimeout.value) || 1200));
      if (!window.subnetNative || typeof window.subnetNative.batchPing !== "function") {
        throw new Error("当前环境不支持系统 Ping。");
      }
      const resultRows = await window.subnetNative.batchPing({
        ips,
        timeoutMs,
        concurrency: 48,
      });
      lastBatchPingRows = Array.isArray(resultRows) ? resultRows : [];
      lastBatchPingSkipped = [];
      lastBatchPingIps = ips.slice();
      lastPingCidrSnapshot = cidr.trim();
      pingCurrentPage = 1;
      renderPingTableByState();
      pushHistory({
        type: "batch-ping",
        title: `群 Ping（${ips.length} 个目标）`,
        tabId: "tab-ping",
        outputTargetId: "pingTableHost",
        outputHtml: pingTableHost ? pingTableHost.innerHTML : "",
        createdAt: Date.now(),
        inputs: { cidr, expandedCount: ips.length, timeoutMs, filterMode: pingStatusFilter ? pingStatusFilter.value : "all" },
        outputData: resultRows,
        exportText: safeStringify(resultRows),
      });
      const okc = lastBatchPingRows.filter((r) => r.ok).length;
      const failc = lastBatchPingRows.length - okc;
      showTaskNotice(
        "群 Ping 完成",
        `已对 ${ips.length} 个地址完成检测。\n可达：${okc}\n不可达：${failc}`,
        true,
        "tab-ping",
      );
    } catch (e) {
      if (pingError) clearError(pingError);
      if (pingSummary) pingSummary.textContent = "";
      renderPingTableByState();
      const msg = e instanceof Error ? e.message : String(e);
      showTaskNotice("群 Ping 失败", msg, false, "tab-ping");
    }
  });

  if (pingStatusFilter) {
    pingStatusFilter.addEventListener("change", () => {
      pingCurrentPage = 1;
      renderPingTableByState();
    });
  }

  if (pingShowNetwork) {
    pingShowNetwork.addEventListener("change", () => {
      pingCurrentPage = 1;
      renderPingTableByState();
    });
  }
  if (pingShowBroadcast) {
    pingShowBroadcast.addEventListener("change", () => {
      pingCurrentPage = 1;
      renderPingTableByState();
    });
  }

  if (pingPageSize) {
    pingPageSize.addEventListener("change", () => {
      pingCurrentPage = 1;
      renderPingTableByState();
    });
  }
  if (pingPrevPageBtn) {
    pingPrevPageBtn.addEventListener("click", () => {
      if (pingCurrentPage <= 1) return;
      pingCurrentPage -= 1;
      renderPingTableByState();
    });
  }
  if (pingNextPageBtn) {
    pingNextPageBtn.addEventListener("click", () => {
      if (pingCurrentPage >= pingCurrentTotalPages) return;
      pingCurrentPage += 1;
      renderPingTableByState();
    });
  }

  let pingInputPreviewTimer = null;
  if (pingInput) {
    pingInput.addEventListener("input", () => {
      clearTimeout(pingInputPreviewTimer);
      pingInputPreviewTimer = setTimeout(() => {
        renderPingTableByState();
      }, 200);
    });
  }
  setTimeout(() => {
    renderPingTableByState();
  }, 0);

  if (batchPingExportBtn) {
    batchPingExportBtn.addEventListener("click", () => {
      if (!lastBatchPingRows.length) {
        showError(pingError, new Error("暂无可导出的群 Ping 结果，请先执行一次检测。"));
        return;
      }
      clearError(pingError);
      const headers = ["IP", "状态", "可达", "延迟(ms)"];
      const rows = lastBatchPingRows.map((r) => {
        const ms =
          r.ok && r.rttMs != null && Number.isFinite(Number(r.rttMs))
            ? String(r.rttMs)
            : r.ok
              ? String(r.elapsedMs ?? "")
              : "-";
        return [r.ip, r.ok ? "可达" : "不可达", r.ok ? "1" : "0", ms];
      });
      const excelHtml = buildExcelHtml(headers, rows);
      downloadText(`batch_ping_${Date.now()}.xls`, excelHtml, "application/vnd.ms-excel;charset=utf-8");
    });
  }

  // ---------- 端口扫描（Electron TCP 轻量探测） ----------
  const portScanCidr = $("portScanCidr");
  const portScanPorts = $("portScanPorts");
  const portScanTimeout = $("portScanTimeout");
  const portScanPingTimeout = $("portScanPingTimeout");
  const portScanConcurrency = $("portScanConcurrency");
  const portScanStagger = $("portScanStagger");
  const portScanPingFirst = $("portScanPingFirst");
  const portScanExcludeNB = $("portScanExcludeNB");
  const portScanStartBtn = $("portScanStartBtn");
  const portScanExportBtn = $("portScanExportBtn");
  const portScanOutput = $("portScanOutput");
  const portScanSummary = $("portScanSummary");
  const portScanFilter = $("portScanFilter");
  const portScanPageSize = $("portScanPageSize");
  const portScanPrevPageBtn = $("portScanPrevPageBtn");
  const portScanNextPageBtn = $("portScanNextPageBtn");
  const portScanPageInfo = $("portScanPageInfo");
  const portScanError = $("portScanError");
  const portScanErrorLeft = $("portScanErrorLeft");

  let lastPortScanRows = [];
  let portScanMeta = { cidr: "", ports: [], pingFirst: false, note: "" };
  let portScanCurrentPage = 1;
  let portScanTotalPages = 1;

  function renderPortScanTable() {
    if (!portScanOutput) return;
    const filterMode = portScanFilter ? portScanFilter.value : "all";
    const pageSize = portScanPageSize ? Number(portScanPageSize.value) : 10;
    const safePageSize = [10, 20, 50].includes(pageSize) ? pageSize : 10;
    const src = Array.isArray(lastPortScanRows) ? lastPortScanRows : [];
    const filtered = src.filter((r) => {
      if (filterMode === "open") return Boolean(r.open);
      if (filterMode === "closed") return !r.open;
      return true;
    });
    portScanTotalPages = Math.max(1, Math.ceil(filtered.length / safePageSize));
    const safePageNo = Math.max(1, Math.min(portScanTotalPages, portScanCurrentPage));
    portScanCurrentPage = safePageNo;
    const start = (safePageNo - 1) * safePageSize;
    const pageRows = filtered.slice(start, start + safePageSize);
    const openCount = src.filter((r) => r.open).length;
    const noteHtml = portScanMeta.note
      ? `<div class="hint" style="margin:0 0 8px;">${escapeHtml(portScanMeta.note)}</div>`
      : "";
    const rowsHtml = pageRows
      .map((r, idx) => {
        const stCls = r.open ? "ping-ok" : "ping-fail";
        const stText = r.open ? "开放" : "关闭";
        const errCol = r.open ? "—" : escapeHtml(String(r.error || "—"));
        return `<tr>
          <td>${start + idx + 1}</td>
          <td>${escapeHtml(r.ip)}</td>
          <td>${escapeHtml(String(r.port))}</td>
          <td class="${stCls}">${stText}</td>
          <td>${escapeHtml(String(r.elapsedMs ?? ""))}</td>
          <td>${errCol}</td>
        </tr>`;
      })
      .join("");
    portScanOutput.innerHTML = `${noteHtml}
      <div class="section-title">探测明细</div>
      <table>
        <tr><th>序号</th><th>IP</th><th>端口</th><th>状态</th><th>耗时(ms)</th><th>备注</th></tr>
        ${rowsHtml || `<tr><td colspan="6">没有符合当前筛选的结果。</td></tr>`}
      </table>`;
    if (portScanSummary) {
      portScanSummary.textContent = src.length
        ? `合计 ${src.length} 条（开放 ${openCount}），当前筛选 ${filtered.length} 条`
        : "";
    }
    if (portScanPageInfo) {
      portScanPageInfo.textContent = src.length ? `第 ${safePageNo} / ${portScanTotalPages} 页` : "—";
    }
    if (portScanPrevPageBtn) portScanPrevPageBtn.disabled = !src.length || safePageNo <= 1;
    if (portScanNextPageBtn) portScanNextPageBtn.disabled = !src.length || safePageNo >= portScanTotalPages;
  }

  if (portScanStartBtn && portScanCidr) {
    portScanStartBtn.addEventListener("click", async () => {
      try {
        if (portScanError) clearError(portScanError);
        if (portScanErrorLeft) clearError(portScanErrorLeft);
        if (portScanSummary) portScanSummary.textContent = "";
        const cidr = String(portScanCidr.value || "").trim();
        if (!cidr) throw new Error("请先输入 IPv4 网段。");
        const ports = parseTcpPortList(portScanPorts ? portScanPorts.value : "");
        const excludeNb = Boolean(portScanExcludeNB && portScanExcludeNB.checked);
        let ips = expandPortScanIpsFromCidr(cidr, excludeNb);
        if (!ips.length) throw new Error("没有可扫描的 IPv4 地址。");
        let note = "";
        if (portScanPingFirst && portScanPingFirst.checked) {
          if (!window.subnetNative || typeof window.subnetNative.batchPing !== "function") {
            throw new Error("当前环境不支持 ICMP Ping，无法使用「先 Ping 再扫」。");
          }
          const pingMs = Math.max(200, Math.min(10000, Number(portScanPingTimeout && portScanPingTimeout.value) || 1200));
          if (portScanOutput) {
            portScanOutput.innerHTML = `<div class="hint">正在 Ping ${ips.length} 个地址以筛选可达主机…</div>`;
          }
          const pingRows = await window.subnetNative.batchPing({
            ips,
            timeoutMs: pingMs,
            concurrency: 40,
          });
          const ok = new Set((Array.isArray(pingRows) ? pingRows : []).filter((r) => r.ok).map((r) => r.ip));
          const before = ips.length;
          ips = ips.filter((ip) => ok.has(ip));
          note = `已先执行 ICMP Ping：${before} 个地址中 ${ips.length} 个可达，已对其做 TCP 探测。`;
          if (!ips.length) throw new Error("没有 ICMP 可达的主机，已终止端口扫描。");
        }
        const tasks = ips.length * ports.length;
        if (tasks > MAX_TCP_PROBE_TASKS_UI) {
          throw new Error(
            `探测任务数 ${tasks} 超过上限 ${MAX_TCP_PROBE_TASKS_UI}，请缩小网段或减少端口数。`,
          );
        }
        if (!window.subnetNative || typeof window.subnetNative.tcpPortScan !== "function") {
          throw new Error("当前环境不支持端口扫描（请使用 Electron 版）。");
        }
        const tcpMs = Math.max(200, Math.min(8000, Number(portScanTimeout && portScanTimeout.value) || 1500));
        const conc = Math.max(1, Math.min(32, Number(portScanConcurrency && portScanConcurrency.value) || 8));
        const stagger = Math.max(0, Math.min(500, Number(portScanStagger && portScanStagger.value) || 0));
        const probes = [];
        for (const ip of ips) {
          for (const p of ports) probes.push({ ip, port: p });
        }
        if (portScanOutput) {
          portScanOutput.innerHTML = `<div class="hint">正在 TCP 探测 ${probes.length} 个任务（并发 ${conc}，超时 ${tcpMs} ms）…</div>`;
        }
        const raw = await window.subnetNative.tcpPortScan({
          probes,
          timeoutMs: tcpMs,
          concurrency: conc,
          staggerMs: stagger,
        });
        lastPortScanRows = Array.isArray(raw)
          ? raw.map((r) => ({
              ip: String(r.ip || ""),
              port: Number(r.port),
              open: Boolean(r.open),
              elapsedMs: Number(r.elapsedMs) || 0,
              error: r.error != null ? String(r.error) : "",
            }))
          : [];
        portScanMeta = {
          cidr,
          ports: ports.slice(),
          pingFirst: Boolean(portScanPingFirst && portScanPingFirst.checked),
          note,
        };
        portScanCurrentPage = 1;
        renderPortScanTable();
        const headers = ["IP", "端口", "开放(1/0)", "状态", "耗时(ms)", "备注"];
        const exRows = lastPortScanRows.map((r) => [
          r.ip,
          String(r.port),
          r.open ? "1" : "0",
          r.open ? "开放" : "关闭",
          String(r.elapsedMs ?? ""),
          r.error || "",
        ]);
        const exportCsv = [headers.map(csvEscape).join(","), ...exRows.map((row) => row.map(csvEscape).join(","))].join(
          "\n",
        );
        const exportText = exRows.map((row) => row.join(" | ")).join("\n");
        pushHistory({
          type: "tcp-port-scan",
          title: `端口扫描 ${cidr}（${ports.join(",")}）`,
          tabId: "tab-portscan",
          outputTargetId: "portScanOutput",
          outputHtml: portScanOutput ? portScanOutput.innerHTML : "",
          createdAt: Date.now(),
          inputs: {
            cidr,
            ports,
            tcpTimeoutMs: tcpMs,
            pingFirst: Boolean(portScanPingFirst && portScanPingFirst.checked),
            excludeNb,
            concurrency: conc,
            staggerMs: stagger,
          },
          outputData: lastPortScanRows,
          exportText,
          exportCsv,
          exportExcelHtml: buildExcelHtml(headers, exRows),
        });
        const openN = lastPortScanRows.filter((r) => r.open).length;
        showTaskNotice(
          "端口扫描完成",
          `任务数：${lastPortScanRows.length}\n开放端口记录：${openN}\n关闭/超时等：${lastPortScanRows.length - openN}`,
          true,
          "tab-portscan",
        );
      } catch (e) {
        lastPortScanRows = [];
        portScanMeta = { cidr: "", ports: [], pingFirst: false, note: "" };
        if (portScanOutput) portScanOutput.innerHTML = "";
        if (portScanSummary) portScanSummary.textContent = "";
        if (portScanError) clearError(portScanError);
        if (portScanErrorLeft) clearError(portScanErrorLeft);
        const msg = e instanceof Error ? e.message : String(e);
        showTaskNotice("端口扫描失败", msg, false, "tab-portscan");
      }
    });
  }

  if (portScanExportBtn) {
    portScanExportBtn.addEventListener("click", () => {
      if (!lastPortScanRows.length) {
        showError(portScanError, new Error("暂无可导出的扫描结果，请先执行一次扫描。"));
        return;
      }
      if (portScanError) clearError(portScanError);
      const headers = ["IP", "端口", "开放(1/0)", "状态", "耗时(ms)", "备注"];
      const exRows = lastPortScanRows.map((r) => [
        r.ip,
        String(r.port),
        r.open ? "1" : "0",
        r.open ? "开放" : "关闭",
        String(r.elapsedMs ?? ""),
        r.error || "",
      ]);
      const excelHtml = buildExcelHtml(headers, exRows);
      downloadText(`port_scan_${Date.now()}.xls`, excelHtml, "application/vnd.ms-excel;charset=utf-8");
    });
  }

  if (portScanFilter) {
    portScanFilter.addEventListener("change", () => {
      portScanCurrentPage = 1;
      renderPortScanTable();
    });
  }
  if (portScanPageSize) {
    portScanPageSize.addEventListener("change", () => {
      portScanCurrentPage = 1;
      renderPortScanTable();
    });
  }
  if (portScanPrevPageBtn) {
    portScanPrevPageBtn.addEventListener("click", () => {
      if (portScanCurrentPage <= 1) return;
      portScanCurrentPage -= 1;
      renderPortScanTable();
    });
  }
  if (portScanNextPageBtn) {
    portScanNextPageBtn.addEventListener("click", () => {
      if (portScanCurrentPage >= portScanTotalPages) return;
      portScanCurrentPage += 1;
      renderPortScanTable();
    });
  }
  if (portScanPrevPageBtn) portScanPrevPageBtn.disabled = true;
  if (portScanNextPageBtn) portScanNextPageBtn.disabled = true;

  // ---------- 路由追踪 ----------
  const traceTarget = $("traceTarget");
  const traceMaxHops = $("traceMaxHops");
  const traceWaitMs = $("traceWaitMs");
  const traceStartBtn = $("traceStartBtn");
  const tracePauseBtn = $("tracePauseBtn");
  const traceStopBtn = $("traceStopBtn");
  const traceCopyRawBtn = $("traceCopyRawBtn");
  const traceOutput = $("traceOutput");
  const traceError = $("traceError");
  const traceErrorLeft = $("traceErrorLeft");
  let lastTracePayload = null;

  function setTraceRunningUi(running) {
    if (traceStartBtn) traceStartBtn.disabled = Boolean(running);
    if (traceStopBtn) traceStopBtn.disabled = !running;
    if (tracePauseBtn) {
      tracePauseBtn.disabled = !running;
      if (!running && tracePauseBtn.textContent !== "暂停") tracePauseBtn.textContent = "暂停";
    }
  }
  setTraceRunningUi(false);
  if (traceStopBtn) traceStopBtn.disabled = true;
  if (tracePauseBtn) tracePauseBtn.disabled = true;

  if (traceStopBtn) {
    traceStopBtn.addEventListener("click", () => {
      if (window.subnetNative && typeof window.subnetNative.traceRouteAbort === "function") {
        window.subnetNative.traceRouteAbort().catch(() => {});
      }
    });
  }

  if (tracePauseBtn) {
    tracePauseBtn.addEventListener("click", async () => {
      if (!window.subnetNative || typeof window.subnetNative.traceRoutePauseToggle !== "function") return;
      try {
        const r = await window.subnetNative.traceRoutePauseToggle();
        if (r && r.unsupported) {
          showToast("Windows 下暂不支持暂停/继续路由进程", "err");
          return;
        }
        if (r && r.ok) {
          tracePauseBtn.textContent = r.paused ? "继续" : "暂停";
        }
      } catch {
        showToast("暂停切换失败", "err");
      }
    });
  }

  if (traceStartBtn) {
    traceStartBtn.addEventListener("click", async () => {
      try {
        if (traceError) clearError(traceError);
        if (traceErrorLeft) clearError(traceErrorLeft);
        const target = String(traceTarget && traceTarget.value ? traceTarget.value : "").trim();
        if (!target) throw new Error("请输入目标 IP 或域名。");
        const maxHops = Math.max(1, Math.min(128, Number(traceMaxHops && traceMaxHops.value) || 30));
        const waitMs = Math.max(100, Math.min(8000, Number(traceWaitMs && traceWaitMs.value) || 4000));
        if (!window.subnetNative || typeof window.subnetNative.traceRoute !== "function") {
          throw new Error("当前环境不支持路由追踪（请使用 Electron 桌面版）。");
        }
        if (traceOutput) {
          traceOutput.innerHTML = `<div class="hint">正在追踪 ${escapeHtml(target)}，请稍候（可能需要数分钟）…</div>`;
        }
        if (tracePauseBtn) tracePauseBtn.textContent = "暂停";
        setTraceRunningUi(true);
        let data;
        try {
          data = await window.subnetNative.traceRoute({ target, maxHops, waitMs });
        } finally {
          setTraceRunningUi(false);
        }
        lastTracePayload = data && typeof data === "object" ? data : null;
        if (traceOutput) traceOutput.innerHTML = renderTraceRouteHtml(lastTracePayload);
        const hops = Array.isArray(lastTracePayload?.hops) ? lastTracePayload.hops : [];
        const aborted = Boolean(lastTracePayload?.aborted);
        const summary = aborted
          ? `已停止，已解析 ${hops.length} 跳。`
          : hops.length > 0
            ? `已完成，共解析 ${hops.length} 跳。`
            : "已结束，但未解析到跃点（请查看原始输出）。";
        const title = aborted ? "路由追踪已停止" : "路由追踪完成";
        showTaskNotice(title, summary, true, "tab-trace");
        pushHistory({
          type: "trace-route",
          title: `路由追踪 ${target}`,
          tabId: "tab-trace",
          outputTargetId: "traceOutput",
          outputHtml: traceOutput ? traceOutput.innerHTML : "",
          createdAt: Date.now(),
          inputs: { target, maxHops, waitMs },
          outputData: lastTracePayload,
          exportText: formatTracePlain(lastTracePayload),
        });
      } catch (e) {
        setTraceRunningUi(false);
        lastTracePayload = null;
        if (traceOutput) traceOutput.innerHTML = "";
        if (traceError) clearError(traceError);
        if (traceErrorLeft) clearError(traceErrorLeft);
        const msg = e instanceof Error ? e.message : String(e);
        showTaskNotice("路由追踪失败", msg, false, "tab-trace");
      }
    });
  }

  if (traceCopyRawBtn) {
    traceCopyRawBtn.addEventListener("click", async () => {
      try {
        if (!lastTracePayload || !lastTracePayload.raw) {
          showToast("暂无原始输出可复制", "err");
          return;
        }
        await copyTextToClipboard(String(lastTracePayload.raw));
        showToast("已复制原始输出");
      } catch (err) {
        showToast(err instanceof Error ? err.message : String(err), "err");
      }
    });
  }

  // ---------- 双栈对比 ----------
  const dualIPv4 = $("dualIPv4");
  const dualIPv6 = $("dualIPv6");
  const dualIPv6SmartHint = $("dualIPv6SmartHint");
  const dualSubtractNB = $("dualSubtractNB");
  const dualBtn = $("dualBtn");
  const dualError = $("dualError");
  const dualOutput = $("dualOutput");

  let dualV6HintTimer = null;
  function runDualV6Hint() {
    clearTimeout(dualV6HintTimer);
    dualV6HintTimer = setTimeout(() => {
      const s = dualIPv6.value.trim();
      const tip = s ? suggestIpv6CidrHint(s) : "";
      if (dualIPv6SmartHint) dualIPv6SmartHint.textContent = tip;
      dualIPv6.classList.toggle(INPUT_INVALID_FLASH_CLS, Boolean(tip));
    }, 220);
  }
  if (dualIPv6) dualIPv6.addEventListener("input", runDualV6Hint);
  runDualV6Hint();

  dualBtn.addEventListener("click", () => {
    try {
      clearError(dualError);
      const v4 = dualIPv4.value.trim();
      const v6 = dualIPv6.value.trim();
      if (!v4 && !v6) throw new Error("请至少输入 IPv4 或 IPv6。");

      const left = v4 ? ipv4CoreCompute(v4, { subtractNB: dualSubtractNB.checked }) : null;
      // IPv6 输入支持：addr/prefix 或 addr（会报错要求用户带 prefix）
      let right = null;
      if (v6) {
        const m = v6.match(/^(.+)\/(\d{1,3})$/);
        if (!m) throw new Error("IPv6 双栈对比输入需要使用 'addr/前缀' 格式，如 2001:db8::/64。");
        right = ipv6CoreCompute(m[1], Number(m[2]), { showExpanded: true });
      }

      const html = `
        <div class="section-title">IPv4 结果</div>
        <div style="margin-bottom:12px;">${left ? renderIPv4Core(left) : `<div class="hint">未填写 IPv4。</div>`}</div>
        <div class="section-title">IPv6 结果</div>
        <div>${right ? `
          <table>
            <tr><th>网络前缀</th><td><span class="hl">${escapeHtml(right.networkPrefix)}</span></td></tr>
            <tr><th>接口 ID</th><td>${escapeHtml(right.interfaceId)}</td></tr>
            <tr><th>地址类型</th><td>${escapeHtml(right.addressType)}</td></tr>
            <tr><th>地址范围</th><td>${escapeHtml(right.prefixRange.first)} - ${escapeHtml(right.prefixRange.last)}</td></tr>
          </table>
        ` : `<div class="hint">未填写 IPv6。</div>`}</div>
      `;
      dualOutput.innerHTML = html;
      if (dualIPv6SmartHint && v6) dualIPv6SmartHint.textContent = "";
      dualIPv6.classList.remove(INPUT_INVALID_FLASH_CLS);
      pushHistory({
        type: "dual-compare",
        title: "双栈对比",
        tabId: "tab-dual",
        outputTargetId: "dualOutput",
        outputHtml: html,
        createdAt: Date.now(),
        inputs: { ipv4: v4 || "", ipv6: v6 || "", subtractNB: dualSubtractNB.checked },
        outputData: { ipv4: left, ipv6: right },
        exportText: safeStringify({ ipv4: left, ipv6: right }),
      });
    } catch (e) {
      dualOutput.innerHTML = "";
      showError(dualError, e);
      const v6 = dualIPv6.value.trim();
      if (dualIPv6SmartHint && v6) dualIPv6SmartHint.textContent = suggestIpv6CidrHint(v6);
    }
  });

  // ---------- 全局快捷键与搜索 ----------
  const GLOBAL_SEARCH_TABS = [
    { id: "tab-ipv4-core", label: "IPv4 计算" },
    { id: "tab-ipv6-core", label: "IPv6 计算" },
    { id: "tab-ipv6-plan", label: "IPv6 子网规划" },
    { id: "tab-ping", label: "群 Ping 检测" },
    { id: "tab-portscan", label: "端口扫描" },
    { id: "tab-trace", label: "路由追踪" },
    { id: "tab-equal", label: "等长子网规划" },
    { id: "tab-vlsm", label: "可变长子网规划" },
    { id: "tab-aggregate", label: "CIDR 汇总" },
    { id: "tab-conflict", label: "冲突/包含检查" },
    { id: "tab-dual", label: "双栈对比" },
    { id: "tab-address-validate", label: "地址验证/归属查询" },
  ];

  const TAB_PRIMARY_BTN = {
    "tab-ipv4-core": "ipv4CalcBtn",
    "tab-ipv6-core": "ipv6CalcBtn",
    "tab-ipv6-plan": "ipv6VlsmPlanBtn",
    "tab-ping": "batchPingBtn",
    "tab-portscan": "portScanStartBtn",
    "tab-trace": "traceStartBtn",
    "tab-equal": "equalGenBtn",
    "tab-vlsm": "vlsmPlanBtn",
    "tab-aggregate": "aggBtn",
    "tab-conflict": "conflictBtn",
    "tab-dual": "dualBtn",
    "tab-address-validate": "addrTypeBtn",
  };

  function isTypingTarget(el) {
    if (!el || !el.tagName) return false;
    const t = el.tagName.toLowerCase();
    if (t === "textarea") return true;
    if (t === "select") return true;
    if (t === "input") {
      const ty = (el.getAttribute("type") || "text").toLowerCase();
      if (["text", "search", "number", "email", "url", "tel", "password"].includes(ty)) return true;
    }
    return Boolean(el.isContentEditable);
  }

  const globalSearchModal = $("globalSearchModal");
  const globalSearchInput = $("globalSearchInput");
  const globalSearchResults = $("globalSearchResults");
  const globalSearchClose = $("globalSearchClose");

  function closeGlobalSearch() {
    if (globalSearchModal) globalSearchModal.style.display = "none";
  }

  function renderGlobalSearchResults(q) {
    if (!globalSearchResults) return;
    const qq = String(q || "").trim().toLowerCase();
    const parts = [];
    parts.push(`<div class="global-search-section">标签页</div>`);
    for (const row of GLOBAL_SEARCH_TABS) {
      if (qq && !row.label.toLowerCase().includes(qq) && !row.id.toLowerCase().includes(qq)) continue;
      parts.push(
        `<button type="button" class="global-search-item" data-nav-tab="${escapeHtml(row.id)}">${escapeHtml(row.label)}</button>`,
      );
    }
    parts.push(`<div class="global-search-section">历史记录</div>`);
    let n = 0;
    for (const rec of historyRecords) {
      const title = String(rec.title || rec.type || "");
      if (qq && !title.toLowerCase().includes(qq)) continue;
      n += 1;
      parts.push(
        `<button type="button" class="global-search-item" data-history-id="${escapeHtml(rec.id)}">${escapeHtml(title)}</button>`,
      );
    }
    if (n === 0 && qq) {
      globalSearchResults.innerHTML = parts.join("") + `<div class="hint">无匹配历史</div>`;
      return;
    }
    globalSearchResults.innerHTML = parts.join("");
  }

  function openGlobalSearch() {
    if (!globalSearchModal || !globalSearchInput) return;
    globalSearchModal.style.display = "flex";
    globalSearchInput.value = "";
    renderGlobalSearchResults("");
    setTimeout(() => globalSearchInput.focus(), 30);
  }

  if (globalSearchClose) globalSearchClose.addEventListener("click", closeGlobalSearch);
  if (globalSearchModal) {
    globalSearchModal.addEventListener("click", (e) => {
      if (e.target === globalSearchModal) closeGlobalSearch();
    });
  }
  if (globalSearchInput) {
    globalSearchInput.addEventListener("input", () => renderGlobalSearchResults(globalSearchInput.value));
  }
  if (globalSearchResults) {
    globalSearchResults.addEventListener("click", (e) => {
      const nav = e.target.closest("button[data-nav-tab]");
      if (nav) {
        switchToTab(nav.getAttribute("data-nav-tab"));
        closeGlobalSearch();
        return;
      }
      const hi = e.target.closest("button[data-history-id]");
      if (hi) {
        const id = hi.getAttribute("data-history-id");
        const rec = historyRecords.find((x) => x.id === id);
        if (rec) {
          selectedHistoryId = id;
          lastRecord = rec;
          if (rec.tabId && rec.outputTargetId && rec.outputHtml) {
            document.querySelectorAll(".tab-panel").forEach((p) => p.classList.remove("is-active"));
            document.querySelectorAll(".tab-button").forEach((b) => b.classList.remove("is-active"));
            const btnTab = document.querySelector(`.tab-button[data-tab="${rec.tabId}"]`);
            if (btnTab) btnTab.classList.add("is-active");
            const pnl = $(rec.tabId);
            if (pnl) pnl.classList.add("is-active");
            const out = $(rec.outputTargetId);
            if (out) out.innerHTML = rec.outputHtml;
          }
          saveHistory();
          renderHistory();
        }
        closeGlobalSearch();
      }
    });
  }

  document.addEventListener("keydown", (e) => {
    const searchOpen = globalSearchModal && globalSearchModal.style.display === "flex";
    if (e.key === "Escape" && searchOpen) {
      e.preventDefault();
      closeGlobalSearch();
      return;
    }
    if (e.ctrlKey && String(e.key).toLowerCase() === "f") {
      e.preventDefault();
      if (searchOpen) {
        globalSearchInput?.focus();
        return;
      }
      openGlobalSearch();
      return;
    }
    if (e.ctrlKey && String(e.key).toLowerCase() === "s") {
      e.preventDefault();
      if (typeof window.__subnetOpenQuickExport === "function") window.__subnetOpenQuickExport();
      return;
    }
    if (e.ctrlKey && (e.key === "Enter" || e.code === "NumpadEnter")) {
      if (searchOpen) return;
      if (isTypingTarget(e.target)) return;
      e.preventDefault();
      const panel = document.querySelector(".tab-panel.is-active");
      const pid = panel ? panel.id : "";
      const bid = TAB_PRIMARY_BTN[pid];
      if (bid) {
        const btn = $(bid);
        if (btn && !btn.disabled) btn.click();
      }
    }
  });

  initResizableGrid2Layouts();
}

