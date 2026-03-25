// 子网计算内核：纯前端（浏览器可直接运行）

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function isNumericString(s) {
  return /^[0-9]+$/.test(s);
}

function normalizeSpaces(s) {
  return s.replace(/\u3000/g, " ").trim();
}

function pow2(exp) {
  // exp: BigInt
  return 1n << exp;
}

// ---------------- IPv4 ----------------

export function parseIPv4Strict(input) {
  const s = normalizeSpaces(input);
  const parts = s.split(".");
  assert(parts.length === 4, `IPv4 地址段数量错误：期望 4 段，实际 ${parts.length} 段`);

  const octets = parts.map((p, idx) => {
    assert(p.length > 0, `IP 地址第 ${idx + 1} 段为空，请检查输入`);
    assert(isNumericString(p), `IP 地址第 ${idx + 1} 段不是数字：${p}`);
    const n = Number(p);
    assert(n >= 0 && n <= 255, `IP 地址第 ${idx + 1} 段超出 0-255 范围：${p}`);
    return n;
  });

  const int = (BigInt(octets[0]) << 24n) | (BigInt(octets[1]) << 16n) | (BigInt(octets[2]) << 8n) | BigInt(octets[3]);
  return { octets, int };
}

export function ipv4IntToString(intValue) {
  const x = BigInt(intValue);
  const o1 = Number((x >> 24n) & 255n);
  const o2 = Number((x >> 16n) & 255n);
  const o3 = Number((x >> 8n) & 255n);
  const o4 = Number(x & 255n);
  return `${o1}.${o2}.${o3}.${o4}`;
}

export function ipv4MaskFromPrefix(prefixLen) {
  const p = Number(prefixLen);
  assert(p >= 0 && p <= 32, `CIDR 前缀必须在 0-32 范围内，当前：/${p}`);
  if (p === 0) return 0n;
  const mask = ((1n << 32n) - 1n) ^ ((1n << BigInt(32 - p)) - 1n);
  return mask;
}

export function ipv4PrefixFromMask(maskStr) {
  const { int: maskInt } = parseIPv4Strict(maskStr);
  // 验证掩码必须是连续的 1...0
  let seenZero = false;
  let ones = 0;
  for (let i = 31; i >= 0; i--) {
    const bit = (maskInt >> BigInt(i)) & 1n;
    if (bit === 1n) {
      assert(!seenZero, "子网掩码不是连续的（中间出现了 0 之后又出现 1）");
      ones++;
    } else {
      seenZero = true;
    }
  }
  return ones; // 0-32
}

/** 若掩码点分十进制合法数值但非连续 1，返回距离最近的标准掩码点分串；已合法则返回 null */
export function nearestValidIpv4MaskString(maskStr) {
  let maskInt;
  try {
    const { int } = parseIPv4Strict(String(maskStr || "").trim());
    maskInt = int;
  } catch {
    return null;
  }
  try {
    ipv4PrefixFromMask(String(maskStr || "").trim());
    return null;
  } catch {
    let best = 0n;
    let bestDiff = (1n << 33n);
    for (let p = 0; p <= 32; p += 1) {
      const m = ipv4MaskFromPrefix(p);
      const d = maskInt >= m ? maskInt - m : m - maskInt;
      if (d < bestDiff) {
        bestDiff = d;
        best = m;
      }
    }
    return ipv4IntToString(best);
  }
}

export function ipv4BinaryMask(maskInt) {
  const m = BigInt(maskInt);
  const parts = [];
  for (let i = 3; i >= 0; i--) {
    const oct = Number((m >> BigInt(i * 8)) & 255n);
    parts.push(oct.toString(2).padStart(8, "0"));
  }
  return parts.join(".");
}

export function detectIPv4AddressType(ipIntOrStr) {
  const { int } = typeof ipIntOrStr === "string" ? parseIPv4Strict(ipIntOrStr) : { int: BigInt(ipIntOrStr) };
  const firstOctet = Number((int >> 24n) & 255n);

  const isInPrefix = (prefixIp, prefixLen) => {
    const mask = ipv4MaskFromPrefix(prefixLen);
    return (int & mask) === (prefixIp & mask);
  };

  const privateRanges = [
    { name: "私网（10.0.0.0/8）", prefix: "10.0.0.0", len: 8 },
    { name: "私网（172.16.0.0/12）", prefix: "172.16.0.0", len: 12 },
    { name: "私网（192.168.0.0/16）", prefix: "192.168.0.0", len: 16 },
  ];
  for (const r of privateRanges) {
    const { int: pInt } = parseIPv4Strict(r.prefix);
    if (isInPrefix(pInt, r.len)) return r.name;
  }

  if (firstOctet === 127) return "环回地址（127.0.0.0/8）";
  if (isInPrefix(parseIPv4Strict("169.254.0.0").int, 16)) return "链路本地（169.254.0.0/16）";
  if (isInPrefix(parseIPv4Strict("0.0.0.0").int, 8)) return "保留/特定用途（0.0.0.0/8）";
  if (isInPrefix(parseIPv4Strict("224.0.0.0").int, 4)) return "组播（224.0.0.0/4）";
  if (isInPrefix(parseIPv4Strict("240.0.0.0").int, 4)) return "保留/未来使用（240.0.0.0/4）";
  if (isInPrefix(parseIPv4Strict("255.255.255.255").int, 32)) return "受限广播（255.255.255.255）";

  // 这里无法穷尽所有“保留/特殊”段，给出通用分类
  return "公网（未命中特殊/私网范围）";
}

export function detectIPv4Class(networkIntOrStr) {
  const { int } = typeof networkIntOrStr === "string" ? parseIPv4Strict(networkIntOrStr) : { int: BigInt(networkIntOrStr) };
  const firstOctet = Number((int >> 24n) & 255n);
  if (firstOctet >= 1 && firstOctet <= 126) return "A 类";
  if (firstOctet >= 128 && firstOctet <= 191) return "B 类";
  if (firstOctet >= 192 && firstOctet <= 223) return "C 类";
  if (firstOctet >= 224 && firstOctet <= 239) return "D 类（组播）";
  if (firstOctet >= 240 && firstOctet <= 255) return "E 类（保留）";
  return "未识别";
}

export function parseIPv4CIDR(input) {
  const s = normalizeSpaces(input);
  const m = s.match(/^(.+?)\/(\d{1,2})$/);
  assert(!!m, `IPv4 CIDR 格式错误：期望 "a.b.c.d/xx"，当前：${input}`);
  const ipPart = m[1].trim();
  const prefix = Number(m[2]);
  assert(prefix >= 0 && prefix <= 32, `CIDR 前缀必须在 0-32 范围内：/${prefix}`);
  const { int } = parseIPv4Strict(ipPart);
  return { ipInt: int, prefixLen: prefix };
}

export function parseIPv4WithMask(input) {
  // 支持：IP + 空格 + 掩码（如 192.168.1.10 255.255.255.0）
  const s = normalizeSpaces(input);
  // 注意：用户可能输入多个空格/Tab；必须按“任意空白”切分
  const parts = s.split(/\s+/);
  assert(parts.length >= 2, `IP + 掩码 模式格式错误：期望 "a.b.c.d 255.255.255.0"，当前：${input}`);
  const ipPart = parts[0];
  const maskPart = parts[1];
  const { int: ipInt } = parseIPv4Strict(ipPart);
  const prefixLen = ipv4PrefixFromMask(maskPart);
  return { ipInt, prefixLen };
}

export function parseIPv4CoreInput(input) {
  const s = normalizeSpaces(input);
  // 识别：包含 / -> CIDR；否则尝试 IP + 掩码；否则报错（本工具核心计算需要掩码信息）
  if (s.includes("/")) return parseIPv4CIDR(s);
  // 使用任意空白判断，兼容 Tab/多空格
  if (/\s+/.test(s)) return parseIPv4WithMask(s);
  throw new Error("IPv4 核心计算需要掩码信息：请使用 'IP/前缀' 或 'IP + 子网掩码' 或直接粘贴 '网段/前缀'。");
}

export function ipv4CalcTriplet(ipInt, prefixLen) {
  const mask = ipv4MaskFromPrefix(prefixLen);
  const network = ipInt & mask;
  const broadcast = network | (~mask & ((1n << 32n) - 1n));

  const total = 1n << BigInt(32 - prefixLen);

  // 可用主机数（可配置：扣除网络/广播）
  const usableWhenSubtract = () => {
    if (prefixLen === 32) return 1n;
    if (prefixLen === 31) return 2n; // /31 常用于点对点，通常不扣除
    return total - 2n;
  };

  return {
    maskInt: mask,
    network,
    broadcast,
    totalAddrs: total,
    usableHostsSubtract: usableWhenSubtract(),
  };
}

export function ipv4FirstLastUsable(network, broadcast, prefixLen, subtractNB) {
  if (!subtractNB) {
    return { first: network, last: broadcast };
  }
  if (prefixLen === 32) return { first: network, last: broadcast };
  if (prefixLen === 31) return { first: network, last: broadcast }; // 不扣除
  return { first: network + 1n, last: broadcast - 1n };
}

export function ipv4CoreCompute(input, { subtractNB } = { subtractNB: true }) {
  const parsed = parseIPv4CoreInput(input);
  const { ipInt, prefixLen } = parsed;
  const triplet = ipv4CalcTriplet(ipInt, prefixLen);
  const { first, last } = ipv4FirstLastUsable(triplet.network, triplet.broadcast, prefixLen, subtractNB);
  const usableCount = subtractNB ? (first > last ? 0n : last - first + 1n) : triplet.totalAddrs;

  const netMaskStr = ipv4IntToString(triplet.maskInt);
  const netClass = detectIPv4Class(triplet.network);
  const netType = detectIPv4AddressType(triplet.network);

  // 位数
  const subnetBits = prefixLen;
  const hostBits = 32 - prefixLen;
  const utilization = usableCount === 0n ? 0 : Number(usableCount) / Number(triplet.totalAddrs);

  return {
    version: "IPv4",
    input: normalizeSpaces(input),
    prefixLen,
    networkInt: triplet.network,
    broadcastInt: triplet.broadcast,
    maskInt: triplet.maskInt,
    netmask: netMaskStr,
    network: ipv4IntToString(triplet.network),
    broadcast: ipv4IntToString(triplet.broadcast),
    maskBinary: ipv4BinaryMask(triplet.maskInt),
    firstUsable: ipv4IntToString(first),
    lastUsable: ipv4IntToString(last),
    usableCount,
    totalAddrs: triplet.totalAddrs,
    subnetBits,
    hostBits,
    totalBits: 32,
    addrClass: netClass,
    addrType: netType,
    utilization,
  };
}

export function ipv4PrefixForHosts(parentPrefix, subtractNB, desiredHosts) {
  const desired = BigInt(desiredHosts);
  assert(desired > 0n, "期望主机数必须大于 0");
  // 目标：在父网段前缀范围内选“最小且足够”的子网（避免地址浪费）
  // 前缀越大，子网越小，因此应在所有可行前缀中选择“最大的 p”（即最小块）。
  let best = null;
  for (let p = parentPrefix; p <= 32; p++) {
    const trip = ipv4CalcTriplet(0n, p);
    const usable = subtractNB ? trip.usableHostsSubtract : trip.totalAddrs;
    if (usable >= desired) best = p;
  }
  assert(best !== null, "父网段划分无法满足期望主机数（超出地址空间）。");
  return best;
}

export function ipv4ReverseCompute(parentCIDR, mode, opts) {
  const { subtractNB, strategy } = opts;
  const parent = parseIPv4CIDR(parentCIDR);
  const parentNetworkCalc = ipv4CalcTriplet(parent.ipInt, parent.prefixLen);
  const parentNetwork = parentNetworkCalc.network;
  const parentPrefix = parent.prefixLen;

  if (mode === "hosts") {
    const desiredHosts = BigInt(opts.desiredHosts);
    assert(desiredHosts > 0n, "期望主机数必须大于 0");

    // 找到最小能装下的子网（即前缀越大，子网越小；利用率通常更高）
    let bestPrefix = null;
    let bestWaste = null;
    for (let p = parentPrefix; p <= 32; p++) {
      const trip = ipv4CalcTriplet(0n, p);
      const usable = subtractNB ? trip.usableHostsSubtract : trip.totalAddrs;
      if (usable >= desiredHosts) {
        const waste = usable - desiredHosts;
        if (bestPrefix === null) {
          bestPrefix = p;
          bestWaste = waste;
          continue;
        }
        // 最优/不浪费倾向于 waste 更小；不超网也已经由 p>=parentPrefix保证
        if (waste < bestWaste) {
          bestPrefix = p;
          bestWaste = waste;
        }
      }
    }
    assert(bestPrefix !== null, "无法在父网段内满足期望主机数。");

    const rec = ipv4CoreCompute(`${ipv4IntToString(parentNetwork)}/${bestPrefix}`, { subtractNB });
    const subnetCount = 1n << BigInt(bestPrefix - parentPrefix);
    return {
      mode,
      strategy,
      parentNetwork: ipv4IntToString(parentNetwork),
      parentPrefix,
      recommended: { prefixLen: bestPrefix, ...rec },
      availableSubnetCount: subnetCount,
    };
  }

  if (mode === "subnets") {
    const desiredSubnets = BigInt(opts.desiredSubnets);
    assert(desiredSubnets > 0n, "期望子网数必须大于 0");

    // 需要 2^(p-parentPrefix) >= desiredSubnets
    let bestPrefix = null;
    let bestUnused = null;
    for (let p = parentPrefix; p <= 32; p++) {
      const totalSubnets = 1n << BigInt(p - parentPrefix);
      if (totalSubnets >= desiredSubnets) {
        const unused = totalSubnets - desiredSubnets;
        // 最优/不浪费：优先 unused 最小；不超网：仍由 p>=parentPrefix保证
        if (bestPrefix === null || unused < bestUnused) {
          bestPrefix = p;
          bestUnused = unused;
        }
      }
    }
    assert(bestPrefix !== null, "无法在父网段内满足期望子网数。");

    const totalSubnets = 1n << BigInt(bestPrefix - parentPrefix);
    const subnetSize = 1n << BigInt(32 - bestPrefix);
    const subnets = [];
    for (let i = 0n; i < desiredSubnets; i++) {
      const snNet = parentNetwork + i * subnetSize;
      subnets.push(ipv4CoreCompute(`${ipv4IntToString(snNet)}/${bestPrefix}`, { subtractNB }));
    }
    return {
      mode,
      strategy,
      parentNetwork: ipv4IntToString(parentNetwork),
      parentPrefix,
      recommended: { prefixLen: bestPrefix },
      availableSubnetCount: totalSubnets,
      unusedSubnets: totalSubnets - desiredSubnets,
      previewSubnets: subnets,
    };
  }

  throw new Error("未知反向计算模式。");
}

export function ipv4SplitEqual(parentCIDR, subnetCount, { subtractNB } = { subtractNB: true }, { startNo } = { startNo: 1 }) {
  const parent = parseIPv4CIDR(parentCIDR);
  const trip = ipv4CalcTriplet(parent.ipInt, parent.prefixLen);
  const parentNetwork = trip.network;
  const parentPrefix = parent.prefixLen;
  const desired = Number(subnetCount);
  assert(Number.isFinite(desired) && desired >= 1, "子网数量必须是合法正整数。");

  // 找到最小前缀 p，使得子网数 >= desired
  let p = parentPrefix;
  while (p <= 32) {
    const totalSubnets = 1n << BigInt(p - parentPrefix);
    if (totalSubnets >= BigInt(desired)) break;
    p++;
  }
  assert(p <= 32, "父网段范围内无法满足子网数量要求。");

  const totalSubnets = 1n << BigInt(p - parentPrefix);
  const subnetSize = 1n << BigInt(32 - p);
  const subnets = [];
  for (let i = 0; i < desired; i++) {
    const snNet = parentNetwork + BigInt(i) * subnetSize;
    const one = ipv4CoreCompute(`${ipv4IntToString(snNet)}/${p}`, { subtractNB });
    one.subnetIndex = startNo + i;
    subnets.push(one);
  }
  return {
    parent: `${ipv4IntToString(parentNetwork)}/${parentPrefix}`,
    parentPrefix,
    newPrefix: p,
    totalAddrsInParent: trip.totalAddrs,
    totalSubnets,
    unusedSubnets: totalSubnets - BigInt(desired),
    subnetSize,
    subnets,
  };
}

export function ipv4VlsmPlan(parentCIDR, requests, { subtractNB } = { subtractNB: true }, strategy = "maxFirst") {
  // 兼容旧调用方式：将实现切换到增强版，支持更多策略与更准确的空闲块选择。
  return ipv4VlsmPlanEnhanced(parentCIDR, requests, { subtractNB }, strategy);
  // 以下旧实现保留在文件中（不可达），避免一次性大改导致其他逻辑回归。
  const parent = parseIPv4CIDR(parentCIDR);
  const parentTrip = ipv4CalcTriplet(parent.ipInt, parent.prefixLen);
  const parentNetwork = parentTrip.network;
  const parentPrefix = parent.prefixLen;
  const parentBroadcast = parentTrip.broadcast;

  const reqs = requests.map((r, idx) => ({
    name: r.name || `Subnet-${idx + 1}`,
    hosts: Number(r.hosts),
    note: r.note || "",
    order: idx,
  }));

  for (const r of reqs) {
    assert(Number.isFinite(r.hosts) && r.hosts >= 1, `子网 ${r.name} 的主机数必须为正整数。`);
  }

  const sorted = [...reqs];
  if (strategy === "maxFirst") sorted.sort((a, b) => b.hosts - a.hosts || a.order - b.order);
  else if (strategy === "minFirst") sorted.sort((a, b) => a.hosts - b.hosts || a.order - b.order);
  else if (strategy === "order") sorted.sort((a, b) => a.order - b.order);
  else throw new Error("未知 VLSM 分配策略。");

  let nextFree = parentNetwork;
  const allocations = [];
  let totalAllocated = 0n;
  let totalWasteAlignment = 0n;

  const alignUp = (value, blockSize) => {
    if (blockSize === 0n) return value;
    const rem = value % blockSize;
    if (rem === 0n) return value;
    return value + (blockSize - rem);
  };

  for (const r of sorted) {
    const pNeeded = ipv4PrefixForHosts(parentPrefix, subtractNB, r.hosts);
    const blockSize = 1n << BigInt(32 - pNeeded);
    const alignedStart = alignUp(nextFree, blockSize);
    const start = alignedStart;
    const end = start + blockSize - 1n;
    if (end > parentBroadcast) {
      // 在“对齐后的起点 start”到父网段末尾，仍能占用的连续地址数；若 start 已超出父网段则按 0 处理
      let availableAddr = parentBroadcast - start + 1n;
      if (availableAddr < 0n) availableAddr = 0n;
      const missingAddr = blockSize > availableAddr ? blockSize - availableAddr : 0n;

      // 下面的主机数仅用于提示信息：当地址不足以形成“完整 CIDR 子网块”时，网络地址/广播地址无法严格落在父网段边界内。
      // 因此这里按“可用地址数量粗略折算”为给用户判断用例，不影响真实 CIDR 是否能落在父网段内。
      const requiredUsableHosts = subtractNB
        ? ipv4CalcTriplet(0n, pNeeded).usableHostsSubtract
        : blockSize;
      let availableUsableApprox = subtractNB ? availableAddr : availableAddr;
      if (subtractNB) {
        if (pNeeded === 32) availableUsableApprox = availableAddr; // /32 理论上无网络/广播扣除差异
        else if (pNeeded === 31) availableUsableApprox = availableAddr; // /31 不扣除网络/广播
        else {
          // 粗略：每个完整块通常扣除 2 个（网络/广播）
          availableUsableApprox = availableAddr >= 3n ? availableAddr - 2n : availableAddr >= 1n ? 1n : 0n;
        }
      }
      const missingHosts = requiredUsableHosts > r.hosts ? 0n : r.hosts > availableUsableApprox ? r.hosts - availableUsableApprox : 0n;

      const suggestByHostsEnough = availableUsableApprox >= BigInt(r.hosts);

      throw new Error(
        suggestByHostsEnough
          ? `VLSM 超出父网段：子网 "${r.name}" 需要 /${pNeeded}（块大小 ${blockSize} 地址），但在当前对齐起点处仅剩 ${availableAddr} 地址（缺少 ${missingAddr} 地址），无法形成完整连续 CIDR 块。主机数按可用地址粗略折算后仍“看起来足够”，该问题通常由“地址块对齐/前序分配顺序”导致。建议：改用其他分配策略（如从“最大优先”改“最小优先”）或调整需求顺序。`
          : `VLSM 超出父网段：子网 "${r.name}" 需要 /${pNeeded}（块大小 ${blockSize} 地址，对应所需主机数 ${r.hosts}），但在当前对齐起点处仅剩 ${availableAddr} 地址。缺少 ${missingAddr} 地址（按可用地址粗略折算主机容量约 ${availableUsableApprox}，还差 ${missingHosts} 个主机）。建议：减少 "${r.name}" 的主机需求或调整分配策略/顺序。`
      );
    }
    const waste = start - nextFree;
    totalWasteAlignment += waste;

    const one = ipv4CoreCompute(`${ipv4IntToString(start)}/${pNeeded}`, { subtractNB });
    allocations.push({
      name: r.name,
      hostsNeed: r.hosts,
      note: r.note,
      prefixLen: pNeeded,
      network: one.network,
      broadcast: one.broadcast,
      netmask: one.netmask,
      maskBinary: one.maskBinary,
      firstUsable: one.firstUsable,
      lastUsable: one.lastUsable,
      usableCount: one.usableCount,
      totalAddrs: one.totalAddrs,
      utilization: one.utilization,
      interval: { start, end },
      order: r.order,
    });

    allocations.sort((a, b) => Number(a.interval.start - b.interval.start)); // stable for display
    nextFree = end + 1n;
    totalAllocated += blockSize;
  }

  const parentTotal = parentTrip.totalAddrs;
  const freeAfter = parentBroadcast - (nextFree - 1n);
  return {
    parent: `${ipv4IntToString(parentNetwork)}/${parentPrefix}`,
    parentTotalAddrs: parentTotal,
    allocations,
    totalAllocated,
    totalWasteAlignment,
    freeRemaining: freeAfter < 0n ? 0n : freeAfter,
    utilization: totalAllocated === 0n ? 0 : Number(totalAllocated) / Number(parentTotal),
    strategy,
  };
}

// 增强版 VLSM 分配：基于“可用区间列表 + CIDR块对齐”选择放置位置
function ipv4VlsmPlanEnhanced(parentCIDR, requests, { subtractNB } = { subtractNB: true }, strategy = "maxFirst") {
  const parent = parseIPv4CIDR(parentCIDR);
  const parentTrip = ipv4CalcTriplet(parent.ipInt, parent.prefixLen);
  const parentNetwork = parentTrip.network;
  const parentPrefix = parent.prefixLen;
  const parentBroadcast = parentTrip.broadcast;

  const reqs = requests.map((r, idx) => ({
    name: r.name || `Subnet-${idx + 1}`,
    hosts: Number(r.hosts),
    note: r.note || "",
    order: idx,
  }));

  for (const r of reqs) {
    assert(Number.isFinite(r.hosts) && r.hosts >= 1, `子网 ${r.name} 的主机数必须为正整数。`);
  }

  const alignUp = (value, blockSize) => {
    if (blockSize === 0n) return value;
    const rem = value % blockSize;
    if (rem === 0n) return value;
    return value + (blockSize - rem);
  };
  const alignDown = (value, blockSize) => {
    if (blockSize === 0n) return value;
    const rem = value % blockSize;
    return value - rem;
  };
  const intervalLen = (it) => it.end - it.start + 1n;

  const splitIntervalsSubtract = (intervals, subStart, subEnd) => {
    // subStart/subEnd inclusive
    const next = [];
    for (const it of intervals) {
      if (subEnd < it.start || subStart > it.end) {
        next.push(it);
        continue;
      }
      if (subStart > it.start) next.push({ start: it.start, end: subStart - 1n });
      if (subEnd < it.end) next.push({ start: subEnd + 1n, end: it.end });
    }
    next.sort((a, b) => (a.start < b.start ? -1 : 1));
    const merged = [];
    for (const it of next) {
      if (!merged.length) merged.push(it);
      else {
        const last = merged[merged.length - 1];
        if (last.end + 1n === it.start) last.end = it.end;
        else merged.push(it);
      }
    }
    return merged;
  };

  const findLargestFreeLenIn = (intervals) => intervals.reduce((mx, it) => (intervalLen(it) > mx ? intervalLen(it) : mx), 0n);

  const buildAllocation = (r, pNeeded, start) => {
    const blockSize = 1n << BigInt(32 - pNeeded);
    const end = start + blockSize - 1n;
    const one = ipv4CoreCompute(`${ipv4IntToString(start)}/${pNeeded}`, { subtractNB });
    return {
      name: r.name,
      hostsNeed: r.hosts,
      note: r.note,
      prefixLen: pNeeded,
      network: one.network,
      broadcast: one.broadcast,
      netmask: one.netmask,
      maskBinary: one.maskBinary,
      firstUsable: one.firstUsable,
      lastUsable: one.lastUsable,
      usableCount: one.usableCount,
      totalAddrs: one.totalAddrs,
      utilization: one.utilization,
      interval: { start, end },
      order: r.order,
    };
  };

  const sortByHostsDesc = () => [...reqs].sort((a, b) => b.hosts - a.hosts || a.order - b.order);
  const sortByHostsAsc = () => [...reqs].sort((a, b) => a.hosts - b.hosts || a.order - b.order);
  const sortByOrderAsc = () => [...reqs].sort((a, b) => a.order - b.order);

  // Fixed Mask：等长子网切割（忽略每个子网实际主机需求差异）
  if (strategy === "fixedMask") {
    const desiredCount = reqs.length;

    let p = parentPrefix;
    while (p <= 32) {
      const totalSubnets = 1n << BigInt(p - parentPrefix);
      if (totalSubnets >= BigInt(desiredCount)) break;
      p++;
    }
    assert(p <= 32, "父网段无法满足固定掩码的子网数量要求。");

    const blockSize = 1n << BigInt(32 - p);
    const sortedReq = sortByOrderAsc();

    const allocations = [];
    let totalAllocated = 0n;

    for (let i = 0; i < desiredCount; i++) {
      const r = sortedReq[i];
      const start = parentNetwork + BigInt(i) * blockSize;
      const end = start + blockSize - 1n;
      assert(end <= parentBroadcast, "固定掩码分配超出父网段。");

      const one = ipv4CoreCompute(`${ipv4IntToString(start)}/${p}`, { subtractNB });
      allocations.push({
        name: r.name,
        hostsNeed: r.hosts,
        note: r.note,
        prefixLen: p,
        network: one.network,
        broadcast: one.broadcast,
        netmask: one.netmask,
        maskBinary: one.maskBinary,
        firstUsable: one.firstUsable,
        lastUsable: one.lastUsable,
        usableCount: one.usableCount,
        totalAddrs: one.totalAddrs,
        utilization: one.utilization,
        interval: { start, end },
        order: r.order,
      });
      totalAllocated += blockSize;
    }

    const freeRemaining = (() => {
      const usedEnd = parentNetwork + BigInt(desiredCount) * blockSize - 1n;
      const remain = parentBroadcast - usedEnd;
      return remain < 0n ? 0n : remain;
    })();

    return {
      parent: `${ipv4IntToString(parentNetwork)}/${parentPrefix}`,
      parentTotalAddrs: parentTrip.totalAddrs,
      allocations,
      totalAllocated,
      totalWasteAlignment: 0n,
      freeRemaining,
      utilization: totalAllocated === 0n ? 0 : Number(totalAllocated) / Number(parentTrip.totalAddrs),
      strategy,
    };
  }

  // 非固定掩码：维护 freeIntervals，按 CIDR块对齐选择空闲块放置
  let freeIntervals = [{ start: parentNetwork, end: parentBroadcast }];
  let cursor = parentNetwork; // 仅用于 sequential/order 的“从前往后”

  let sorted;
  if (strategy === "maxFirst") sorted = sortByHostsDesc();
  else if (strategy === "minFirst") sorted = sortByHostsAsc();
  else if (strategy === "sequential" || strategy === "order") sorted = sortByOrderAsc();
  else if (strategy === "bestFit" || strategy === "aggregation" || strategy === "defrag" || strategy === "balanced") sorted = sortByHostsDesc();
  else throw new Error("未知 VLSM 分配策略。");

  let totalAllocated = 0n;
  let totalWasteAlignment = 0n;
  const allocations = [];

  for (const r of sorted) {
    const pNeeded = ipv4PrefixForHosts(parentPrefix, subtractNB, r.hosts);
    const blockSize = 1n << BigInt(32 - pNeeded);

    const restrictToCursor = strategy === "sequential" || strategy === "order";

    // 生成所有对齐候选（跨多个自由区间）
    const candidates = [];
    for (const it of freeIntervals) {
      if (restrictToCursor && it.end < cursor) continue;
      const minStart = restrictToCursor ? (cursor > it.start ? cursor : it.start) : it.start;

      const s1 = alignUp(minStart, blockSize);
      const e1 = s1 + blockSize - 1n;
      if (s1 <= it.end && e1 <= it.end) candidates.push({ start: s1, end: e1, freeIt: it });

      const rightStartBase = it.end - blockSize + 1n;
      const s2 = alignDown(rightStartBase, blockSize);
      const e2 = s2 + blockSize - 1n;
      if (s2 >= it.start && e2 <= it.end) candidates.push({ start: s2, end: e2, freeIt: it });
    }

    // 去重
    const uniq = [];
    const seen = new Set();
    for (const c of candidates) {
      const k = `${c.start.toString()}_${c.end.toString()}`;
      if (seen.has(k)) continue;
      seen.add(k);
      uniq.push(c);
    }

    if (!uniq.length) {
      const largestFree = findLargestFreeLenIn(freeIntervals);
      const missingAddr = blockSize > largestFree ? blockSize - largestFree : 0n;
      const availableUsable = subtractNB ? (largestFree >= 3n ? largestFree - 2n : largestFree) : largestFree;
      const missingHosts = BigInt(r.hosts) > availableUsable ? BigInt(r.hosts) - availableUsable : 0n;

      throw new Error(
        `VLSM 超出父网段：子网 "${r.name}" 需要 /${pNeeded}（块大小 ${blockSize} 地址），但最大连续空闲地址数 ${largestFree}（缺少 ${missingAddr} 地址）。按可用地址粗略折算主机容量约 ${availableUsable}，还差 ${missingHosts} 个主机。建议：减少 "${r.name}" 主机需求或调整分配策略/顺序。`
      );
    }

    const score = (cand) => {
      const afterFree = splitIntervalsSubtract(freeIntervals, cand.start, cand.end);
      const largestAfter = findLargestFreeLenIn(afterFree);
      const intervalWaste = intervalLen(cand.freeIt) - blockSize;

      // 分割碎片数近似：0=完整吃掉区间；1=从一侧吃掉；2=中间切开
      const leftExists = cand.start > cand.freeIt.start;
      const rightExists = cand.end < cand.freeIt.end;
      const fragmentsCount = (leftExists ? 1 : 0) + (rightExists ? 1 : 0);

      return {
        start: cand.start,
        end: cand.end,
        afterFree,
        largestAfter,
        intervalWaste,
        fragmentsCount,
      };
    };

    const scored = uniq.map((c) => score(c));

    // 策略选择
    let chosen;
    if (strategy === "maxFirst") {
      // 最大优先：尽量放在更低起点，减小散碎空洞
      scored.sort((a, b) => (a.start < b.start ? -1 : 1));
      chosen = scored[0];
    } else if (strategy === "minFirst") {
      // 最小优先：最小浪费（更倾向塞进更小的空闲区间）
      scored.sort((a, b) => {
        if (a.intervalWaste < b.intervalWaste) return -1;
        if (a.intervalWaste > b.intervalWaste) return 1;
        if (a.fragmentsCount < b.fragmentsCount) return -1;
        if (a.fragmentsCount > b.fragmentsCount) return 1;
        return a.start < b.start ? -1 : 1;
      });
      chosen = scored[0];
    } else if (strategy === "bestFit") {
      // 按需匹配：最小浪费优先
      scored.sort((a, b) => {
        if (a.intervalWaste < b.intervalWaste) return -1;
        if (a.intervalWaste > b.intervalWaste) return 1;
        if (a.fragmentsCount < b.fragmentsCount) return -1;
        if (a.fragmentsCount > b.fragmentsCount) return 1;
        return a.start < b.start ? -1 : 1;
      });
      chosen = scored[0];
    } else if (strategy === "sequential" || strategy === "order") {
      // 顺序分配：从 cursor 往后，取最靠前的可行块
      scored.sort((a, b) => (a.start < b.start ? -1 : 1));
      chosen = scored[0];
    } else if (strategy === "balanced") {
      // 平衡分配：尽量保留最大的连续空闲块
      scored.sort((a, b) => {
        if (a.largestAfter > b.largestAfter) return -1;
        if (a.largestAfter < b.largestAfter) return 1;
        if (a.fragmentsCount < b.fragmentsCount) return -1;
        if (a.fragmentsCount > b.fragmentsCount) return 1;
        if (a.intervalWaste < b.intervalWaste) return -1;
        if (a.intervalWaste > b.intervalWaste) return 1;
        return a.start < b.start ? -1 : 1;
      });
      chosen = scored[0];
    } else if (strategy === "aggregation") {
      // 聚合导向：更靠前的地址 + 尽量保留大空闲块
      scored.sort((a, b) => {
        if (a.start < b.start) return -1;
        if (a.start > b.start) return 1;
        if (a.largestAfter > b.largestAfter) return -1;
        if (a.largestAfter < b.largestAfter) return 1;
        if (a.fragmentsCount < b.fragmentsCount) return -1;
        if (a.fragmentsCount > b.fragmentsCount) return 1;
        return 0;
      });
      chosen = scored[0];
    } else if (strategy === "defrag") {
      // 碎片整理：碎片数更少优先，再看最大连续空闲块
      scored.sort((a, b) => {
        if (a.fragmentsCount < b.fragmentsCount) return -1;
        if (a.fragmentsCount > b.fragmentsCount) return 1;
        if (a.largestAfter > b.largestAfter) return -1;
        if (a.largestAfter < b.largestAfter) return 1;
        if (a.intervalWaste < b.intervalWaste) return -1;
        if (a.intervalWaste > b.intervalWaste) return 1;
        return a.start < b.start ? -1 : 1;
      });
      chosen = scored[0];
    } else {
      scored.sort((a, b) => (a.start < b.start ? -1 : 1));
      chosen = scored[0];
    }

    const chosenStart = chosen.start;
    const chosenEnd = chosen.end;

    // 更新 freeIntervals
    freeIntervals = splitIntervalsSubtract(freeIntervals, chosenStart, chosenEnd);

    // 更新 cursor
    if (strategy === "sequential" || strategy === "order") cursor = chosenEnd + 1n;
    else cursor = chosenStart; // 保持对齐起点可控（不强制推进）

    // 产出分配结果
    const oneAlloc = buildAllocation(r, pNeeded, chosenStart);
    allocations.push(oneAlloc);
    totalAllocated += blockSize;
    totalWasteAlignment += chosen.intervalWaste;
  }

  allocations.sort((a, b) => (a.interval.start < b.interval.start ? -1 : 1));
  const freeRemaining = freeIntervals.reduce((sum, it) => sum + intervalLen(it), 0n);

  return {
    parent: `${ipv4IntToString(parentNetwork)}/${parentPrefix}`,
    parentTotalAddrs: parentTrip.totalAddrs,
    allocations,
    totalAllocated,
    totalWasteAlignment,
    freeRemaining,
    utilization: totalAllocated === 0n ? 0 : Number(totalAllocated) / Number(parentTrip.totalAddrs),
    strategy,
  };
}

// ---------------- IPv6 ----------------

function parseIPv6ToBigIntStrict(input) {
  // 需要可变：当检测到 IPv4 尾部时会替换原始字符串
  let s = normalizeSpaces(input).toLowerCase();
  assert(s.length > 0, "IPv6 输入不能为空。");

  // 支持最后部分为 IPv4 形式，例如 ::ffff:192.0.2.1
  if (s.includes(".")) {
    const m = s.match(/^(.*:)([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})$/);
    assert(!!m, `IPv6 末尾包含 IPv4 但格式不合法：${input}`);
    const ipv4TailInt = parseIPv4Strict(m[2]).int;
    const upper16 = (ipv4TailInt >> 16n) & 0xffffn;
    const lower16 = ipv4TailInt & 0xffffn;
    const upperHex = upper16.toString(16);
    const lowerHex = lower16.toString(16);
    s = m[1] + upperHex + ":" + lowerHex;
  }

  const parts = s.split("::");
  assert(parts.length <= 2, `IPv6 冒号使用过多（只能出现一次 "::"）：${input}`);
  const left = parts[0] ? parts[0].split(":").filter((x) => x.length > 0) : [];
  const right = parts.length === 2 && parts[1] ? parts[1].split(":").filter((x) => x.length > 0) : [];

  // 如果没有 ::，长度必须为 8
  if (parts.length === 1) {
    assert(left.length === 8, `IPv6 组数错误：期望 8 组，实际 ${left.length} 组`);
  }

  const hasDouble = parts.length === 2;
  const missing = hasDouble ? 8 - (left.length + right.length) : 0;
  assert(!hasDouble || missing >= 1, `IPv6 "::" 展开后组数不足：${input}`);

  const all = [];
  for (const p of left) all.push(parseHextet(p, input));
  if (hasDouble) {
    for (let i = 0; i < missing; i++) all.push(0);
  }
  for (const p of right) all.push(parseHextet(p, input));

  if (all.length !== 8) {
    // 保险
    assert(all.length === 8, `IPv6 解析失败：展开后组数为 ${all.length}，不是 8。`);
  }

  // BigInt 拼接
  let res = 0n;
  for (let i = 0; i < 8; i++) {
    res = (res << 16n) | BigInt(all[i]);
  }
  return res;
}

function parseHextet(token, original) {
  const t = token.trim();
  assert(t.length > 0, `IPv6 存在空组：${original}`);
  assert(/^[0-9a-f]{1,4}$/.test(t), `IPv6 组格式错误（期望 1-4 个十六进制字符）：${t}（原始：${original}）`);
  return parseInt(t, 16);
}

export function parseIPv6Strict(input) {
  const addr = parseIPv6ToBigIntStrict(input);
  return { addrInt: addr };
}

/** 仅地址本体（不含 /前缀）的智能纠错提示 */
export function suggestIpv6AddrHint(input) {
  const s = normalizeSpaces(String(input || ""));
  if (!s) return "";
  if (s.includes("/")) {
    return "智能提示：此处只填 IPv6 地址，不要带 / 与前缀数字；前缀请在「Prefix length」中填写。";
  }
  if (/[^0-9a-fA-F:.]/.test(s)) {
    return "智能提示：含有非法字符，仅允许 0-9、A-F、a-f、冒号「:」与点「.」（点仅用于末尾 IPv4 映射写法）。";
  }
  if ((s.match(/::/g) || []).length > 1) {
    return "智能提示：「::」只能出现一次，表示一段连续的全零十六位组。";
  }
  if (s.includes(":::") || /:{3,}/.test(s)) {
    return "智能提示：不能连续多个冒号写成「:::」等形式，仅允许单独的「::」压缩。";
  }
  try {
    parseIPv6ToBigIntStrict(s);
    return "";
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    if (msg.includes("IPv6 输入不能为空")) return "";
    return `智能提示：${msg}`;
  }
}

/** 前缀长度框（0～128 整数） */
export function suggestIpv6PrefixHint(prefRaw) {
  const t = String(prefRaw ?? "").trim();
  if (t === "") return "";
  if (!/^\d+$/.test(t)) return "智能提示：前缀应为 0～128 的整数。";
  const n = Number(t);
  if (!Number.isInteger(n) || n < 0 || n > 128) {
    return `智能提示：前缀须在 0～128 之间，当前为 /${t}`;
  }
  return "";
}

/** 完整 CIDR「地址/前缀」（用于子网规划父网段、双栈等） */
export function suggestIpv6CidrHint(cidrRaw) {
  const s = normalizeSpaces(String(cidrRaw || ""));
  if (!s) return "";
  if ((s.match(/\//g) || []).length > 1) {
    return "智能提示：CIDR 只应包含一个「/」分隔地址与前缀。";
  }
  const slash = s.indexOf("/");
  if (slash < 0) {
    const ah = suggestIpv6AddrHint(s);
    if (ah) return ah;
    return "智能提示：请使用 CIDR 格式「地址/前缀」，例如 2001:db8::/48。";
  }
  const addrPart = s.slice(0, slash).trim();
  const prefPart = s.slice(slash + 1).trim();
  if (!prefPart) return "智能提示：「/」后应填写前缀长度（0～128 的整数）。";
  if (!/^\d+$/.test(prefPart)) {
    return `智能提示：「/」后应为整数前缀，当前为「${prefPart}」。`;
  }
  const pr = Number(prefPart);
  if (!Number.isInteger(pr) || pr < 0 || pr > 128) {
    return `智能提示：前缀须在 0～128 之间，当前 /${prefPart}`;
  }
  if (!addrPart) return "智能提示：「/」前应填写 IPv6 地址。";
  const ah = suggestIpv6AddrHint(addrPart);
  if (ah) return ah;
  return "";
}

export function ipv6IntToHextets(addrInt) {
  let a = BigInt(addrInt);
  const hextets = new Array(8);
  for (let i = 7; i >= 0; i--) {
    hextets[i] = Number(a & 0xffffn);
    a = a >> 16n;
  }
  return hextets;
}

export function ipv6IntToExpanded(addrInt) {
  let a = BigInt(addrInt);
  const parts = new Array(8);
  for (let i = 7; i >= 0; i--) {
    const v = Number(a & 0xffffn);
    parts[i] = v.toString(16).padStart(4, "0");
    a = a >> 16n;
  }
  return parts.join(":");
}

export function ipv6IntToCompressed(addrInt) {
  const expanded = ipv6IntToExpanded(addrInt);
  const hextets = expanded.split(":").map((h) => parseInt(h, 16));

  // 找最长 0 连续段（长度>=2）
  let bestStart = -1;
  let bestLen = 0;
  let curStart = -1;
  let curLen = 0;
  for (let i = 0; i < 8; i++) {
    if (hextets[i] === 0) {
      if (curStart === -1) curStart = i;
      curLen++;
    } else {
      if (curLen > bestLen && curLen >= 2) {
        bestLen = curLen;
        bestStart = curStart;
      }
      curStart = -1;
      curLen = 0;
    }
  }
  if (curLen > bestLen && curLen >= 2) {
    bestLen = curLen;
    bestStart = curStart;
  }

  const parts = [];
  for (let i = 0; i < 8; i++) {
    if (bestStart !== -1 && i === bestStart) {
      parts.push("");
      i += bestLen - 1;
      if (i === 7) parts.push("");
      continue;
    }
    parts.push(hextets[i].toString(16));
  }

  let res = parts.join(":");
  // 处理 '::' 位置与多余冒号
  res = res.replace(/^:/, "::");
  res = res.replace(/:$/, "::");
  res = res.replace(/:{3,}/g, "::");
  return res;
}

export function ipv6MaskFromPrefix(prefixLen) {
  const p = Number(prefixLen);
  assert(p >= 0 && p <= 128, `IPv6 Prefix length 必须在 0-128：/${p}`);
  const allOnes = (1n << 128n) - 1n;
  if (p === 0) return 0n;
  if (p === 128) return allOnes;
  const hostBits = 128n - BigInt(p);
  return (allOnes << hostBits) & allOnes;
}

function isIPv6InPrefix(addrInt, prefixValueInt, prefixLen) {
  const mask = ipv6MaskFromPrefix(prefixLen);
  return (addrInt & mask) === (prefixValueInt & mask);
}

export function detectIPv6AddressType(addrInt) {
  // 简化常见类型
  if (addrInt === 0n) return "未指定 (::/128)";
  if (addrInt === 1n) return "环回地址（::1）";
  // link-local fe80::/10
  const fe80 = parseIPv6Strict("fe80::").addrInt;
  if (isIPv6InPrefix(addrInt, fe80, 10)) return "链路本地（fe80::/10）";
  // unique local fc00::/7
  const fc00 = parseIPv6Strict("fc00::").addrInt;
  if (isIPv6InPrefix(addrInt, fc00, 7)) return "唯一本地（fc00::/7）";
  // multicast ff00::/8
  const ff00 = parseIPv6Strict("ff00::").addrInt;
  if (isIPv6InPrefix(addrInt, ff00, 8)) return "组播（ff00::/8）";
  // global unicast 2000::/3
  const two000 = parseIPv6Strict("2000::").addrInt;
  if (isIPv6InPrefix(addrInt, two000, 3)) return "全球单播（2000::/3）";
  return "其他/未明确类型";
}

export function ipv6CoreCompute(addrInput, prefixLen, { showExpanded } = { showExpanded: true }) {
  const addr = parseIPv6Strict(addrInput).addrInt;
  const p = Number(prefixLen);
  assert(p >= 0 && p <= 128, `IPv6 Prefix length 必须在 0-128：/${p}`);

  const mask = ipv6MaskFromPrefix(p);
  const network = addr & mask;
  const hostBits = 128 - p;
  const allOnes = (1n << 128n) - 1n;
  const hostMask = allOnes ^ mask;
  const interfaceId = addr & hostMask;

  const rangeSize = hostBits === 0 ? 1n : pow2(BigInt(hostBits));
  const first = network;
  const last = network + rangeSize - 1n;

  const networkStr = showExpanded ? ipv6IntToExpanded(network) : ipv6IntToCompressed(network);
  const addrStr = showExpanded ? ipv6IntToExpanded(addr) : ipv6IntToCompressed(addr);
  const ifaceStr = showExpanded ? ipv6IntToExpanded(interfaceId) : ipv6IntToCompressed(interfaceId);
  const firstStr = showExpanded ? ipv6IntToExpanded(first) : ipv6IntToCompressed(first);
  const lastStr = showExpanded ? ipv6IntToExpanded(last) : ipv6IntToCompressed(last);

  return {
    version: "IPv6",
    input: addrInput,
    prefixLen: p,
    address: addrStr,
    addressExpanded: ipv6IntToExpanded(addr),
    addressCompressed: ipv6IntToCompressed(addr),
    networkPrefix: `${networkStr}/${p}`,
    networkInt: network,
    interfaceId: ifaceStr,
    addressType: detectIPv6AddressType(addr),
    prefixRange: { first: firstStr, last: lastStr },
  };
}

export function ipv6SplitEqual(parentCIDR, subnetCount, { showExpanded } = { showExpanded: true }) {
  const s = normalizeSpaces(parentCIDR);
  const m = s.match(/^(.+)\/(\d{1,3})$/);
  assert(!!m, `IPv6 CIDR 格式错误：期望 "addr/xx" 当前：${parentCIDR}`);
  const addrInput = m[1];
  const pParent = Number(m[2]);
  assert(pParent >= 0 && pParent <= 128, `IPv6 Prefix length 必须在 0-128：/${pParent}`);

  const addr = parseIPv6Strict(addrInput).addrInt;
  const maskParent = ipv6MaskFromPrefix(pParent);
  const parentNetwork = addr & maskParent;

  const desired = Number(subnetCount);
  assert(Number.isFinite(desired) && desired >= 1, "子网数量必须为合法正整数。");

  // 找最小新增位 k，使得 2^k >= desired
  let k = 0;
  while ((1n << BigInt(k)) < BigInt(desired)) k++;
  const newPrefix = pParent + k;
  assert(newPrefix <= 128, "父网段无法满足子网数量。");

  const blockSize = 1n << BigInt(128 - newPrefix); // each subnet range size
  const subnets = [];
  for (let i = 0; i < desired; i++) {
    const snNet = parentNetwork + BigInt(i) * blockSize;
    const comp = ipv6CoreCompute(ipv6IntToCompressed(snNet), newPrefix, { showExpanded });
    subnets.push(comp);
  }

  const totalPossible = 1n << BigInt(newPrefix - pParent);
  return {
    parent: `${ipv6IntToCompressed(parentNetwork)}/${pParent}`,
    parentPrefix: pParent,
    newPrefix,
    desiredSubnets: desired,
    totalPossible,
    unusedSubnets: totalPossible - BigInt(desired),
    subnets,
  };
}

/**
 * 根据「可容纳的地址数量」求最小子网前缀长度（IPv6，无 IPv4 式网络/广播扣除）。
 * 需满足返回值 >= parentPrefix。
 */
export function ipv6PrefixForInterfaceCount(parentPrefix, interfaceCount) {
  const p0 = Number(parentPrefix);
  assert(p0 >= 0 && p0 <= 128, `父前缀 /${p0} 非法。`);
  const n = BigInt(interfaceCount);
  assert(n >= 1n, "接口/地址需求须为 >= 1 的整数。");
  assert(n <= (1n << 100n), "需求数量过大。");
  if (n === 1n) {
    assert(128 >= p0, `父前缀 /${p0} 无法容纳单地址子网。`);
    return 128;
  }
  let hostBits = 0n;
  let cap = 1n;
  while (cap < n) {
    cap <<= 1n;
    hostBits += 1n;
  }
  const pNeeded = Number(128n - hostBits);
  assert(pNeeded >= p0, `父前缀 /${p0} 过小，无法满足至少 ${interfaceCount} 个 IPv6 地址空间。`);
  return pNeeded;
}

function ipv6VlsmBigUtilization(totalAllocated, parentTotal) {
  if (parentTotal === 0n) return "0%";
  // 比例以字符串给出，避免超大整数转 Number 失真
  const scale = 10000n;
  const pct = (totalAllocated * scale) / parentTotal;
  const whole = Number(pct / 100n);
  const frac = Number(pct % 100n);
  return `${whole}.${String(frac).padStart(2, "0")}%`;
}

/**
 * IPv6 可变长子网规划：按各子网「所需地址/接口 ID 规模」在父前缀内划分，输出子网前缀与地址范围。
 * requests: { name, interfaces, note? } — interfaces 表示该子网内需要容纳的地址数量（2 的幂对齐块）。
 * strategy 与 IPv4 增强版一致：maxFirst | minFirst | sequential | order | bestFit | balanced | aggregation | defrag | fixedMask
 */
export function ipv6VlsmPlan(parentCIDR, requests, strategy = "maxFirst") {
  const s = normalizeSpaces(parentCIDR);
  const m = s.match(/^(.+)\/(\d{1,3})$/);
  assert(!!m, `IPv6 CIDR 格式错误：期望 "addr/xx"，当前：${parentCIDR}`);
  const addrInput = m[1];
  const pParent = Number(m[2]);
  assert(pParent >= 0 && pParent <= 128, `父前缀 /${pParent} 非法。`);

  const addr = parseIPv6Strict(addrInput).addrInt;
  const maskParent = ipv6MaskFromPrefix(pParent);
  const parentNetwork = addr & maskParent;
  const hostBitsParent = 128 - pParent;
  const parentTotal = hostBitsParent === 0 ? 1n : pow2(BigInt(hostBitsParent));
  const parentEnd = parentNetwork + parentTotal - 1n;

  const alignUp = (value, blockSize) => {
    if (blockSize === 0n) return value;
    const rem = value % blockSize;
    if (rem === 0n) return value;
    return value + (blockSize - rem);
  };
  const alignDown = (value, blockSize) => {
    if (blockSize === 0n) return value;
    const rem = value % blockSize;
    return value - rem;
  };
  const intervalLen = (it) => it.end - it.start + 1n;

  const splitIntervalsSubtract = (intervals, subStart, subEnd) => {
    const next = [];
    for (const it of intervals) {
      if (subEnd < it.start || subStart > it.end) {
        next.push(it);
        continue;
      }
      if (subStart > it.start) next.push({ start: it.start, end: subStart - 1n });
      if (subEnd < it.end) next.push({ start: subEnd + 1n, end: it.end });
    }
    next.sort((a, b) => (a.start < b.start ? -1 : 1));
    const merged = [];
    for (const it of next) {
      if (!merged.length) merged.push(it);
      else {
        const last = merged[merged.length - 1];
        if (last.end + 1n === it.start) last.end = it.end;
        else merged.push(it);
      }
    }
    return merged;
  };

  const findLargestFreeLenIn = (intervals) =>
    intervals.reduce((mx, it) => (intervalLen(it) > mx ? intervalLen(it) : mx), 0n);

  const reqs = requests.map((r, idx) => ({
    name: r.name || `Subnet-${idx + 1}`,
    interfaces: Number(r.interfaces),
    note: r.note || "",
    order: idx,
  }));
  for (const r of reqs) {
    assert(Number.isFinite(r.interfaces) && r.interfaces >= 1, `子网「${r.name}」的地址需求须为 >=1 的整数。`);
  }

  const buildAllocation = (r, pNeeded, start) => {
    const blockSize = pow2(BigInt(128 - pNeeded));
    const end = start + blockSize - 1n;
    const comp = ipv6CoreCompute(ipv6IntToCompressed(start), pNeeded, { showExpanded: false });
    const ifaceBits = 128 - pNeeded;
    return {
      name: r.name,
      interfacesNeed: r.interfaces,
      note: r.note,
      prefixLen: pNeeded,
      networkPrefix: comp.networkPrefix,
      networkInt: start,
      interfaceIdBits: ifaceBits,
      firstAddress: comp.prefixRange.first,
      lastAddress: comp.prefixRange.last,
      addressCount: blockSize.toString(),
      utilizationHint:
        ifaceBits >= 64
          ? `建议下游使用 /64 作为终端子网时，接口 ID 占 64 位（常见 SLAAC 场景）。当前块 /${pNeeded} 含 ${ifaceBits} 位主机部分。`
          : `主机部分 ${ifaceBits} 位，可容纳至多 ${blockSize.toString()} 个地址（按 2^${ifaceBits} 对齐）。`,
      interval: { start, end },
      order: r.order,
    };
  };

  const sortByIfDesc = () => [...reqs].sort((a, b) => b.interfaces - a.interfaces || a.order - b.order);
  const sortByIfAsc = () => [...reqs].sort((a, b) => a.interfaces - b.interfaces || a.order - b.order);
  const sortByOrderAsc = () => [...reqs].sort((a, b) => a.order - b.order);

  // fixedMask：等长切分，忽略各行需求差异
  if (strategy === "fixedMask") {
    const desiredCount = reqs.length;
    let p = pParent;
    while (p <= 128) {
      const totalSubnets = 1n << BigInt(p - pParent);
      if (totalSubnets >= BigInt(desiredCount)) break;
      p++;
    }
    assert(p <= 128, "父网段无法满足固定前缀的子网数量。");
    const blockSize = pow2(BigInt(128 - p));
    const sortedReq = sortByOrderAsc();
    const allocations = [];
    let totalAllocated = 0n;
    for (let i = 0; i < desiredCount; i++) {
      const r = sortedReq[i];
      const start = parentNetwork + BigInt(i) * blockSize;
      const end = start + blockSize - 1n;
      assert(end <= parentEnd, "固定掩码分配超出父网段。");
      allocations.push(buildAllocation(r, p, start));
      totalAllocated += blockSize;
    }
    const lastUsedEnd = parentNetwork + BigInt(desiredCount) * blockSize - 1n;
    const freeRemaining = lastUsedEnd >= parentEnd ? 0n : parentEnd - lastUsedEnd;
    return {
      parent: `${ipv6IntToCompressed(parentNetwork)}/${pParent}`,
      parentPrefix: pParent,
      parentTotalAddrs: parentTotal.toString(),
      allocations,
      totalAllocated: totalAllocated.toString(),
      totalWasteAlignment: "0",
      freeRemaining: freeRemaining.toString(),
      utilization: ipv6VlsmBigUtilization(totalAllocated, parentTotal),
      strategy,
    };
  }

  let freeIntervals = [{ start: parentNetwork, end: parentEnd }];
  let cursor = parentNetwork;

  let sorted;
  if (strategy === "maxFirst") sorted = sortByIfDesc();
  else if (strategy === "minFirst") sorted = sortByIfAsc();
  else if (strategy === "sequential" || strategy === "order") sorted = sortByOrderAsc();
  else if (
    strategy === "bestFit" ||
    strategy === "aggregation" ||
    strategy === "defrag" ||
    strategy === "balanced"
  ) {
    sorted = sortByIfDesc();
  } else {
    throw new Error(`未知 IPv6 VLSM 策略：${strategy}`);
  }

  let totalAllocated = 0n;
  let totalWasteAlignment = 0n;
  const allocations = [];

  for (const r of sorted) {
    const pNeeded = ipv6PrefixForInterfaceCount(pParent, r.interfaces);
    const blockSize = pow2(BigInt(128 - pNeeded));
    const restrictToCursor = strategy === "sequential" || strategy === "order";

    const candidates = [];
    for (const it of freeIntervals) {
      if (restrictToCursor && it.end < cursor) continue;
      const minStart = restrictToCursor ? (cursor > it.start ? cursor : it.start) : it.start;
      const s1 = alignUp(minStart, blockSize);
      const e1 = s1 + blockSize - 1n;
      if (s1 <= it.end && e1 <= it.end) candidates.push({ start: s1, end: e1, freeIt: it });
      const rightStartBase = it.end - blockSize + 1n;
      const s2 = alignDown(rightStartBase, blockSize);
      const e2 = s2 + blockSize - 1n;
      if (s2 >= it.start && e2 <= it.end) candidates.push({ start: s2, end: e2, freeIt: it });
    }

    const uniq = [];
    const seen = new Set();
    for (const c of candidates) {
      const k = `${c.start.toString()}_${c.end.toString()}`;
      if (seen.has(k)) continue;
      seen.add(k);
      uniq.push(c);
    }

    if (!uniq.length) {
      const largestFree = findLargestFreeLenIn(freeIntervals);
      throw new Error(
        `IPv6 VLSM 超出父网段：子网「${r.name}」需要 /${pNeeded}（块 ${blockSize.toString()} 地址），但最大连续空闲仅 ${largestFree.toString()} 地址。请减少需求或更换策略/顺序。`,
      );
    }

    const score = (cand) => {
      const afterFree = splitIntervalsSubtract(freeIntervals, cand.start, cand.end);
      const largestAfter = findLargestFreeLenIn(afterFree);
      const intervalWaste = intervalLen(cand.freeIt) - blockSize;
      const leftExists = cand.start > cand.freeIt.start;
      const rightExists = cand.end < cand.freeIt.end;
      const fragmentsCount = (leftExists ? 1 : 0) + (rightExists ? 1 : 0);
      return { start: cand.start, end: cand.end, afterFree, largestAfter, intervalWaste, fragmentsCount };
    };
    const scored = uniq.map((c) => score(c));

    let chosen;
    if (strategy === "maxFirst") {
      scored.sort((a, b) => (a.start < b.start ? -1 : 1));
      chosen = scored[0];
    } else if (strategy === "minFirst" || strategy === "bestFit") {
      scored.sort((a, b) => {
        if (a.intervalWaste < b.intervalWaste) return -1;
        if (a.intervalWaste > b.intervalWaste) return 1;
        if (a.fragmentsCount < b.fragmentsCount) return -1;
        if (a.fragmentsCount > b.fragmentsCount) return 1;
        return a.start < b.start ? -1 : 1;
      });
      chosen = scored[0];
    } else if (strategy === "sequential" || strategy === "order") {
      scored.sort((a, b) => (a.start < b.start ? -1 : 1));
      chosen = scored[0];
    } else if (strategy === "balanced") {
      scored.sort((a, b) => {
        if (a.largestAfter > b.largestAfter) return -1;
        if (a.largestAfter < b.largestAfter) return 1;
        if (a.fragmentsCount < b.fragmentsCount) return -1;
        if (a.fragmentsCount > b.fragmentsCount) return 1;
        return a.intervalWaste < b.intervalWaste ? -1 : 1;
      });
      chosen = scored[0];
    } else if (strategy === "aggregation") {
      scored.sort((a, b) => {
        if (a.start < b.start) return -1;
        if (a.start > b.start) return 1;
        if (a.largestAfter > b.largestAfter) return -1;
        if (a.largestAfter < b.largestAfter) return 1;
        return a.fragmentsCount - b.fragmentsCount;
      });
      chosen = scored[0];
    } else if (strategy === "defrag") {
      scored.sort((a, b) => {
        if (a.fragmentsCount < b.fragmentsCount) return -1;
        if (a.fragmentsCount > b.fragmentsCount) return 1;
        if (a.largestAfter > b.largestAfter) return -1;
        if (a.largestAfter < b.largestAfter) return 1;
        return a.intervalWaste < b.intervalWaste ? -1 : 1;
      });
      chosen = scored[0];
    } else {
      scored.sort((a, b) => (a.start < b.start ? -1 : 1));
      chosen = scored[0];
    }

    freeIntervals = splitIntervalsSubtract(freeIntervals, chosen.start, chosen.end);
    if (strategy === "sequential" || strategy === "order") cursor = chosen.end + 1n;

    allocations.push(buildAllocation(r, pNeeded, chosen.start));
    totalAllocated += blockSize;
    totalWasteAlignment += chosen.intervalWaste;
  }

  allocations.sort((a, b) => (a.interval.start < b.interval.start ? -1 : 1));
  const freeRemaining = freeIntervals.reduce((sum, it) => sum + intervalLen(it), 0n);

  return {
    parent: `${ipv6IntToCompressed(parentNetwork)}/${pParent}`,
    parentPrefix: pParent,
    parentTotalAddrs: parentTotal.toString(),
    allocations,
    totalAllocated: totalAllocated.toString(),
    totalWasteAlignment: totalWasteAlignment.toString(),
    freeRemaining: freeRemaining.toString(),
    utilization: ipv6VlsmBigUtilization(totalAllocated, parentTotal),
    strategy,
  };
}

// ---------------- Aggregation / Conflict ----------------

export function parseCIDROrSingleToRange(ipInput) {
  const s = normalizeSpaces(ipInput);
  if (s.includes(":")) {
    // IPv6
    const m = s.match(/^(.+)\/(\d{1,3})$/);
    if (m) {
      const addr = parseIPv6Strict(m[1]).addrInt;
      const p = Number(m[2]);
      const mask = ipv6MaskFromPrefix(p);
      const network = addr & mask;
      const hostBits = 128 - p;
      const end = hostBits === 0 ? network : network + (pow2(BigInt(hostBits)) - 1n);
      return { version: "IPv6", start: network, end, prefixLen: p, original: s };
    }
    // 单地址按 /128
    const addr = parseIPv6Strict(s).addrInt;
    return { version: "IPv6", start: addr, end: addr, prefixLen: 128, original: s };
  }

  // IPv4
  const m = s.match(/^(.+)\/(\d{1,2})$/);
  if (m) {
    const parsed = parseIPv4CIDR(s);
    const trip = ipv4CalcTriplet(parsed.ipInt, parsed.prefixLen);
    return { version: "IPv4", start: trip.network, end: trip.broadcast, prefixLen: parsed.prefixLen, original: s };
  }
  const { int } = parseIPv4Strict(s);
  return { version: "IPv4", start: int, end: int, prefixLen: 32, original: s };
}

export function ipv4Aggregate(cidrList) {
  const ranges = cidrList
    .map((c) => normalizeSpaces(c))
    .filter(Boolean)
    .map((c) => {
      const parsed = parseIPv4CIDR(c.includes("/") ? c : `${c}/32`);
      const trip = ipv4CalcTriplet(parsed.ipInt, parsed.prefixLen);
      return {
        version: "IPv4",
        start: trip.network,
        end: trip.broadcast,
        prefixLen: parsed.prefixLen,
        original: c,
      };
    });

  // 去重：以 start+prefixLen
  const unique = new Map();
  for (const r of ranges) {
    const k = `${r.start.toString()}_${r.prefixLen}`;
    unique.set(k, r);
  }

  let blocks = [...unique.values()].sort((a, b) => (a.start < b.start ? -1 : 1));

  const maskForPrefix = (p) => ipv4MaskFromPrefix(p);
  const canMerge = (a, b) => {
    if (a.prefixLen !== b.prefixLen) return false;
    if (a.end + 1n !== b.start) return false;
    const mergedPrefix = a.prefixLen - 1;
    if (mergedPrefix < 0) return false;
    const mergedNetwork = a.start & maskForPrefix(mergedPrefix);
    return (b.start & maskForPrefix(mergedPrefix)) === mergedNetwork;
  };

  let changed = true;
  while (changed) {
    changed = false;
    blocks.sort((a, b) => (a.start < b.start ? -1 : 1));
    const next = [];
    let i = 0;
    while (i < blocks.length) {
      if (i + 1 < blocks.length && canMerge(blocks[i], blocks[i + 1])) {
        const a = blocks[i];
        const b = blocks[i + 1];
        const mergedPrefix = a.prefixLen - 1;
        const mergedStart = a.start & maskForPrefix(mergedPrefix);
        const mergedSize = 1n << BigInt(32 - mergedPrefix);
        const mergedEnd = mergedStart + mergedSize - 1n;
        next.push({ version: "IPv4", start: mergedStart, end: mergedEnd, prefixLen: mergedPrefix });
        i += 2;
        changed = true;
      } else {
        next.push(blocks[i]);
        i += 1;
      }
    }
    blocks = next;
  }

  // 转回展示格式
  const toCIDR = (b) => `${ipv4IntToString(b.start)}/${b.prefixLen}`;
  const beforeCount = ranges.length;
  return {
    version: "IPv4",
    before: [...unique.values()].sort((a, b) => (a.start < b.start ? -1 : 1)).map(toCIDR),
    after: blocks.map(toCIDR).sort(),
    reducedRoutes: beforeCount - blocks.length,
    blocks,
  };
}

export function computeOverlapRelations(rangeList) {
  // 分版本比较（IPv4 与 IPv6 不互相比较）
  const byVersion = new Map();
  for (const r of rangeList) {
    const arr = byVersion.get(r.version) || [];
    arr.push(r);
    byVersion.set(r.version, arr);
  }

  const relations = [];
  for (const [version, arr] of byVersion.entries()) {
    const sorted = arr.sort((a, b) => (a.start < b.start ? -1 : 1));
    for (let i = 0; i < sorted.length; i++) {
      for (let j = i + 1; j < sorted.length; j++) {
        const A = sorted[i];
        const B = sorted[j];
        if (A.end < B.start || B.end < A.start) continue; // 无交集

        const interStart = A.start > B.start ? A.start : B.start;
        const interEnd = A.end < B.end ? A.end : B.end;

        const exact = A.start === B.start && A.end === B.end;
        const AcontainsB = A.start <= B.start && A.end >= B.end;
        const BcontainsA = B.start <= A.start && B.end >= A.end;

        let type = "部分重叠";
        let detail = "";
        if (exact) {
          type = "完全重叠";
          detail = "两个网段范围完全一致。";
        } else if (AcontainsB) {
          type = "包含关系";
          detail = "A 网段包含 B 网段。";
        } else if (BcontainsA) {
          type = "包含关系";
          detail = "B 网段包含 A 网段。";
        }

        const overlapText =
          version === "IPv4"
            ? `${ipv4IntToString(interStart)} - ${ipv4IntToString(interEnd)}`
            : `${ipv6IntToCompressed(interStart)} - ${ipv6IntToCompressed(interEnd)}`;

        relations.push({
          version,
          type,
          detail,
          left: A.original,
          right: B.original,
          overlapText,
          overlapStart: interStart,
          overlapEnd: interEnd,
        });
      }
    }
  }

  return relations;
}

export function ipv4GatewayCheck(subnetCIDR, gatewayStr, { subtractNBForSuggest } = { subtractNBForSuggest: true }) {
  const subnet = parseIPv4CIDR(subnetCIDR);
  const trip = ipv4CalcTriplet(subnet.ipInt, subnet.prefixLen);
  const { int: gwInt } = parseIPv4Strict(gatewayStr);

  const okInRange = gwInt >= trip.network && gwInt <= trip.broadcast;
  if (!okInRange) {
    return {
      ok: false,
      subnet: `${ipv4IntToString(trip.network)}/${subnet.prefixLen}`,
      gateway: gatewayStr,
      message: "网关不在对应网段范围内。",
      status: "danger",
    };
  }

  if (gwInt === trip.network) {
    return {
      ok: false,
      subnet: `${ipv4IntToString(trip.network)}/${subnet.prefixLen}`,
      gateway: gatewayStr,
      message: "网关是网络地址（通常不作为网关使用）。",
      status: "warn",
    };
  }
  if (gwInt === trip.broadcast) {
    return {
      ok: false,
      subnet: `${ipv4IntToString(trip.network)}/${subnet.prefixLen}`,
      gateway: gatewayStr,
      message: "网关是广播地址（通常不作为网关使用）。",
      status: "warn",
    };
  }

  const { first, last } = ipv4FirstLastUsable(trip.network, trip.broadcast, subnet.prefixLen, subtractNBForSuggest);
  const suggest = [];
  suggest.push({ label: "建议1（第一个可用）", value: ipv4IntToString(first) });
  if (last !== first) suggest.push({ label: "建议2（最后一个可用）", value: ipv4IntToString(last) });
  // 再给一个常见：次一个地址
  if (subtractNBForSuggest && subnet.prefixLen <= 30 && first + 1n <= last) {
    suggest.push({ label: "建议3（次优常用：+1）", value: ipv4IntToString(first + 1n) });
  }

  return {
    ok: true,
    subnet: `${ipv4IntToString(trip.network)}/${subnet.prefixLen}`,
    gateway: gatewayStr,
    message: "网关在网段内，且不是网络/广播地址。",
    status: "ok",
    suggestions: suggest,
    triplet: {
      network: ipv4IntToString(trip.network),
      broadcast: ipv4IntToString(trip.broadcast),
      netmask: ipv4IntToString(trip.maskInt),
      firstUsable: ipv4IntToString(first),
      lastUsable: ipv4IntToString(last),
    },
  };
}

