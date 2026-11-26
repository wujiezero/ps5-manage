'use strict';

/* ── 概览渲染 ───────────────────────────────────────────────────────── */

function actionInfo(action) {
  const value = asText(action, '').toLowerCase();
  if (value === 'local') return ['局域网', 'good'];
  if (/^(allow|allowed|accept|accepted|permit|permitted|forward|forwarded|resolved|cache|cached)$/.test(value)) return ['已允许', 'good'];
  if (/^(deny|denied|block|blocked|drop|dropped|reject|rejected|refused|nxdomain)$/.test(value)) return ['已拒绝', 'error'];
  const other = { nodata: '无解析记录', upstream: '上游查询', error: '解析异常' };
  return [other[value] || asText(action, '未知'), 'neutral'];
}

function setField(name, text, datetime) {
  for (const element of $$(`[data-field="${name}"]`)) {
    element.textContent = text;
    if (element.tagName === 'TIME') {
      if (datetime) element.setAttribute('datetime', String(datetime));
      else element.removeAttribute('datetime');
    }
  }
}

function setBadge(name, count) {
  const value = Number(count);
  for (const node of $$(`[data-badge="${name}"]`)) {
    if (Number.isFinite(value) && value > 0) {
      node.textContent = String(value);
      node.hidden = false;
    } else {
      node.textContent = '';
      node.hidden = true;
    }
  }
}

function renderService(id, value) {
  const statuses = {
    running: ['运行中', 'good'], active: ['已启用', 'good'], ok: ['正常', 'good'],
    stopped: ['已停止', 'error'], inactive: ['未启用', 'warning'], failed: ['故障', 'error'],
    error: ['异常', 'error'], unknown: ['状态未知', 'neutral'], unavailable: ['不可用', 'error']
  };
  const [label, tone] = statuses[String(value).toLowerCase()] || [asText(value, '状态未知'), 'neutral'];
  $(id).textContent = label;
  $(id).dataset.tone = tone;
}

function renderQueryLogs(logs) {
  const entries = Array.isArray(logs) ? logs.filter((entry) => entry && typeof entry === 'object') : [];
  let allowed = 0;
  let blocked = 0;
  for (const log of entries) {
    const [, tone] = actionInfo(log.action);
    if (tone === 'good') allowed += 1;
    if (tone === 'error') blocked += 1;
  }
  $('query-total').textContent = String(entries.length);
  $('query-allowed').textContent = String(allowed);
  $('query-blocked').textContent = String(blocked);
  $('query-other').textContent = String(entries.length - allowed - blocked);

  const fragment = document.createDocumentFragment();
  const preview = entries.slice(0, 5);
  if (!preview.length) {
    const empty = document.createElement('li');
    empty.className = 'log-item muted';
    empty.textContent = '暂无 DNS 请求。PS5 使用本机 DNS 后，请求会显示在这里。';
    fragment.append(empty);
  } else {
    for (const log of preview) {
      const [label, tone] = actionInfo(log.action);
      const item = document.createElement('li');
      item.className = 'log-item';
      const head = document.createElement('div');
      head.className = 'log-head';
      const name = document.createElement('span');
      name.className = 'log-name mono';
      name.textContent = asText(log.name);
      const badge = document.createElement('span');
      badge.className = 'result-badge';
      badge.dataset.tone = tone;
      badge.textContent = label;
      head.append(name, badge);
      item.append(head);

      const meta = document.createElement('p');
      meta.className = 'log-meta';
      meta.textContent = [formatTime(log.time), asText(log.client), asText(log.qtype)]
        .filter((value) => value && value !== '—' && value !== '尚无记录')
        .join(' · ');
      item.append(meta);

      const detail = asText(log.detail, '');
      if (detail && detail !== '—') {
        const detailNode = document.createElement('p');
        detailNode.className = 'log-detail';
        detailNode.textContent = detail;
        item.append(detailNode);
      }
      fragment.append(item);
    }
  }
  $('overview-logs').replaceChildren(fragment);
}

function renderFirewall(firewall) {
  const counters = [];
  const totals = { packets: 0, bytes: 0 };
  let hasTotals = false;
  let partial = false;
  const labels = { packets: '数据包', bytes: '字节', allowed: '允许', blocked: '拒绝', dropped: '丢弃', accepted: '接受', dns: 'DNS', forward: '转发', input: '入站', output: '出站', counter: '计数器', counters: '计数器', nftables: '防火墙', rule: '规则', expr: '匹配项' };
  const walk = (node, path = [], depth = 0) => {
    if (node === null || node === undefined) return;
    if (counters.length >= 64 || depth > 16) { partial = true; return; }
    if (typeof node === 'number' && Number.isFinite(node)) {
      counters.push([path.join(' / ') || '计数', node.toLocaleString('zh-CN')]);
      if (path.at(-1) === '数据包') { totals.packets += node; hasTotals = true; }
      if (path.at(-1) === '字节') { totals.bytes += node; hasTotals = true; }
    } else if (Array.isArray(node)) {
      node.forEach((item, index) => walk(item, [...path, asText(item && (item.name || item.comment), String(index + 1))], depth + 1));
    } else if (typeof node === 'object') {
      const name = node.name || node.comment;
      for (const [key, value] of Object.entries(node)) {
        if (['handle', 'index', 'family', 'name', 'comment', 'version', 'schema'].includes(key)) continue;
        walk(value, [...path, ...(name && !path.includes(String(name)) ? [String(name)] : []), labels[key] || key], depth + 1);
      }
    }
  };
  walk(firewall);
  if (!counters.length) {
    const empty = document.createElement('p');
    empty.className = 'muted';
    empty.textContent = '暂无网关计数数据。';
    $('firewall-counters').replaceChildren(empty);
    return;
  }
  if (hasTotals) counters.unshift(['已展示规则累计数据包', totals.packets.toLocaleString('zh-CN')], ['已展示规则累计字节', totals.bytes.toLocaleString('zh-CN')]);
  const list = document.createElement('dl');
  for (const [label, value] of counters) {
    const row = document.createElement('div');
    const term = document.createElement('dt');
    const count = document.createElement('dd');
    term.textContent = label;
    count.textContent = value;
    count.className = 'mono';
    row.append(term, count);
    list.append(row);
  }
  const explanation = document.createElement('p');
  explanation.className = 'secondary-note';
  explanation.textContent = `${partial ? '条目较多，仅展示部分计数。' : ''}计数按规则累加，同一数据包可能被多次计数。`;
  $('firewall-counters').replaceChildren(list, explanation);
}

function renderState(data, forceConfig = false) {
  if (!data.config || typeof data.config !== 'object' || typeof data.csrf !== 'string' || !data.csrf) throw new ApiError('状态数据不完整，请刷新后重试。');
  csrf = data.csrf;
  const config = cleanConfig(data.config);
  const nextSignature = signature(config);
  // 未保存的编辑属于用户，轮询结果不能覆盖。
  const keepDraft = dirty && !forceConfig;
  showDashboard();
  if (!keepDraft) fillConfig(config);
  else if (remoteSignature && nextSignature !== remoteSignature) toast('服务器配置已更新。当前未保存的编辑已保留；保存将覆盖服务器上的配置。', 'info');
  remoteSignature = nextSignature;

  const status = data.status && typeof data.status === 'object' ? data.status : {};
  const diagnostics = [...new Set([status.last_error, status.gateway_error]
    .filter((message) => typeof message === 'string' && message.trim())
    .map((message) => message.trim()))];
  const diagnosticsNode = $('status-diagnostics');
  diagnosticsNode.textContent = diagnostics.length ? `服务诊断：${diagnostics.join('；')}` : '';
  diagnosticsNode.hidden = diagnostics.length === 0;

  renderService('dns-status', status.dns);
  renderService('gateway-status', status.gateway);
  renderService('host-status', status.host);
  hasPrevious = status.has_previous !== false;
  serviceInfo = data.service && typeof data.service === 'object' ? data.service : null;
  renderServiceInfo(status);
  $('uptime').textContent = uptime(status.uptime);
  const dynamic = Number(status.dynamic_addresses);
  $('dynamic-addresses').textContent = Number.isFinite(dynamic) && dynamic >= 0 ? `${Math.floor(dynamic)} 个` : '—';
  $$('[data-host-ip]').forEach((element) => { element.textContent = asText(status.host_ip, '—'); });
  renderBuiltinDomains(data.local_domains, status.host_ip);
  setField('last-applied', formatTime(status.last_applied, true), status.last_applied);
  $('ipv6-note').textContent = status.ipv6_forwarding === true
    ? '检测到主机已开启 IPv6 转发。当前策略仅控制 IPv4；请确认家庭网络仍关闭 IPv6 互联网。'
    : '家庭网络已关闭 IPv6 互联网；本页网关策略不提供 IPv6 访问控制。';

  renderQueryLogs(data.logs);
  renderFirewall(data.firewall);
  renderQuickLinks();
  setConnection('状态已同步', 'good');
  $('sync-time').textContent = `${formatTime(new Date())} · 每 8 秒刷新`;
  updateControls();
}

/* ── 概览：PS5 遥测卡片 & 主机开放 ELF 端口卡片 ────────────────────────── */

let overviewSelectedHost = '';
let overviewTelemetryTimer = null;
let overviewTelemetryBusy = false;
let overviewServicesBusy = false;
let overviewTelemetryAt = 0;
let overviewServicesAt = 0;

function syncOverviewHostSelect() {
  const select = $('overview-host-select');
  if (!select) return '';
  const hosts = Array.isArray(ps5.hosts) ? ps5.hosts : [];
  if (!hosts.length) {
    select.hidden = true;
    select.replaceChildren();
    overviewSelectedHost = '';
    return '';
  }
  const preferred = hosts.find((h) => h.ip === overviewSelectedHost)
    || hosts.find((h) => h.online)
    || hosts.find((h) => files.info && files.info.host === h.ip)
    || hosts[0];
  overviewSelectedHost = preferred ? preferred.ip : '';
  const fragment = document.createDocumentFragment();
  for (const host of hosts) {
    const opt = document.createElement('option');
    opt.value = host.ip;
    const status = host.online ? '在线' : host.power && host.power.state === 'standby' ? '待机' : '离线';
    const label = host.power && host.power.name ? `${host.power.name} (${host.ip})` : host.ip;
    opt.textContent = `${label} · ${status}`;
    if (host.ip === overviewSelectedHost) opt.selected = true;
    fragment.append(opt);
  }
  select.replaceChildren(fragment);
  select.hidden = hosts.length <= 1;
  return overviewSelectedHost;
}

function setTelemetryBar(barNode, percent) {
  if (!barNode) return;
  const numeric = Number(percent);
  const clamped = Number.isFinite(numeric) ? Math.max(0, Math.min(100, numeric)) : 0;
  barNode.style.width = `${clamped.toFixed(1)}%`;
  barNode.dataset.tone = clamped >= 90 ? 'error' : clamped >= 75 ? 'warning' : 'good';
}

function renderOverviewTelemetry(data) {
  if (!$('overview-telemetry-section')) return;
  const host = str(data && data.host);
  const metaNode = $('overview-telemetry-host-meta');
  const noteNode = $('overview-telemetry-note');
  if (!host) {
    if (metaNode) metaNode.textContent = '未发现 PS5 主机，请先在「PS5 主机」页添加或扫描';
    if (noteNode) { noteNode.hidden = true; noteNode.textContent = ''; }
  } else {
    const parts = [host];
    if (data.host_name) parts.push(str(data.host_name));
    if (data.firmware) parts.push(`系统 ${str(data.firmware)}`);
    if (data.engine_available) parts.push('ps5upload 已连接');
    else parts.push('ps5upload 引擎未连接');
    if (metaNode) metaNode.textContent = parts.join(' · ');
    if (noteNode) {
      if (data.error) {
        noteNode.textContent = `主机读数提示：${str(data.error)}`;
        noteNode.hidden = false;
      } else if (!data.engine_available) {
        noteNode.textContent = '提示：部署 ps5upload-engine 并在 PS5 运行 ps5upload.elf 后，可实时读取处理器、内存、存储与帧率信息。';
        noteNode.hidden = false;
      } else {
        noteNode.textContent = '';
        noteNode.hidden = true;
      }
    }
  }

  const cpu = (data && data.cpu && typeof data.cpu === 'object') ? data.cpu : {};
  $('telemetry-cpu-freq').textContent = Number.isFinite(cpu.freq_ghz) ? `${Number(cpu.freq_ghz).toFixed(2)} GHz` : '—';
  $('telemetry-cpu-cores').textContent = Number.isFinite(cpu.cores) ? `${cpu.cores} 逻辑核心` : '—';
  $('telemetry-cpu-temp').textContent = Number.isFinite(cpu.temp_c) ? `${Number(cpu.temp_c).toFixed(1)}°C` : '—';
  $('telemetry-soc-temp').textContent = Number.isFinite(cpu.soc_temp_c) ? `SoC ${Number(cpu.soc_temp_c).toFixed(1)}°C` : 'SoC —';
  $('telemetry-cpu-power').textContent = Number.isFinite(cpu.power_w) ? `${Number(cpu.power_w).toFixed(1)} W` : '—';
  $('telemetry-cpu-power-note').textContent = asText(cpu.power_note, '整机 SoC 估算');
  $('telemetry-cpu-load').textContent = Number.isFinite(cpu.load_pct) ? `${Math.round(cpu.load_pct)}%` : '—';
  $('telemetry-fan-pct').textContent = Number.isFinite(cpu.fan_pct) ? `风扇 ${Math.round(cpu.fan_pct)}%` : '风扇 —';
  $('telemetry-cpu-load-bar-text').textContent = Number.isFinite(cpu.load_pct) ? `${Math.round(cpu.load_pct)}%` : '—';
  setTelemetryBar($('telemetry-cpu-load-bar'), cpu.load_pct);

  const mem = (data && data.memory && typeof data.memory === 'object') ? data.memory : {};
  const memUsedNode = $('telemetry-mem-used-total');
  if (Number.isFinite(mem.used_bytes) && Number.isFinite(mem.total_bytes)) {
    memUsedNode.replaceChildren(
      document.createTextNode(`${formatBytes(mem.used_bytes)} /`),
      document.createElement('br'),
      document.createTextNode(formatBytes(mem.total_bytes))
    );
  } else {
    memUsedNode.textContent = '—';
  }
  $('telemetry-mem-note').textContent = asText(mem.note, 'ps5upload 硬件读数');
  $('telemetry-mem-direct').textContent = Number.isFinite(mem.direct_bytes) ? formatBytes(mem.direct_bytes) : '—';
  $('telemetry-mem-pct-text').textContent = Number.isFinite(mem.used_pct) ? `${Number(mem.used_pct).toFixed(1)}%` : '—';
  setTelemetryBar($('telemetry-mem-bar'), mem.used_pct);
  const swapText = Number.isFinite(mem.swap_bytes) ? formatBytes(mem.swap_bytes) : '—';
  const wiredText = Number.isFinite(mem.wired_bytes) ? formatBytes(mem.wired_bytes) : '—';
  $('telemetry-mem-sub').textContent = `Swap ${swapText} · 常驻 ${wiredText}`;

  const storageList = $('overview-storage-list');
  const volumes = Array.isArray(data && data.volumes) ? data.volumes : [];
  if (!volumes.length) {
    storageList.replaceChildren(makeElement('p', 'muted telemetry-empty', '暂无存储容量数据。'));
  } else {
    const fragment = document.createDocumentFragment();
    for (const vol of volumes) {
      const item = makeElement('div', 'telemetry-storage-item');
      const top = makeElement('div', 'telemetry-storage-top');
      top.append(makeElement('span', 'telemetry-storage-name', str(vol.label || vol.path)));
      const pct = Number(vol.percent);
      const pctNode = makeElement('span', 'telemetry-storage-pct mono', Number.isFinite(pct) ? `${pct.toFixed(1)}%` : '—');
      top.append(pctNode);

      const mid = makeElement('div', 'telemetry-storage-meta');
      mid.append(makeElement('span', '', '已用'), makeElement('span', 'mono', `${formatBytes(vol.used_bytes)} / ${formatBytes(vol.total_bytes)}`));

      const bar = makeElement('div', 'telemetry-bar');
      const fill = makeElement('div', 'telemetry-bar-fill');
      setTelemetryBar(fill, pct);
      bar.append(fill);

      const bot = makeElement('div', 'telemetry-storage-meta');
      bot.append(makeElement('span', '', '剩余'), makeElement('span', 'mono', formatBytes(vol.free_bytes)));

      item.append(top, mid, bar, bot);
      fragment.append(item);
    }
    storageList.replaceChildren(fragment);
  }

  const game = (data && data.game && typeof data.game === 'object') ? data.game : {};
  const running = game.running === true;
  const titleId = str(game.title_id);
  $('telemetry-game-id-pill').textContent = titleId || (running ? '运行中' : '空闲');
  $('telemetry-fps-val').textContent = running && Number.isFinite(game.fps) ? String(game.fps) : '—';
  $('telemetry-fps-box').dataset.active = String(running && Number.isFinite(game.fps));
  $('telemetry-game-name').textContent = running ? asText(game.name, '正在运行游戏') : '未在运行游戏';
  const subParts = [];
  if (game.title_en && game.title_en !== game.name) subParts.push(str(game.title_en));
  if (titleId) subParts.push(titleId);
  const subNode = $('telemetry-game-sub');
  subNode.textContent = subParts.join(' · ');
  subNode.hidden = !subParts.length;
  $('telemetry-game-dev').textContent = str(game.developer);
  $('telemetry-game-dev').hidden = !game.developer;
  $('telemetry-game-genre').textContent = str(game.genre);
  $('telemetry-game-genre').hidden = !game.genre;

  const cover = $('telemetry-game-cover');
  const blank = $('telemetry-cover-placeholder');
  const statePill = $('telemetry-game-state-pill');
  statePill.hidden = !running;
  if (running && game.cover_url) {
    cover.src = str(game.cover_url);
    cover.alt = asText(game.name, '游戏封面');
    cover.hidden = false;
    blank.hidden = true;
  } else {
    cover.hidden = true;
    cover.removeAttribute('src');
    blank.textContent = titleId || 'PS5';
    blank.hidden = false;
  }
  $('telemetry-game-desc').textContent = running
    ? asText(game.description, '游戏正在运行 · 标题、帧率与存储由 PS5 管理服务实时聚合。')
    : '打开游戏并在主机运行 ps5upload 后，此处展示帧率、标题与封面信息。';
}

async function copyOverviewText(text) {
  if (!text) return;
  try {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      await navigator.clipboard.writeText(text);
    } else {
      const area = document.createElement('textarea');
      area.value = text;
      area.setAttribute('readonly', '');
      area.style.position = 'fixed';
      area.style.opacity = '0';
      document.body.append(area);
      area.select();
      document.execCommand('copy');
      area.remove();
    }
    toast(`已复制 ${text}`, 'success');
  } catch {
    toast(`地址：${text}`, 'info');
  }
}

function renderOverviewServices(data) {
  const grid = $('overview-services-grid');
  if (!grid) return;
  const host = str(data && data.host);
  const services = Array.isArray(data && data.services) ? data.services : [];
  const hostChip = $('overview-services-host');
  if (hostChip) {
    hostChip.textContent = host ? `${host}${data.online ? '' : ' · 未检测到开放端口'}` : '未选择主机';
    hostChip.dataset.tone = !host ? 'neutral' : services.length ? 'good' : 'neutral';
  }
  const summary = $('overview-services-summary');
  if (summary) {
    if (!host) summary.textContent = '还没有已连接的 PS5 主机，连接或扫描后自动识别主机开放的 ELF 服务端口。';
    else if (!services.length) summary.textContent = `已探测 ${Number(data.scanned_ports) || 0} 个常见 PS5 自制服务端口，当前未检测到监听端口（可能处于待机或未运行 ELF）。`;
    else summary.textContent = `已识别 ${services.length} 个开放服务（Web 服务可点击新窗口打开，协议端口可点击复制地址）。`;
  }
  if (!services.length) {
    grid.replaceChildren(makeElement('p', 'muted services-empty', host ? '暂未发现开放的 ELF 网络服务端口。' : '请先扫描或添加 PS5 主机。'));
    return;
  }
  const fragment = document.createDocumentFragment();
  for (const svc of services) {
    const isWeb = svc.web === true && str(svc.url).startsWith('http');
    const card = document.createElement(isWeb ? 'a' : 'button');
    card.className = `service-card ${isWeb ? 'service-card-web' : 'service-card-proto'}`;
    if (isWeb) {
      card.href = svc.url;
      card.target = '_blank';
      card.rel = 'noopener noreferrer';
      card.setAttribute('aria-label', `在新窗口打开 ${svc.name}（${svc.url}）`);
    } else {
      card.type = 'button';
      card.setAttribute('aria-label', `复制连接地址 ${svc.url}`);
      card.addEventListener('click', () => copyOverviewText(svc.url));
    }

    const top = makeElement('div', 'service-card-top');
    top.append(makeElement('span', 'service-card-name', asText(svc.name, `端口 ${svc.port}`)));
    const portTag = makeElement('span', 'service-card-port mono', `${String(svc.protocol || 'tcp').toUpperCase()} ${svc.port}`);
    top.append(portTag);

    const descText = svc.title && svc.title !== svc.name ? `${svc.title} · ${asText(svc.description, '')}` : asText(svc.description, '');
    const desc = makeElement('p', 'service-card-desc', descText);

    const foot = makeElement('div', 'service-card-foot');
    foot.append(makeElement('span', 'service-card-addr mono', str(svc.url)));
    foot.append(makeElement('span', 'service-card-action', isWeb ? '新窗口打开 ↗' : '复制地址'));

    card.append(top, desc);
    if (svc.repo || svc.process) {
      const meta = [svc.repo ? `GitHub: ${svc.repo}` : '', svc.process ? `进程: ${svc.process}` : ''].filter(Boolean).join(' · ');
      card.append(makeElement('p', 'service-card-repo', meta));
    }
    card.append(foot);
    fragment.append(card);
  }
  grid.replaceChildren(fragment);
}

async function refreshOverviewTelemetry({ force = false, quiet = true } = {}) {
  if (!authenticated || overviewTelemetryBusy || !$('overview-telemetry-section')) return false;
  overviewTelemetryBusy = true;
  if (!quiet) buttonBusy('overview-telemetry-refresh', true, '刷新中…');
  const ip = syncOverviewHostSelect();
  const requestEpoch = epoch;
  try {
    const query = new URLSearchParams();
    if (ip) query.set('ip', ip);
    if (force) query.set('force', '1');
    const data = await api(`/api/ps5/telemetry?${query}`, undefined, 10000);
    if (requestEpoch !== epoch) return false;
    overviewTelemetryAt = Date.now();
    renderOverviewTelemetry(data);
    if (!quiet) toast('PS5 硬件状态已刷新。', 'success');
    return true;
  } catch (error) {
    if (requestEpoch !== epoch) return false;
    if (error.status === 401) { showLogin(error.message); return false; }
    if (!quiet) toast(error.message || '读取主机状态失败。', 'error');
    return false;
  } finally {
    overviewTelemetryBusy = false;
    if (!quiet) buttonBusy('overview-telemetry-refresh', false, '刷新状态');
  }
}

async function refreshOverviewServices({ force = false, quiet = true } = {}) {
  if (!authenticated || overviewServicesBusy || !$('overview-services-section')) return false;
  overviewServicesBusy = true;
  if (!quiet) buttonBusy('overview-services-refresh', true, '扫描中…');
  const ip = syncOverviewHostSelect();
  const requestEpoch = epoch;
  try {
    const query = new URLSearchParams();
    if (ip) query.set('ip', ip);
    if (force) query.set('force', '1');
    const data = await api(`/api/ps5/services?${query}`, undefined, 12000);
    if (requestEpoch !== epoch) return false;
    overviewServicesAt = Date.now();
    renderOverviewServices(data);
    if (!quiet) toast(`端口扫描完成，发现 ${(data.services || []).length} 个开放服务。`, 'success');
    return true;
  } catch (error) {
    if (requestEpoch !== epoch) return false;
    if (error.status === 401) { showLogin(error.message); return false; }
    if (!quiet) toast(error.message || '端口扫描失败。', 'error');
    return false;
  } finally {
    overviewServicesBusy = false;
    if (!quiet) buttonBusy('overview-services-refresh', false, '扫描端口');
  }
}

function maybeRefreshOverviewExtras({ force = false } = {}) {
  if (!authenticated || currentSection !== 'overview') return;
  syncOverviewHostSelect();
  const now = Date.now();
  if (force || now - overviewTelemetryAt > 5000) refreshOverviewTelemetry({ force });
  if (force || now - overviewServicesAt > 25000) refreshOverviewServices({ force });
}

function renderBuiltinDomains(localDomains, hostIp) {
  const block = $('builtin-domains');
  const names = Array.isArray(localDomains) ? localDomains.map((value) => str(value)).filter(Boolean) : [];
  block.hidden = names.length === 0;
  const list = $('builtin-domain-list');
  list.replaceChildren();
  for (const name of names) {
    const chip = document.createElement('code');
    chip.className = 'builtin-domain';
    chip.textContent = name;
    list.append(chip);
  }
  $('builtin-host-ip').textContent = asText(hostIp, location.hostname || '本机');
}

function renderServiceInfo(status) {
  const info = serviceInfo || {};
  const ports = info.ports && typeof info.ports === 'object' ? info.ports : {};
  const paths = info.paths && typeof info.paths === 'object' ? info.paths : {};
  const units = info.units && typeof info.units === 'object' ? info.units : {};
  const hostIp = asText(status.host_ip, location.hostname);
  const port = (key, fallback) => (Number.isInteger(ports[key]) ? ports[key] : fallback);
  const adminPort = port('admin', 8443);
  const repoPort = port('repo', 8080);
  $('dns-status-hint').textContent = `UDP / TCP ${port('dns', 53)}`;
  $('host-status-hint').textContent = `HTTPS ${port('https', 443)} · ${asText(units.host && units.host.name, 'ps5-manage-host')}`;
  $('info-admin').textContent = `https://${hostIp}:${adminPort}/`;
  $('info-ports').textContent = `DNS ${port('dns', 53)} · 用户手册 ${port('https', 443)}/${port('http', 80)} · 仓库 ${repoPort} · 管理 ${adminPort}`;
  $('info-subnet').textContent = asText(info.subnet, '—');
  // Older servers do not report the interface; keep the row hidden then.
  const iface = typeof status.interface === 'string' ? status.interface : '';
  $('info-interface').textContent = iface || '—';
  $('info-interface-row').hidden = !iface;
  $('info-repo-dir').textContent = paths.repo ? `${paths.repo}/（repo.json + payloads/）` : '—';
  $('info-data-dir').textContent = asText(paths.data, '—');
  $('info-config').textContent = asText(paths.config, '—');
  const names = ['host', 'server', 'repo'].map((role) => units[role] && units[role].name).filter(Boolean);
  $('info-units').textContent = names.length ? names.map((name) => `${name}.service`).join(' · ') : '—';
  $('info-repo-url').textContent = `http://${hostIp}:${repoPort}/repo.json`;
  if (names.length) $('info-stop-command').textContent = `systemctl disable --now ${names.join(' ')}`;
}

function renderQuickLinks() {
  const set = (id, text) => { const node = $(id); if (node && text) node.textContent = text; };
  if (activity.loaded) {
    const { blocked } = activity.counts;
    set('quick-activity', blocked ? `${blocked} 条未放行 · 共 ${activity.events.length} 条记录` : `共 ${activity.events.length} 条记录，暂无未放行`);
  }
  const domains = lines($('domains').value).length;
  const networks = lines($('networks').value).length;
  if (baseline !== null) set('quick-policy', `域名 ${domains} 项 · IPv4 ${networks} 项${dirty ? ' · 有未保存修改' : ''}`);
  if (ps5.loaded) {
    const online = ps5.hosts.filter((host) => host.online);
    if (ps5.discovery.scanning && !ps5.hosts.length) set('quick-ps5', '正在扫描局域网…');
    else if (!ps5.hosts.length) set('quick-ps5', '未发现主机，进入页面重新扫描');
    else {
      const upgradable = ps5.hosts.reduce((sum, host) => sum + ps5UpgradeCandidates(host).length, 0);
      set('quick-ps5', `${online.length} 台在线 · ${ps5.hosts.map((host) => host.ip).join('、')}${upgradable ? ` · ${upgradable} 个插件可更新` : ''}`);
    }
  }
  if (files.info && files.info.host) set('quick-files', `${files.info.reachable ? '已连接' : '无法连接'} ${files.info.host}`);
}

/* ── 轮询 ───────────────────────────────────────────────────────────── */

function stopPolling() {
  clearTimeout(pollTimer);
  pollTimer = null;
}

function schedulePoll() {
  stopPolling();
  if (authenticated) pollTimer = setTimeout(() => refreshState(), POLL_MS);
}

async function refreshState({ forceConfig = false, manual = false } = {}) {
  if (refreshing || busy || uploading || passwordBusy) {
    schedulePoll();
    return false;
  }
  stopPolling();
  refreshing = true;
  const requestEpoch = epoch;
  if (manual) actBusy('refresh', true);
  updateControls();
  try {
    const data = await api('/api/state');
    if (requestEpoch !== epoch) return false;
    renderState(data, forceConfig);
    if (manual) toast('服务状态已刷新。', 'success');
    if (requestEpoch === epoch) refreshRepo();
    if (requestEpoch === epoch) refreshActivity();
    // The PS5 page polls hosts every cycle; elsewhere a slower refresh keeps
    // the overview summary current without hammering the console.
    if (requestEpoch === epoch && (currentSection === 'ps5' || Date.now() - ps5FetchedAt > 30000)) refreshPs5();
    if (requestEpoch === epoch && currentSection === 'overview') maybeRefreshOverviewExtras({ force: manual });
    return true;
  } catch (error) {
    if (requestEpoch !== epoch) return false;
    if (error.status === 401) {
      showLogin(authenticated ? `${error.message}${dirty ? ' 未保存的编辑已暂存，重新登录后可继续。' : ''}` : '');
    } else if (!authenticated) {
      showLogin(error.message);
    } else {
      setConnection('同步失败 · 数据可能已过期', 'error');
      toast(error.message, 'error');
    }
    return false;
  } finally {
    refreshing = false;
    if (manual) actBusy('refresh', false);
    updateControls();
    schedulePoll();
  }
}

function handleRefresh() {
  if (!authenticated) return;
  if (currentSection === 'activity') refreshActivity({ manual: true });
  else if (currentSection === 'repository') refreshRepo({ manual: true });
  else refreshState({ manual: true });
}
