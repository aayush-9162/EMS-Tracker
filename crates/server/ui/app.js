'use strict';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

const state = {
  page: 'overview',
  range: 'today',
  visitCategory: 'suspicious',
  // The signed-in user: { username, role, access:{orgId:[perms]} }.
  me: null,
  // The organisation every page except "Organisations"/"Users" is showing.
  org: null,
  orgs: [],
  agentAvailable: false,
  machines: [],
  blocked: [],
  loadedSettings: false,
};

const ERRORS = {
  invalid_credentials: 'Wrong username or password.',
  too_many_attempts: 'Too many failed attempts. Try again in a few minutes.',
  invalid_domain: 'That is not a valid domain. Enter something like example.com.',
  cannot_block_this_server: 'That would block this console itself, so agents could never be told to unblock it.',
  invalid_word: 'Enter a word or phrase of at least 2 characters.',
  keyword_required: 'Enter a word of at least 2 characters.',
  password_too_short: 'The new password must be at least 8 characters.',
  wrong_current_password: 'The current password is not correct.',
  not_found: 'That item no longer exists.',
  bad_command: 'Choose restart or shut down.',
  agent_not_available: 'The agent program is not on the server yet. Upload ems-agent.exe on the Organisations page.',
  not_an_agent_program: 'That file is not an EMS agent of version 1.1 or later, so it was not accepted.',
  org_name_invalid: 'Enter a name of 2 to 60 characters.',
  org_name_taken: 'An organisation with this name already exists. Each organisation needs its own name.',
  org_name_mismatch: 'The name typed does not match, so nothing was removed.',
  organisation_required: 'Choose an organisation first.',
  unknown_organisation: 'That organisation no longer exists.',
  forbidden: 'You do not have permission for that.',
  user_name_invalid: 'Enter a username of 2 to 64 characters.',
  user_name_taken: 'That username is already taken.',
  unknown_user: 'That user no longer exists.',
  cannot_remove_self: 'You cannot remove your own account.',
  last_owner: 'There must be at least one owner.',
  owner_has_all_access: 'An owner already has access to everything.',
  server_error: 'The server could not complete the request. Try again.',
};

class ApiError extends Error {}

async function api(path, opts = {}) {
  const init = { method: opts.method || 'GET', headers: {}, credentials: 'same-origin' };
  // Says which organisation the request is about. The server checks it on every call.
  if (state.org != null) init.headers['X-EMS-Org'] = String(state.org);
  if (opts.body !== undefined) {
    init.headers['Content-Type'] = 'application/json';
    init.body = JSON.stringify(opts.body);
  }
  // A file, sent as it is.
  if (opts.raw !== undefined) {
    init.headers['Content-Type'] = 'application/octet-stream';
    init.body = opts.raw;
  }
  Object.assign(init.headers, opts.headers || {});
  let res;
  try {
    res = await fetch('/api' + path, init);
  } catch {
    throw new ApiError('Cannot reach the server. Check the connection and try again.');
  }
  if (res.status === 401 && path !== '/login') {
    showLogin();
    throw new ApiError('Signed out.');
  }
  const data = await res.json().catch(() => ({}));
  // Answered by the web server in front of EMS, not by EMS itself.
  if (res.status === 413) throw new ApiError('The web server in front of EMS refused a file this large. Raise its upload limit, or copy the file into the server data folder instead.');
  if (!res.ok) throw new ApiError(ERRORS[data.error] || data.error || res.statusText);
  return data;
}

function esc(s) {
  return String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

function fmtDuration(sec) {
  sec = Math.max(0, Math.round(Number(sec) || 0));
  if (sec < 60) return `${sec}s`;
  const m = Math.floor(sec / 60);
  if (m < 60) return `${m}m ${sec % 60}s`;
  const h = Math.floor(m / 60);
  return `${h}h ${String(m % 60).padStart(2, '0')}m`;
}

/** Accepts Unix seconds or milliseconds. */
function toDate(t) {
  const n = Number(t) || 0;
  return new Date(n < 1e11 ? n * 1000 : n);
}

function fmtWhen(t) {
  if (!t) return '';
  return toDate(t).toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

function fmtAgo(t) {
  if (!t) return 'never';
  const s = Math.max(0, Math.round((Date.now() - toDate(t).getTime()) / 1000));
  if (s < 90) return 'just now';
  if (s < 3600) return `${Math.round(s / 60)} min ago`;
  if (s < 86400) return `${Math.round(s / 3600)} h ago`;
  return fmtWhen(t);
}

function fmtBytes(n) {
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(0)} KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / 1048576).toFixed(1)} MB`;
  return `${(n / 1073741824).toFixed(2)} GB`;
}

/** The label as the main name with the computer name in brackets when a
 *  label is set — e.g. "Front desk (DESKTOP-V3M7L2B)"; just the computer
 *  name otherwise. */
function machineName(m) {
  const name = m.hostname || (m.machine_uuid ? m.machine_uuid.slice(0, 8) : 'unknown');
  const label = (m.label || '').trim();
  return label && label.toLowerCase() !== name.toLowerCase() ? `${label} (${name})` : name;
}

function machineCell(r) {
  const user = r.os_user ? `<div class="sub2">${esc(r.os_user)}</div>` : '';
  return `<td><div>${esc(machineName(r))}</div>${user}</td>`;
}

/** Only ever link to plain web addresses. */
function linkCell(url, title) {
  if (!url) return `<td class="url">${title ? `<div class="title">${esc(title)}</div>` : ''}</td>`;
  const safe = /^https?:\/\//i.test(url);
  const text = safe ? `<a href="${esc(url)}" target="_blank" rel="noopener noreferrer">${esc(url)}</a>` : esc(url);
  return `<td class="url">${text}${title ? `<div class="title">${esc(title)}</div>` : ''}</td>`;
}

function emptyRow(cols, text) {
  return `<tr><td colspan="${cols}" class="empty">${esc(text)}</td></tr>`;
}

function setMsg(el, text, isError) {
  el.textContent = text || '';
  el.classList.toggle('error', Boolean(isError));
  el.classList.toggle('hint', !isError);
}

/** Page-level problems go in a banner. Nothing here ever blocks the page with a dialog. */
function banner(text) {
  const el = $('#banner');
  el.textContent = text || '';
  el.hidden = !text;
}

async function guarded(el, fn) {
  try {
    await fn();
    if (!el) banner('');
  } catch (err) {
    if (el) setMsg(el, err.message, true);
    else if (err.message !== 'Signed out.') banner(err.message);
  }
}

// ---------------------------------------------------------------------------
// Date range
// ---------------------------------------------------------------------------

function isoDay(d) {
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
}

function startOfDay(offsetDays = 0) {
  const d = new Date();
  d.setHours(0, 0, 0, 0);
  d.setDate(d.getDate() + offsetDays);
  return d;
}

/** The selected period as Unix-ms bounds, in the viewer's own time zone. */
function currentRange() {
  const endOfToday = startOfDay(1).getTime() - 1;
  switch (state.range) {
    case 'yesterday': return { since: startOfDay(-1).getTime(), until: startOfDay(0).getTime() - 1 };
    case '7d': return { since: startOfDay(-6).getTime(), until: endOfToday };
    case '30d': return { since: startOfDay(-29).getTime(), until: endOfToday };
    case 'custom': {
      const from = $('#from').value ? new Date($('#from').value + 'T00:00:00') : startOfDay(0);
      const to = $('#to').value ? new Date($('#to').value + 'T00:00:00') : from;
      const lo = Math.min(from.getTime(), to.getTime());
      const hi = Math.max(from.getTime(), to.getTime());
      return { since: lo, until: hi + 86400000 - 1 };
    }
    default: return { since: startOfDay(0).getTime(), until: endOfToday };
  }
}

function rangeParams(extra = {}) {
  const { since, until } = currentRange();
  const p = new URLSearchParams({ since, until });
  if ($('#machine').value) p.set('machine_uuid', $('#machine').value);
  for (const [k, v] of Object.entries(extra)) if (v !== '' && v != null) p.set(k, v);
  return p.toString();
}

// ---------------------------------------------------------------------------
// Tooltip (hover and keyboard focus)
// ---------------------------------------------------------------------------

const tip = $('#tooltip');

function showTip(target, html) {
  tip.innerHTML = html;
  tip.hidden = false;
  const r = target.getBoundingClientRect();
  const t = tip.getBoundingClientRect();
  let x = r.left + r.width / 2 - t.width / 2;
  x = Math.max(8, Math.min(x, window.innerWidth - t.width - 8));
  let y = r.top - t.height - 8;
  if (y < 8) y = r.bottom + 8;
  tip.style.left = `${x}px`;
  tip.style.top = `${y}px`;
}

function bindTips(root) {
  for (const el of $$('[data-tip]', root)) {
    const show = () => showTip(el, el.dataset.tip);
    const hide = () => { tip.hidden = true; };
    el.addEventListener('mouseenter', show);
    el.addEventListener('mouseleave', hide);
    el.addEventListener('focus', show);
    el.addEventListener('blur', hide);
  }
}

// ---------------------------------------------------------------------------
// Overview
// ---------------------------------------------------------------------------

/** Round axis maximum and step for a duration axis. */
function niceAxis(maxSec) {
  const steps = [60, 300, 600, 900, 1800, 3600, 7200, 14400, 28800, 43200, 86400, 172800, 432000, 864000, 1728000];
  const step = steps.find((s) => maxSec / s <= 4) || Math.ceil(maxSec / 4 / 86400) * 86400;
  const ticks = Math.max(1, Math.ceil(maxSec / step));
  return { step, max: step * ticks, ticks };
}

function axisLabel(sec) {
  if (sec === 0) return '0';
  if (sec < 3600) return `${Math.round(sec / 60)}m`;
  const h = sec / 3600;
  return `${Number.isInteger(h) ? h : h.toFixed(1)}h`;
}

function renderActivity(o) {
  const el = $('#activity');
  const hourly = o.bucket_ms <= 3600000;
  $('#activity-title').textContent = hourly ? 'Active time by hour' : 'Active time by day';
  $('#activity-sub').textContent = $('#machine').value ? 'Time at the keyboard on the selected computer' : 'Time at the keyboard, all computers combined';

  const byBucket = new Map(o.series.map((p) => [p.t, p.sec]));
  const end = Math.min(o.until, Date.now());
  const points = [];
  for (let t = o.since; t <= end; t += o.bucket_ms) points.push({ t, sec: byBucket.get(t) || 0 });
  const max = Math.max(...points.map((p) => p.sec), 0);
  if (!points.length || max === 0) {
    el.innerHTML = '<div class="empty" style="grid-column:1/-1">No activity recorded in this period.</div>';
    return;
  }

  const axis = niceAxis(max);
  const yLabels = [];
  for (let i = 0; i <= axis.ticks; i++) yLabels.push(`<span>${axisLabel(i * axis.step)}</span>`);
  const grid = [];
  for (let i = 1; i <= axis.ticks; i++) grid.push(`<div class="gridline" style="bottom:${(i / axis.ticks) * 100}%"></div>`);

  const fmtBucket = (t) => {
    const d = new Date(t);
    return hourly
      ? `${d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' })}, ${String(d.getHours()).padStart(2, '0')}:00 to ${String((d.getHours() + 1) % 24).padStart(2, '0')}:00`
      : d.toLocaleDateString(undefined, { weekday: 'short', month: 'short', day: 'numeric' });
  };
  const every = Math.ceil(points.length / 8);
  const bars = points.map((p) => {
    const tipHtml = `<b>${esc(fmtBucket(p.t))}</b>${esc(fmtDuration(p.sec))} active`;
    return `<div class="slot" tabindex="0" data-tip="${esc(tipHtml)}" aria-label="${esc(fmtBucket(p.t))}: ${esc(fmtDuration(p.sec))}">
      <div class="bar" style="height:${(p.sec / axis.max) * 100}%"></div></div>`;
  });
  const xLabels = points.map((p, i) => {
    if (i % every !== 0) return '<span></span>';
    const d = new Date(p.t);
    const text = hourly ? `${String(d.getHours()).padStart(2, '0')}:00` : d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
    return `<span>${esc(text)}</span>`;
  });

  el.innerHTML = `
    <div class="yaxis">${yLabels.join('')}</div>
    <div class="plot">${grid.join('')}<div class="bars-row">${bars.join('')}</div></div>
    <div class="xaxis">${xLabels.join('')}</div>`;
  bindTips(el);
}

function renderCategoryBar(o) {
  const el = $('#categories-bar');
  const parts = [
    ['productive', 'Productive', o.by_category.productive || 0],
    ['neutral', 'Neutral', o.by_category.neutral || 0],
    ['suspicious', 'Suspicious (unreviewed)', o.by_category.suspicious || 0],
  ];
  const total = parts.reduce((a, p) => a + p[2], 0);
  if (!total) {
    el.innerHTML = '<div class="empty">No browsing recorded in this period.</div>';
    return;
  }
  const names = parts.map(([, name, sec]) => `${name} ${fmtDuration(sec)} (${Math.round((sec / total) * 100)}%)`).join(', ');
  const segs = parts.filter(([, , sec]) => sec > 0).map(([key, name, sec]) => {
    const share = (sec / total) * 100;
    const tipHtml = `<b>${esc(name)}</b>${esc(fmtDuration(sec))}, ${share.toFixed(0)}% of web time`;
    // A share label is printed only where the block is wide enough to hold it.
    return `<div class="part ${key}" style="flex:${sec} 1 0" tabindex="0" data-tip="${esc(tipHtml)}">${share >= 9 ? `${share.toFixed(0)}%` : ''}</div>`;
  });
  const legend = parts.map(([key, name, sec]) => `<span><i class="swatch ${key}"></i>${esc(name)}: ${esc(fmtDuration(sec))}</span>`);
  el.innerHTML = `<div class="segbar" role="img" aria-label="${esc(names)}">${segs.join('')}</div><div class="legend">${legend.join('')}</div>`;
  bindTips(el);
}

function renderBars(el, rows, emptyText) {
  if (!rows.length) {
    el.innerHTML = `<div class="empty">${esc(emptyText)}</div>`;
    return;
  }
  const max = Math.max(...rows.map((r) => r.sec), 1);
  el.innerHTML = rows.map((r) => `
    <div class="bar-row" tabindex="0" data-tip="${esc(`<b>${esc(r.name)}</b>${esc(r.detail)}`)}">
      <div class="name">${esc(r.name)}${r.tag ? `<span class="tag">${esc(r.tag)}</span>` : ''}</div>
      <div class="track"><div class="fill" style="width:${(r.sec / max) * 100}%"></div></div>
      <div class="val">${esc(fmtDuration(r.sec))}</div>
    </div>`).join('');
  bindTips(el);
}

async function loadOverview() {
  const { since, until } = currentRange();
  const bucket = until - since > 2 * 86400000 ? 86400000 : 3600000;
  const o = await api('/overview?' + rangeParams({ bucket_ms: bucket }));
  const tiles = [
    ['Computers online', `${o.machines_online} of ${o.machines_total}`, 'connected right now'],
    ['Active time', fmtDuration(o.active_sec), `${o.active_machines} computer${o.active_machines === 1 ? '' : 's'} with activity`],
    ['Time on websites', fmtDuration(o.web_sec), o.active_sec ? `${Math.round((o.web_sec / o.active_sec) * 100)}% of active time` : ''],
    ['Blocked attempts', o.blocked_attempts.toLocaleString(), 'tries to open a blocked site'],
    ['Blacklist hits', o.word_hits.toLocaleString(), 'pages closed for a restricted term'],
  ];
  $('#tiles').innerHTML = tiles.map(([label, value, note]) =>
    `<div class="tile"><div class="label">${esc(label)}</div><div class="value">${esc(value)}</div><div class="note">${esc(note)}</div></div>`).join('');
  renderActivity(o);
  renderCategoryBar(o);
  renderBars($('#top-domains'), o.top_domains.map((d) => ({ name: d.domain, tag: d.category, sec: d.total_sec, detail: `${fmtDuration(d.total_sec)} over ${d.visits} visit${d.visits === 1 ? '' : 's'} (${d.category})` })), 'No websites recorded in this period.');
  renderBars($('#top-apps'), o.top_apps.map((a) => ({ name: a.app_name, sec: a.total_sec, detail: `${fmtDuration(a.total_sec)} in ${a.sessions} session${a.sessions === 1 ? '' : 's'}` })), 'No applications recorded in this period.');
  renderBars($('#top-machines'), o.top_machines.map((m) => ({ name: machineName(m), sec: m.total_sec, detail: `${fmtDuration(m.total_sec)} active` })), 'No activity recorded in this period.');
}

// ---------------------------------------------------------------------------
// Computers (also feeds every computer picker)
// ---------------------------------------------------------------------------

async function loadMachines() {
  state.machines = await api('/machines');
  const options = state.machines.map((m) => `<option value="${esc(m.machine_uuid)}">${esc(machineName(m))}</option>`).join('');
  const pick = $('#machine');
  const current = pick.value;
  pick.innerHTML = '<option value="">All computers</option>' + options;
  pick.value = state.machines.some((m) => m.machine_uuid === current) ? current : '';
  const scope = $('#block-scope');
  const scopeCurrent = scope.value;
  scope.innerHTML = '<option value="*">All computers</option>' + state.machines.map((m) => `<option value="${esc(m.machine_uuid)}">Only ${esc(machineName(m))}</option>`).join('');
  scope.value = state.machines.some((m) => m.machine_uuid === scopeCurrent) ? scopeCurrent : '*';
  renderMachines();
}

/** Marks a computer whose agent is not the one the server holds, and says what happens next. */
function agentChip(m) {
  if (m.agent_state === 'pending') return ' <span class="chip warn" title="The server holds a newer agent. This computer updates itself at one of its next check-ins.">update pending</span>';
  if (m.agent_state === 'held') return ' <span class="chip" title="The server holds a different agent, but automatic updates are turned off for this organisation under Settings.">updates off</span>';
  return '';
}

function renderMachines() {
  const q = $('#machine-search').value.trim().toLowerCase();
  const rows = state.machines
    .filter((m) => !q || [m.hostname, m.os_user, m.label].some((v) => String(v || '').toLowerCase().includes(q)))
    .sort((a, b) => (b.online - a.online) || String(a.label || a.hostname || '').localeCompare(String(b.label || b.hostname || ''), undefined, { numeric: true, sensitivity: 'base' }));
  const online = state.machines.filter((m) => m.online).length;
  $('#machine-count').textContent = `${online} online, ${state.machines.length} total`;
  $('#machines-body').innerHTML = rows.map((m) => `
    <tr>
      <td><span class="status ${m.online ? 'online' : ''}">${m.online ? 'Online' : 'Offline'}</span>${m.pending_command ? ` <span class="chip warn">${esc(m.pending_command)} queued</span>` : ''}</td>
      <td>${esc(m.hostname || '')}</td>
      <td>${esc(m.os_user || '')}</td>
      <td><input class="label-edit" data-uuid="${esc(m.machine_uuid)}" value="${esc(m.label || '')}" placeholder="Add a label" aria-label="Label for ${esc(m.hostname || 'computer')}" /></td>
      <td>${esc(m.os_version || '')}</td>
      <td>${esc(m.agent_version || '')}${agentChip(m)}</td>
      <td>${esc(m.ip || '')}</td>
      <td class="when">${esc(m.online ? 'now' : fmtAgo(m.last_seen))}</td>
      <td class="actions">${!can('control') ? '' :
        (m.pending_command
          ? `<button class="small" data-cancelcmd="${esc(m.machine_uuid)}">Cancel ${esc(m.pending_command)}</button>`
          : `<button class="small" data-power="lock" data-uuid="${esc(m.machine_uuid)}" data-name="${esc(machineName(m))}">Lock</button>
             <button class="small" data-power="restart" data-uuid="${esc(m.machine_uuid)}" data-name="${esc(machineName(m))}">Restart</button>
             <button class="small" data-power="shutdown" data-uuid="${esc(m.machine_uuid)}" data-name="${esc(machineName(m))}">Shut down</button>`) +
        `<button class="small danger" data-remove="${esc(m.machine_uuid)}" data-name="${esc(machineName(m))}">Remove</button>`}
      </td>
    </tr>`).join('') || emptyRow(9, state.machines.length ? 'No computer matches the search.' : `No computers in ${orgName()} yet. Download its installer under Settings and run it on a computer.`);
}

$('#machines-body').addEventListener('change', (e) => {
  const input = e.target.closest('.label-edit');
  if (!input) return;
  guarded(null, async () => {
    await api(`/machines/${encodeURIComponent(input.dataset.uuid)}`, { method: 'PATCH', body: { label: input.value } });
    await loadMachines();
  });
});

$('#machines-body').addEventListener('click', (e) => {
  const btn = e.target.closest('[data-remove]');
  if (!btn) return;
  if (!window.confirm(`Remove ${btn.dataset.name} and everything recorded for it?\n\nIf the agent is still installed on that computer it will register again.`)) return;
  guarded(null, async () => {
    await api(`/machines/${encodeURIComponent(btn.dataset.remove)}`, { method: 'DELETE' });
    await loadMachines();
  });
});

const POWER_VERB = { restart: 'Restart', shutdown: 'Shut down', lock: 'Lock' };

function openPower(uuid, name, kind) {
  const d = $('#power-dialog');
  d.dataset.uuid = uuid;
  d.dataset.kind = kind;
  const verb = POWER_VERB[kind] || kind;
  $('#power-heading').textContent = `${verb} ${name}?`;
  $('#power-text').textContent = kind === 'lock'
    ? `The screen on ${name} will be locked, so the person has to sign in again to carry on. This reaches the computer at its next check-in (within a few minutes). If it is offline, it happens when it next connects — cancel it here before then if you change your mind.`
    : `The person using ${name} will see a 60-second warning to save their work, then the computer will ${kind === 'restart' ? 'restart' : 'shut down'}. This reaches the computer at its next check-in (within a few minutes). If it is offline, it happens when it next connects — cancel it here before then if you change your mind.`;
  $('#power-go').textContent = verb;
  $('#power-go').className = kind === 'shutdown' ? 'primary danger' : 'primary';
  $('#power-msg').hidden = true;
  d.showModal();
}

$('#machines-body').addEventListener('click', (e) => {
  const power = e.target.closest('[data-power]');
  const cancel = e.target.closest('[data-cancelcmd]');
  if (power) openPower(power.dataset.uuid, power.dataset.name, power.dataset.power);
  if (cancel) guarded(null, async () => {
    await api(`/machines/${encodeURIComponent(cancel.dataset.cancelcmd)}/command`, { method: 'DELETE' });
    await loadMachines();
  });
});

$('#power-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const d = $('#power-dialog');
  const msg = $('#power-msg');
  msg.hidden = true;
  try {
    const res = await api(`/machines/${encodeURIComponent(d.dataset.uuid)}/command`, { method: 'POST', body: { kind: d.dataset.kind } });
    d.close();
    await loadMachines();
    const verb = POWER_VERB[d.dataset.kind] || d.dataset.kind;
    bannerTemp(res.online ? `${verb} sent to the computer. It will act at its next check-in, within a few minutes.` : `${verb} queued. The computer is offline; it will act when it next connects.`);
  } catch (ex) {
    msg.textContent = ex.message;
    msg.hidden = false;
  }
});

$('#power-cancel').addEventListener('click', () => $('#power-dialog').close());

/** A short-lived note in the page banner, cleared after a few seconds. */
function bannerTemp(text) {
  banner(text);
  clearTimeout(bannerTemp.t);
  bannerTemp.t = setTimeout(() => banner(''), 6000);
}

$('#machine-search').addEventListener('input', renderMachines);

// ---------------------------------------------------------------------------
// Websites
// ---------------------------------------------------------------------------

function blockFor(row) {
  return state.blocked.find((b) =>
    (b.machine_uuid === '*' || b.machine_uuid === row.machine_uuid) &&
    (row.domain === b.domain || row.domain.endsWith('.' + b.domain)));
}

const CATEGORY_NAMES = { suspicious: 'Suspicious', neutral: 'Neutral', productive: 'Productive' };

function categorySelect(domain, current) {
  const opts = Object.entries(CATEGORY_NAMES).map(([v, n]) => `<option value="${v}" ${v === current ? 'selected' : ''}>${n}</option>`).join('');
  return `<select data-category-for="${esc(domain)}" aria-label="Category for ${esc(domain)}">${opts}</select>`;
}

async function loadVisits() {
  const rows = await api('/visits?' + rangeParams({ category: state.visitCategory, domain: $('#visit-domain').value.trim(), limit: 300 }));
  $('#visits-body').innerHTML = rows.map((r) => {
    const block = blockFor(r);
    const action = !can('blocking') ? ''
      : block
      ? `<button class="small" data-unblock="${block.id}">Unblock</button>`
      : `<button class="small danger" data-block="${esc(r.domain)}">Block</button>`;
    return `<tr>
      <td class="when">${esc(fmtWhen(r.last_seen))}</td>
      ${machineCell(r)}
      <td>${esc(r.domain)}${block ? ' <span class="chip">blocked</span>' : ''}</td>
      ${linkCell(r.url, r.title)}
      <td>${categorySelect(r.domain, r.category)}</td>
      <td class="num">${r.visits}</td>
      <td class="num">${esc(fmtDuration(r.total_sec))}</td>
      <td>${action}</td>
    </tr>`;
  }).join('') || emptyRow(8, 'Nothing recorded for this selection.');
}

$('#visits-body').addEventListener('click', (e) => {
  const block = e.target.closest('[data-block]');
  const unblock = e.target.closest('[data-unblock]');
  if (!block && !unblock) return;
  guarded(null, async () => {
    if (block) await api('/blocked-domains', { method: 'POST', body: { domain: block.dataset.block, machine_uuid: '*' } });
    else await api(`/blocked-domains/${unblock.dataset.unblock}`, { method: 'DELETE' });
    await loadBlocked();
    await loadVisits();
  });
});

async function setDomainCategory(domain, category) {
  await api(`/categories/domains/${encodeURIComponent(domain)}`, { method: 'PUT', body: { category } });
}

$('#visits-body').addEventListener('change', (e) => {
  const sel = e.target.closest('[data-category-for]');
  if (!sel) return;
  guarded(null, async () => {
    await setDomainCategory(sel.dataset.categoryFor, sel.value);
    await loadVisits();
  });
});

function toCsv(matrix) {
  const cell = (v) => {
    let s = String(v ?? '');
    // Stops a spreadsheet from running a cell that starts like a formula.
    if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;
    return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
  };
  return matrix.map((row) => row.map(cell).join(',')).join('\r\n');
}

function download(text, filename) {
  const blob = new Blob(['﻿' + text], { type: 'text/csv;charset=utf-8' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(a.href);
}

$('#report-download').addEventListener('click', () => guarded(null, async () => {
  const minSec = Math.max(0, Number($('#report-min').value) || 0) * 60;
  const rows = (await api('/visits?' + rangeParams({ category: 'suspicious', limit: 1000 }))).filter((r) => r.total_sec > minSec);
  if (!rows.length) {
    banner('No suspicious visits longer than the minimum in the selected period, so there is nothing to download.');
    return;
  }
  const header = ['Computer', 'User', 'Site', 'Address', 'Visits', 'Total time', 'Total seconds', 'Last seen', 'Blocked'];
  const body = rows.map((r) => [machineName(r), r.os_user || '', r.domain, r.url || '', r.visits, fmtDuration(r.total_sec), r.total_sec, toDate(r.last_seen).toLocaleString(), blockFor(r) ? 'yes' : 'no']);
  const { since, until } = currentRange();
  download(toCsv([header, ...body]), `suspicious-report_${isoDay(new Date(since))}_to_${isoDay(new Date(until))}.csv`);
}));

// ---------------------------------------------------------------------------
// Applications
// ---------------------------------------------------------------------------

async function loadApps() {
  const filter = $('#app-filter').value.trim();
  const [rows, summary] = await Promise.all([
    api('/app-usage?' + rangeParams({ app: filter, limit: 300 })),
    api('/app-usage/summary?' + rangeParams()),
  ]);
  $('#apps-body').innerHTML = rows.map((r) => `
    <tr class="clickable" data-app="${esc(r.app_name)}" data-machine="${esc(r.machine_uuid)}" tabindex="0">
      <td class="when">${esc(fmtWhen(r.last_seen))}</td>
      ${machineCell(r)}
      <td>${esc(r.app_name)}</td>
      <td class="num">${r.sessions}</td>
      <td class="num">${esc(fmtDuration(r.total_sec))}</td>
    </tr>`).join('') || emptyRow(5, 'Nothing recorded for this selection.');
  $('#apps-summary-body').innerHTML = summary.map((r) => `
    <tr class="clickable" data-app="${esc(r.app_name)}" data-machine="" tabindex="0">
      <td>${esc(r.app_name)}</td>
      <td class="num">${r.machines}</td>
      <td class="num">${esc(fmtDuration(r.total_sec))}</td>
    </tr>`).join('') || emptyRow(3, 'Nothing recorded.');
}

async function showTitles(app, machine) {
  const p = new URLSearchParams(rangeParams({ app }));
  if (machine) p.set('machine_uuid', machine);
  const rows = await api('/app-usage/titles?' + p.toString());
  $('#titles-heading').textContent = `Windows open in ${app}`;
  $('#titles-body').innerHTML = rows.map((r) => `
    <tr><td>${esc(r.title || '(no title)')}</td><td class="num">${r.sessions}</td><td class="num">${esc(fmtDuration(r.total_sec))}</td></tr>`).join('') || emptyRow(3, 'Nothing recorded.');
  $('#titles-dialog').showModal();
}

for (const id of ['#apps-body', '#apps-summary-body']) {
  const open = (e) => {
    const tr = e.target.closest('tr[data-app]');
    if (tr && (e.type === 'click' || e.key === 'Enter')) guarded(null, () => showTitles(tr.dataset.app, tr.dataset.machine));
  };
  $(id).addEventListener('click', open);
  $(id).addEventListener('keydown', open);
}
$('#titles-close').addEventListener('click', () => $('#titles-dialog').close());

// ---------------------------------------------------------------------------
// Site blocking
// ---------------------------------------------------------------------------

async function loadBlocked() {
  state.blocked = await api('/blocked-domains');
  $('#blocked-body').innerHTML = state.blocked.map((b) => {
    const scope = b.machine_uuid === '*' ? 'All computers' : `Only ${machineName(b)}`;
    return `<tr>
      <td>${esc(b.domain)}</td>
      <td><span class="chip">${esc(scope)}</span></td>
      <td>${esc(b.note || '')}</td>
      <td class="when">${esc(fmtWhen(b.created_at))}</td>
      <td>${can('blocking') ? `<button class="small" data-unblock="${b.id}">Unblock</button>` : ''}</td>
    </tr>`;
  }).join('') || emptyRow(5, 'No sites are blocked.');
}

async function loadAttempts() {
  const rows = await api('/block-events?' + rangeParams({ limit: 300 }));
  $('#attempts-body').innerHTML = rows.map((r) => `
    <tr>
      <td class="when">${esc(fmtWhen(r.last_seen))}</td>
      ${machineCell(r)}
      <td>${esc(r.domain)}</td>
      ${linkCell(r.url)}
      <td class="num">${r.hit_count}</td>
    </tr>`).join('') || emptyRow(5, 'No attempts in this period.');
}

$('#block-form').addEventListener('submit', (e) => {
  e.preventDefault();
  const msg = $('#block-msg');
  guarded(msg, async () => {
    const res = await api('/blocked-domains', { method: 'POST', body: { domain: $('#block-domain').value, machine_uuid: $('#block-scope').value, note: $('#block-note').value } });
    $('#block-domain').value = '';
    $('#block-note').value = '';
    const wait = res.within_s < 120 ? `${res.within_s} seconds` : `${Math.round(res.within_s / 60)} minutes`;
    setMsg(msg, `${res.domain} is now blocked. Each computer applies it at its next check-in, within about ${wait}.`);
    await loadBlocked();
  });
});

$('#blocked-body').addEventListener('click', (e) => {
  const btn = e.target.closest('[data-unblock]');
  if (!btn) return;
  guarded($('#block-msg'), async () => {
    await api(`/blocked-domains/${btn.dataset.unblock}`, { method: 'DELETE' });
    setMsg($('#block-msg'), 'Unblocked.');
    await loadBlocked();
  });
});

// ---------------------------------------------------------------------------
// Blacklist words
// ---------------------------------------------------------------------------

async function loadWords() {
  const [words, hits] = await Promise.all([api('/blacklist-words'), api('/blacklist-words/hits?' + rangeParams({ limit: 300 }))]);
  $('#word-list').innerHTML = words.map((w) => `
    <span class="pill">${esc(w.word)}${w.note ? `<span class="tag">${esc(w.note)}</span>` : ''}
      <button data-word="${w.id}" aria-label="Remove ${esc(w.word)}" title="Remove">&times;</button></span>`).join('') || '<span class="muted">No words yet.</span>';
  $('#hits-body').innerHTML = hits.map((r) => `
    <tr>
      <td class="when">${esc(fmtWhen(r.last_hit))}</td>
      ${machineCell(r)}
      <td>${esc(r.word)}</td>
      <td>${esc(r.domain)}</td>
      ${linkCell(r.url)}
      <td class="num">${r.hit_count}</td>
    </tr>`).join('') || emptyRow(6, 'No detections yet.');
}

$('#word-form').addEventListener('submit', (e) => {
  e.preventDefault();
  guarded(null, async () => {
    await api('/blacklist-words', { method: 'POST', body: { word: $('#word-text').value, note: $('#word-note').value } });
    $('#word-text').value = '';
    $('#word-note').value = '';
    await loadWords();
  });
});

$('#word-list').addEventListener('click', (e) => {
  const btn = e.target.closest('[data-word]');
  if (btn) guarded(null, async () => { await api(`/blacklist-words/${btn.dataset.word}`, { method: 'DELETE' }); await loadWords(); });
});

// ---------------------------------------------------------------------------
// Categories
// ---------------------------------------------------------------------------

async function loadCategories() {
  const [keywords, domains] = await Promise.all([api('/categories/keywords'), api('/categories/domains')]);
  $('#keyword-list').innerHTML = keywords.map((k) => `
    <span class="pill">${esc(k.keyword)}<span class="tag">${esc(CATEGORY_NAMES[k.category] || k.category)}</span>
      <button data-keyword="${k.id}" aria-label="Remove rule ${esc(k.keyword)}" title="Remove">&times;</button></span>`).join('') || '<span class="muted">No word rules yet.</span>';
  $('#domain-cat-body').innerHTML = domains.map((d) => `
    <tr>
      <td>${esc(d.domain)}</td>
      <td>${categorySelect(d.domain, d.category)}</td>
      <td class="when">${esc(fmtWhen(d.updated_at))}</td>
      <td><button class="small" data-clear="${esc(d.domain)}">Clear</button></td>
    </tr>`).join('') || emptyRow(4, 'No domain categories yet.');
}

$('#keyword-form').addEventListener('submit', (e) => {
  e.preventDefault();
  guarded(null, async () => {
    await api('/categories/keywords', { method: 'POST', body: { keyword: $('#keyword-text').value, category: $('#keyword-category').value } });
    $('#keyword-text').value = '';
    await loadCategories();
  });
});

$('#keyword-list').addEventListener('click', (e) => {
  const btn = e.target.closest('[data-keyword]');
  if (btn) guarded(null, async () => { await api(`/categories/keywords/${btn.dataset.keyword}`, { method: 'DELETE' }); await loadCategories(); });
});

$('#domain-cat-form').addEventListener('submit', (e) => {
  e.preventDefault();
  guarded(null, async () => {
    await setDomainCategory($('#domain-cat-domain').value.trim(), $('#domain-cat-category').value);
    $('#domain-cat-domain').value = '';
    await loadCategories();
  });
});

$('#domain-cat-body').addEventListener('change', (e) => {
  const sel = e.target.closest('[data-category-for]');
  if (sel) guarded(null, async () => { await setDomainCategory(sel.dataset.categoryFor, sel.value); await loadCategories(); });
});

$('#domain-cat-body').addEventListener('click', (e) => {
  const btn = e.target.closest('[data-clear]');
  if (btn) guarded(null, async () => { await api(`/categories/domains/${encodeURIComponent(btn.dataset.clear)}`, { method: 'DELETE' }); await loadCategories(); });
});

// ---------------------------------------------------------------------------
// Roles and permissions
// ---------------------------------------------------------------------------

function isOwner() {
  return !!state.me && state.me.role === 'owner';
}

/** Whether the signed-in user may do `perm` in the currently selected org. */
function can(perm) {
  if (isOwner()) return true;
  if (!state.me || state.org == null) return false;
  const perms = (state.me.access || {})[String(state.org)];
  if (perms == null) return false; // no access to this organisation
  return perm === 'view' ? true : perms.includes(perm);
}

/** Shows or hides the owner-only nav and the permission-gated controls. */
function applyRole() {
  const owner = isOwner();
  $$('#nav button[data-page="orgs"], #nav button[data-page="users"]').forEach((b) => (b.hidden = !owner));
  updatePermUI();
}

function updatePermUI() {
  const settingsBtn = $('#nav button[data-page="settings"]');
  if (settingsBtn) settingsBtn.hidden = !(isOwner() || can('settings'));
  const blocking = can('blocking');
  ['#block-form', '#word-form', '#keyword-form', '#domain-cat-form'].forEach((sel) => {
    const el = $(sel);
    if (el) el.hidden = !blocking;
  });
  const installer = can('installer');
  ['#download-installer', '#download-setup-file'].forEach((sel) => {
    const el = $(sel);
    if (el) el.disabled = !installer;
  });
}

// ---------------------------------------------------------------------------
// Organisations
// ---------------------------------------------------------------------------

function orgName(id = state.org) {
  const org = state.orgs.find((o) => o.id === id);
  return org ? org.name : 'this organisation';
}

/** Shows, next to the page title, which organisation the page is about. */
function showPageOrg() {
  const el = $('#page-org');
  const page = PAGES[state.page];
  el.hidden = !page || page.all || state.org == null;
  el.textContent = orgName();
}

function rememberOrg(id) {
  try { localStorage.setItem('ems-org', String(id)); } catch { /* private browsing: the choice lasts for this visit only */ }
}

function rememberedOrg() {
  try { return Number(localStorage.getItem('ems-org')) || null; } catch { return null; }
}

/** Switches every page to another organisation. Nothing of the previous one is kept on screen. */
function setOrg(id) {
  state.org = id;
  if (id != null) rememberOrg(id);
  state.machines = [];
  state.blocked = [];
  state.loadedSettings = false;
  $('#machine').value = '';
  $('#org').value = id == null ? '' : String(id);
  $('#api-key-value').hidden = true;
  for (const msg of ['#block-msg', '#settings-msg']) setMsg($(msg), '');
  showPageOrg();
  updatePermUI();
}

/** Reads the list of organisations and fills the picker and the Organisations page. */
async function loadOrgs() {
  const d = await api('/orgs');
  state.orgs = d.orgs;
  state.agentAvailable = d.agent.available;
  state.agentVersion = d.agent.version || null;
  const pick = $('#org');
  pick.innerHTML = state.orgs.map((o) => `<option value="${o.id}">${esc(o.name)}</option>`).join('') || '<option value="">No organisation yet</option>';
  pick.disabled = !state.orgs.length;
  const known = (id) => state.orgs.some((o) => o.id === id);
  // Keep the current one if it still exists; otherwise the one used last time, or the first.
  const next = known(state.org) ? state.org : known(rememberedOrg()) ? rememberedOrg() : (state.orgs[0] ? state.orgs[0].id : null);
  if (next !== state.org) setOrg(next);
  else pick.value = next == null ? '' : String(next);
  showPageOrg();
  renderOrgs();
}

/** How far an organisation's computers have got with the agent the server holds. */
function agentProgress(o) {
  const known = o.agent_current + o.agent_behind;
  if (!state.agentAvailable || !known) return '<span class="muted">no report yet</span>';
  if (!o.agent_behind) return `${o.agent_current} of ${known} up to date`;
  const why = o.auto_update ? 'updating' : 'updates off';
  return `${o.agent_current} of ${known} up to date <span class="chip ${o.auto_update ? 'warn' : ''}">${why}</span>`;
}

function renderOrgs() {
  $('#org-create').textContent = state.agentAvailable ? 'Create and download installer' : 'Create';
  $('#agent-program-state').textContent = state.agentAvailable
    ? `The server holds agent version ${state.agentVersion || 'unknown'}. Every organisation's installer is made from it, and installed computers keep themselves on it.`
    : 'The server has no agent program yet, so it cannot make installers. Upload ems-agent.exe here.';
  $('#orgs-body').innerHTML = state.orgs.map((o) => `
    <tr class="${o.id === state.org ? 'current' : ''}">
      <td><input class="org-edit" data-org-rename="${o.id}" value="${esc(o.name)}" maxlength="60" aria-label="Name of ${esc(o.name)}" /></td>
      <td class="num">${o.machines}</td>
      <td class="num">${o.online}</td>
      <td>${agentProgress(o)}</td>
      <td class="when">${esc(fmtWhen(o.created_at))}</td>
      <td class="actions">
        <button class="small" data-org-installer="${o.id}">${state.agentAvailable ? 'Download installer' : 'Download ems-agent.json'}</button>
        <button class="small" data-org-open="${o.id}">Open</button>
        <button class="small danger" data-org-remove="${o.id}">Remove</button>
      </td>
    </tr>`).join('') || emptyRow(6, 'No organisations yet. Enter the name of the first one above.');
}

$('#agent-upload-form').addEventListener('submit', (e) => {
  e.preventDefault();
  const msg = $('#agent-upload-msg');
  const file = $('#agent-file').files[0];
  if (!file) return;
  const button = $('#agent-upload-go');
  guarded(msg, async () => {
    button.disabled = true;
    setMsg(msg, `Uploading ${file.name}...`);
    try {
      // The password travels in a header, encoded so that any character fits.
      const res = await api('/agent-program', { method: 'POST', raw: await file.arrayBuffer(), headers: { 'X-EMS-Password': encodeURIComponent($('#agent-password').value) } });
      $('#agent-password').value = '';
      $('#agent-file').value = '';
      await loadOrgs();
      setMsg(msg, res.unchanged
        ? `The server already holds exactly this program (version ${res.version}). Nothing changes.`
        : `Version ${res.version} is now on the server. Each computer moves to it at its next check-in; the Agent column above shows how far each organisation has got.`);
    } finally {
      button.disabled = false;
    }
  });
});

$('#org').addEventListener('change', (e) => {
  setOrg(Number(e.target.value) || null);
  renderOrgs();
  reload();
});

$('#org-form').addEventListener('submit', (e) => {
  e.preventDefault();
  const msg = $('#org-msg');
  guarded(msg, async () => {
    const res = await api('/orgs', { method: 'POST', body: { name: $('#org-name').value } });
    $('#org-name').value = '';
    await loadOrgs();
    setOrg(res.org.id);
    renderOrgs();
    if (state.agentAvailable) {
      downloadInstaller(res.org.id);
      setMsg(msg, `${res.org.name} was created and its installer is downloading. Run it on each of its computers; they appear under ${res.org.name} by themselves.`);
    } else {
      setMsg(msg, `${res.org.name} was created. The agent program is not on the server, so no installer could be made: use "Download ems-agent.json" in its row.`);
    }
  });
});

$('#orgs-body').addEventListener('click', (e) => {
  const installer = e.target.closest('[data-org-installer]');
  const open = e.target.closest('[data-org-open]');
  const remove = e.target.closest('[data-org-remove]');
  if (installer) downloadInstaller(Number(installer.dataset.orgInstaller), state.agentAvailable ? 'agent-installer' : 'agent-setup');
  if (open) {
    setOrg(Number(open.dataset.orgOpen));
    go('overview');
  }
  if (remove) {
    const org = state.orgs.find((o) => o.id === Number(remove.dataset.orgRemove));
    if (!org) return;
    const dialog = $('#org-remove-dialog');
    dialog.dataset.org = String(org.id);
    $('#org-remove-heading').textContent = `Remove ${org.name}?`;
    $('#org-remove-text').textContent = `This deletes ${org.name}, its ${org.machines} computer${org.machines === 1 ? '' : 's'} and everything recorded for them, and cannot be undone. Agents still installed on its computers will be turned away by the server; uninstall them on those computers.`;
    $('#org-remove-name').value = '';
    $('#org-remove-msg').hidden = true;
    dialog.showModal();
  }
});

$('#orgs-body').addEventListener('change', (e) => {
  const input = e.target.closest('[data-org-rename]');
  if (!input) return;
  guarded($('#org-msg'), async () => {
    try {
      const res = await api(`/orgs/${input.dataset.orgRename}`, { method: 'PATCH', body: { name: input.value } });
      setMsg($('#org-msg'), `Renamed to ${res.name}.`);
    } finally {
      // Shows the stored name again, whether or not the change was accepted.
      await loadOrgs();
    }
  });
});

$('#org-remove-cancel').addEventListener('click', () => $('#org-remove-dialog').close());

$('#org-remove-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const dialog = $('#org-remove-dialog');
  const err = $('#org-remove-msg');
  err.hidden = true;
  try {
    await api(`/orgs/${dialog.dataset.org}`, { method: 'DELETE', body: { name: $('#org-remove-name').value } });
    dialog.close();
    await loadOrgs();
    setMsg($('#org-msg'), 'The organisation was removed.');
    if (state.org == null) go('orgs');
  } catch (ex) {
    err.textContent = ex.message;
    err.hidden = false;
  }
});

// ---------------------------------------------------------------------------
// Users and permissions (owner only)
// ---------------------------------------------------------------------------

const PERM_LABEL = { blocking: 'Blocking', settings: 'Settings', control: 'Control', installer: 'Installer' };

async function loadUsers() {
  state.usersData = await api('/users');
  renderUsers();
}

function renderUsers() {
  const d = state.usersData;
  const orgName2 = (id) => (d.orgs.find((o) => o.id === id) || {}).name || `#${id}`;
  $('#users-body').innerHTML = d.users.map((u) => {
    const access = u.role === 'owner'
      ? '<span class="chip">all organisations</span>'
      : (u.access.length
          ? u.access.map((a) => `<span class="chip">${esc(orgName2(a.org_id))}${a.perms.length ? ': ' + a.perms.map((p) => PERM_LABEL[p] || p).join(', ') : ' (view only)'}</span>`).join(' ')
          : '<span class="muted">no access yet</span>');
    const you = u.username === (state.me && state.me.username);
    const actions = you
      ? '<span class="muted">you</span>'
      : `${u.role === 'member' ? `<button class="small" data-access="${u.id}">Edit access</button>` : ''}
         <button class="small" data-resetpw="${u.id}" data-name="${esc(u.username)}">Reset password</button>
         <button class="small danger" data-deluser="${u.id}" data-name="${esc(u.username)}">Remove</button>`;
    return `<tr>
      <td>${esc(u.username)}</td>
      <td>${u.role === 'owner' ? '<span class="chip">Owner</span>' : 'Member'}</td>
      <td>${access}</td>
      <td class="when">${esc(fmtWhen(u.created_at))}</td>
      <td class="actions">${actions}</td>
    </tr>`;
  }).join('') || emptyRow(5, 'No users yet.');
}

$('#user-form').addEventListener('submit', (e) => {
  e.preventDefault();
  const msg = $('#user-msg');
  guarded(msg, async () => {
    const res = await api('/users', { method: 'POST', body: { username: $('#user-name').value, password: $('#user-pass').value, owner: $('#user-owner').checked } });
    $('#user-name').value = '';
    $('#user-pass').value = '';
    $('#user-owner').checked = false;
    await loadUsers();
    setMsg(msg, 'User created. Use "Edit access" to choose which organisations they manage.');
    if (res.id) openAccess(res.id);
  });
});

$('#users-body').addEventListener('click', (e) => {
  const access = e.target.closest('[data-access]');
  const resetpw = e.target.closest('[data-resetpw]');
  const del = e.target.closest('[data-deluser]');
  if (access) openAccess(Number(access.dataset.access));
  if (resetpw) {
    const d = $('#userpw-dialog');
    d.dataset.user = resetpw.dataset.resetpw;
    $('#userpw-heading').textContent = `Reset password for ${resetpw.dataset.name}`;
    $('#userpw-new').value = '';
    $('#userpw-msg').hidden = true;
    d.showModal();
  }
  if (del) {
    if (!window.confirm(`Remove the user ${del.dataset.name}? They will no longer be able to sign in.`)) return;
    guarded($('#user-msg'), async () => {
      await api(`/users/${del.dataset.deluser}`, { method: 'DELETE' });
      await loadUsers();
    });
  }
});

$('#userpw-form').addEventListener('submit', (e) => {
  e.preventDefault();
  const d = $('#userpw-dialog');
  guarded($('#userpw-msg'), async () => {
    await api(`/users/${d.dataset.user}/password`, { method: 'POST', body: { password: $('#userpw-new').value } });
    d.close();
    setMsg($('#user-msg'), 'Password changed. That user has been signed out.');
  });
});
$('#userpw-cancel').addEventListener('click', () => $('#userpw-dialog').close());

/** Opens the access matrix for a member. */
function openAccess(userId) {
  const d = state.usersData;
  const u = d.users.find((x) => x.id === userId);
  if (!u) return;
  const dlg = $('#access-dialog');
  dlg.dataset.user = userId;
  $('#access-heading').textContent = `Access for ${u.username}`;
  const current = {};
  u.access.forEach((a) => (current[a.org_id] = new Set(a.perms)));
  $('#access-body').innerHTML = d.orgs.map((o) => {
    const has = current[o.id];
    const cells = d.permissions.map((p) => `<td class="num"><input type="checkbox" data-perm="${p}" data-org="${o.id}" ${has && has.has(p) ? 'checked' : ''} ${has ? '' : 'disabled'} /></td>`).join('');
    return `<tr><td>${esc(o.name)}</td><td class="num"><input type="checkbox" data-access-org="${o.id}" ${has ? 'checked' : ''} /></td>${cells}</tr>`;
  }).join('') || emptyRow(6, 'No organisations yet. Create one first.');
  $('#access-msg').hidden = true;
  dlg.showModal();
}

$('#access-body').addEventListener('change', (e) => {
  const acc = e.target.closest('[data-access-org]');
  if (!acc) return;
  $$(`#access-body [data-org="${acc.dataset.accessOrg}"]`).forEach((cb) => {
    cb.disabled = !acc.checked;
    if (!acc.checked) cb.checked = false;
  });
});

$('#access-save').addEventListener('click', () => guarded($('#access-msg'), async () => {
  const grants = [];
  $$('#access-body [data-access-org]').forEach((acc) => {
    if (!acc.checked) return;
    const perms = $$(`#access-body [data-org="${acc.dataset.accessOrg}"]`).filter((cb) => cb.checked).map((cb) => cb.dataset.perm);
    grants.push({ org_id: Number(acc.dataset.accessOrg), perms });
  });
  await api(`/users/${$('#access-dialog').dataset.user}/access`, { method: 'PUT', body: { grants } });
  $('#access-dialog').close();
  await loadUsers();
}));
$('#access-close').addEventListener('click', () => $('#access-dialog').close());
$('#access-cancel').addEventListener('click', () => $('#access-dialog').close());

// ---------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------


async function loadSettings() {
  const d = await api('/settings');
  const s = d.settings;
  if (!state.loadedSettings) {
    $('#set-track-web').checked = s.track_web;
    $('#set-track-apps').checked = s.track_apps;
    $('#set-url-mode').value = s.url_mode;
    $('#set-idle').value = Math.round(s.idle_threshold_s / 60);
    $('#set-upload').value = s.upload_interval_s;
    $('#set-close-tabs').checked = s.close_blocked_tabs;
    $('#set-notify').checked = s.notify_user;
    $('#set-browser-policy').checked = s.browser_policy;
    $('#set-auto-update').checked = s.auto_update;
    $('#set-retention').value = s.retention_days;
    $('#set-tz').value = s.tz_offset_min;
    state.loadedSettings = true;
  }
  const local = -new Date().getTimezoneOffset();
  $('#tz-hint').textContent = `Used for calendar days in the report API. Your browser's zone is ${local >= 0 ? '+' : ''}${local} minutes.`;
  state.agentAvailable = d.agent.available;
  $('#installer-ready').hidden = !d.agent.available;
  $('#installer-missing').hidden = d.agent.available;
  for (const el of $$('#page-settings .org-name')) el.textContent = d.org.name;
  $('#api-key-state').textContent = d.api_key_enabled ? 'A key is active. Creating a new one replaces it.' : 'No key is active.';
  $('#api-key-revoke').disabled = !d.api_key_enabled;
  const up = d.server.uptime_s;
  $('#server-info').innerHTML = [
    ['Version', d.server.version],
    ['Agent it hands out', d.agent.available ? `version ${d.agent.version || 'unknown'}` : 'none (ems-agent.exe is not in the data folder)'],
    ['Running for', up < 3600 ? `${Math.round(up / 60)} min` : up < 172800 ? `${(up / 3600).toFixed(1)} h` : `${Math.round(up / 86400)} days`],
    ['Database size', fmtBytes(d.server.db_bytes)],
    ['Organisations', String(d.server.organisations)],
    ['Computers', `${d.org.machines} in ${d.org.name} (${d.org.online} online), ${d.server.machines} in all`],
  ].map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(v)}</dd>`).join('');
}

$('#settings-form').addEventListener('submit', (e) => {
  e.preventDefault();
  const msg = $('#settings-msg');
  guarded(msg, async () => {
    await api('/settings', { method: 'PUT', body: {
      track_web: $('#set-track-web').checked,
      track_apps: $('#set-track-apps').checked,
      url_mode: $('#set-url-mode').value,
      idle_threshold_s: Math.round(Number($('#set-idle').value) * 60),
      upload_interval_s: Number($('#set-upload').value),
      close_blocked_tabs: $('#set-close-tabs').checked,
      notify_user: $('#set-notify').checked,
      browser_policy: $('#set-browser-policy').checked,
      auto_update: $('#set-auto-update').checked,
      retention_days: Number($('#set-retention').value),
      tz_offset_min: Number($('#set-tz').value),
    } });
    state.loadedSettings = false;
    await loadSettings();
    setMsg(msg, `Saved for ${orgName()}. Its computers pick the change up at their next check-in.`);
  });
});

/**
 * Starts the download of an organisation's installer (or, when the server has
 * no agent program, of its settings file). A plain link, so the browser
 * streams the file straight to disk.
 */
function downloadInstaller(orgId, what = 'agent-installer') {
  const a = document.createElement('a');
  a.href = `/api/download/${what}?org=${encodeURIComponent(orgId)}&server=${encodeURIComponent(location.origin)}`;
  document.body.appendChild(a);
  a.click();
  a.remove();
}

$('#clear-activity').addEventListener('click', () => {
  if (!window.confirm(`Delete ALL recorded website and application activity for ${orgName()} now?\n\nBlocked sites, blacklist words, categories and computers are kept. This cannot be undone.`)) return;
  guarded($('#settings-msg'), async () => {
    const res = await api('/activity', { method: 'DELETE' });
    setMsg($('#settings-msg'), `Cleared. ${res.removed.toLocaleString()} activity record(s) were deleted.`);
  });
});

$('#download-installer').addEventListener('click', () => downloadInstaller(state.org));
$('#download-setup-file').addEventListener('click', () => downloadInstaller(state.org, 'agent-setup'));

$('#api-key-create').addEventListener('click', () => guarded(null, async () => {
  const res = await api('/settings/api-key', { method: 'POST' });
  const box = $('#api-key-value');
  box.textContent = res.api_key;
  box.hidden = false;
  await loadSettings();
  $('#api-key-state').textContent = 'Copy this key now. It is not shown again.';
}));

$('#api-key-revoke').addEventListener('click', () => guarded(null, async () => {
  await api('/settings/api-key', { method: 'DELETE' });
  $('#api-key-value').hidden = true;
  await loadSettings();
}));

$('#password-form').addEventListener('submit', (e) => {
  e.preventDefault();
  const msg = $('#password-msg');
  guarded(msg, async () => {
    await api('/password', { method: 'POST', body: { current: $('#pw-current').value, new: $('#pw-new').value } });
    $('#pw-current').value = '';
    $('#pw-new').value = '';
    setMsg(msg, 'Password changed. Other sessions were signed out.');
  });
});

// ---------------------------------------------------------------------------
// System info (Overview card) and installed programs
// ---------------------------------------------------------------------------

function fmtUptime(sec) {
  sec = Math.max(0, Number(sec) || 0);
  const d = Math.floor(sec / 86400), h = Math.floor((sec % 86400) / 3600), m = Math.floor((sec % 3600) / 60);
  if (d) return `${d}d ${h}h`;
  if (h) return `${h}h ${m}m`;
  return `${m}m`;
}

/** "YYYYMMDD" → "YYYY-MM-DD"; anything else is returned unchanged. */
function prettyDate(s) {
  const m = /^(\d{4})(\d{2})(\d{2})$/.exec(String(s || ''));
  return m ? `${m[1]}-${m[2]}-${m[3]}` : (s || '');
}

/** How long ago a "YYYY-MM-DD[ HH:MM:SS]" date was, in words. */
function daysAgo(dateStr) {
  const t = Date.parse(String(dateStr || '').replace(' ', 'T'));
  if (isNaN(t)) return '';
  const days = Math.floor((Date.now() - t) / 86400000);
  return days <= 0 ? 'today' : days === 1 ? 'yesterday' : days < 45 ? `${days} days ago` : `${Math.round(days / 30)} months ago`;
}

async function loadSystem() {
  const uuid = $('#machine').value;
  const d = await api('/system' + (uuid ? '?machine_uuid=' + encodeURIComponent(uuid) : ''));
  renderSystem(d, uuid);
}

function renderSystem(d, uuid) {
  const card = $('#system-card');
  card.hidden = false;
  if (!uuid) {
    const f = d.fleet || { machines: 0, reported: 0, reboot_pending: 0 };
    const pend = f.reboot_pending
      ? `<b>${f.reboot_pending}</b> computer${f.reboot_pending === 1 ? '' : 's'} need a restart to finish a Windows update.`
      : 'None are waiting for a restart to finish an update.';
    card.innerHTML = `<h3>System</h3><p class="hint">${f.reported} of ${f.machines} computer${f.machines === 1 ? '' : 's'} have reported system details. ${pend} Pick a computer in the filter above to see its full system info and installed programs.</p>`;
    return;
  }
  const m = d.machine;
  if (!m || !m.system) {
    card.innerHTML = '<h3>System</h3><p class="hint">No system details reported yet for this computer. They arrive at a check-in, usually within a few minutes of installing the agent.</p>';
    return;
  }
  const s = m.system;
  const mm = state.machines.find((x) => x.machine_uuid === uuid) || { machine_uuid: uuid };
  const updates = s.reboot_pending
    ? '<span class="chip warn">Restart needed to finish an update</span>'
    : '<span class="chip">No restart pending</span>';
  const dateCell = (v) => (v ? `${esc(v)} <span class="muted">(${daysAgo(v)})</span>` : '—');
  const rows = [
    ['Windows', esc(s.os || '—')],
    ['Windows installed', s.os_installed ? dateCell(s.os_installed) : '—'],
    ['Last update recorded', s.last_update ? dateCell(s.last_update) : '<span class="muted">not reported</span>'],
    ['Update status', updates],
    ['Processor', esc(s.cpu || '—')],
    ['Memory', s.ram_mb ? `${(s.ram_mb / 1024).toFixed(1)} GB` : '—'],
    ['Disk (system drive)', s.disk_total_gb ? `${s.disk_free_gb} GB free of ${s.disk_total_gb} GB` : '—'],
    ['Uptime', fmtUptime(s.uptime_s)],
    ['Make / model', [s.manufacturer, s.model].filter(Boolean).map(esc).join(' ') || '—'],
    ['Connection', esc(s.net_type || '—') + (s.mac ? ` <span class="muted">${esc(s.mac)}</span>` : '')],
    ['Local IP', esc(s.local_ip || '—')],
    ['Public IP', esc(s.public_ip || '—')],
    ['Printers', s.printers && s.printers.length ? esc(s.printers.join(', ')) : 'none'],
    ['Installed programs', `${m.app_count} <button class="small" id="view-apps">View all</button>`],
  ];
  card.innerHTML = `<div class="head"><h3>System — ${esc(machineName(mm))}</h3><span class="muted">updated ${esc(fmtAgo(m.updated_at))} <button class="small" id="view-logs">View logs</button></span></div>
    <dl class="kv">${rows.map(([k, v]) => `<dt>${esc(k)}</dt><dd>${v}</dd>`).join('')}</dl>`;
  const view = $('#view-apps');
  if (view) view.addEventListener('click', () => openAppsDialog(uuid));
  const logs = $('#view-logs');
  if (logs) logs.addEventListener('click', () => openLogsDialog(uuid));
}

async function openLogsDialog(uuid) {
  const name = machineName(state.machines.find((m) => m.machine_uuid === uuid) || { machine_uuid: uuid });
  $('#logs-heading').textContent = `Agent log — ${name}`;
  $('#logs-body').textContent = 'Loading…';
  $('#logs-meta').textContent = '';
  $('#logs-dialog').showModal();
  guarded(null, async () => {
    const d = await api(`/machines/${encodeURIComponent(uuid)}/logs`);
    const lines = d.lines || [];
    $('#logs-body').textContent = lines.length ? lines.join('\n') : 'No log lines reported yet. They arrive with the daily system snapshot.';
    $('#logs-meta').textContent = d.updated_at ? `updated ${fmtAgo(d.updated_at)}` : '';
    const b = $('#logs-body');
    b.scrollTop = b.scrollHeight;
  });
}

$('#logs-close').addEventListener('click', () => $('#logs-dialog').close());

let installedApps = [];

function renderInstalledApps() {
  const q = $('#apps-search').value.trim().toLowerCase();
  const rows = installedApps.filter((a) => !q || `${a.name} ${a.publisher || ''}`.toLowerCase().includes(q));
  $('#apps-list-body').innerHTML = rows.map((a) => `
    <tr>
      <td>${esc(a.name)}</td>
      <td>${esc(a.version || '')}</td>
      <td>${esc(a.publisher || '')}</td>
      <td class="when">${esc(prettyDate(a.installed_on))}</td>
    </tr>`).join('') || emptyRow(4, installedApps.length ? 'No program matches the search.' : 'No programs reported yet for this computer.');
}

async function loadInstalledApps(uuid) {
  $('#apps-list-body').innerHTML = emptyRow(4, 'Loading…');
  $('#apps-meta').textContent = '';
  const d = await api(`/machines/${encodeURIComponent(uuid)}/apps`);
  installedApps = d.apps || [];
  $('#apps-meta').textContent = d.count ? `${d.count} program(s) · updated ${fmtAgo(d.updated_at)}` : '';
  renderInstalledApps();
}

async function openAppsDialog(uuid) {
  if (!state.machines.length) await loadMachines();
  const sel = uuid || $('#machine').value || (state.machines[0] && state.machines[0].machine_uuid);
  if (!sel) { banner('Add a computer first — download the installer under Settings.'); return; }
  $('#apps-machine').innerHTML = state.machines.map((m) => `<option value="${esc(m.machine_uuid)}" ${m.machine_uuid === sel ? 'selected' : ''}>${esc(machineName(m))}</option>`).join('');
  $('#apps-search').value = '';
  installedApps = [];
  $('#apps-dialog').showModal();
  guarded(null, () => loadInstalledApps(sel));
}

$('#installed-apps-btn').addEventListener('click', () => guarded(null, () => openAppsDialog()));
$('#apps-machine').addEventListener('change', (e) => guarded(null, () => loadInstalledApps(e.target.value)));
$('#apps-search').addEventListener('input', renderInstalledApps);
$('#apps-close').addEventListener('click', () => $('#apps-dialog').close());

// ---------------------------------------------------------------------------
// Navigation and loading
// ---------------------------------------------------------------------------

const PAGES = {
  overview: { title: 'Overview', filters: true, load: () => Promise.all([loadMachines(), loadOverview(), loadSystem()]) },
  visits: { title: 'Websites', filters: true, load: async () => { await Promise.all([loadMachines(), loadBlocked()]); await loadVisits(); } },
  apps: { title: 'Applications', filters: true, load: () => Promise.all([loadMachines(), loadApps()]) },
  blocking: { title: 'Site blocking', filters: true, load: async () => { await loadMachines(); await Promise.all([loadBlocked(), loadAttempts()]); } },
  words: { title: 'Blacklist words', filters: true, load: () => Promise.all([loadMachines(), loadWords()]) },
  categories: { title: 'Categories', filters: false, load: loadCategories },
  machines: { title: 'Computers', filters: false, load: loadMachines },
  settings: { title: 'Settings', filters: false, load: loadSettings },
  // The pages that are not about a single organisation.
  orgs: { title: 'Organisations', filters: false, all: true, load: loadOrgs },
  users: { title: 'Users', filters: false, all: true, load: loadUsers },
};

let loading = 0;

async function reload() {
  const page = PAGES[state.page];
  const ticket = ++loading;
  $('#refresh').disabled = true;
  try {
    await page.load();
    if (ticket === loading) banner('');
  } catch (err) {
    if (err.message !== 'Signed out.' && ticket === loading) banner(err.message);
  } finally {
    if (ticket === loading) $('#refresh').disabled = false;
  }
}

function go(page) {
  if (!PAGES[page]) page = 'overview';
  // Owner-only pages are off limits to members.
  if ((page === 'orgs' || page === 'users') && !isOwner()) page = 'overview';
  if (page === 'settings' && !(isOwner() || can('settings'))) page = 'overview';
  // Nothing to show until there is an organisation: start by creating one.
  if (state.org == null) page = isOwner() ? 'orgs' : 'overview';
  state.page = page;
  $$('#nav button').forEach((b) => b.classList.toggle('active', b.dataset.page === page));
  $$('.page').forEach((p) => p.classList.toggle('active', p.id === 'page-' + page));
  $('#page-title').textContent = PAGES[page].title;
  showPageOrg();
  updatePermUI();
  $('#global-filters').hidden = !PAGES[page].filters;
  if (location.hash !== '#' + page) history.replaceState(null, '', '#' + page);
  reload();
}

$('#nav').addEventListener('click', (e) => {
  const b = e.target.closest('button[data-page]');
  if (b) go(b.dataset.page);
});

// Deep links and the browser's back/forward buttons.
window.addEventListener('hashchange', () => {
  const page = location.hash.slice(1);
  if (!$('#app').hidden && page !== state.page) go(page);
});

$('#range').addEventListener('click', (e) => {
  const b = e.target.closest('button[data-range]');
  if (!b) return;
  state.range = b.dataset.range;
  $$('#range button').forEach((x) => x.classList.toggle('active', x === b));
  $('#custom-range').hidden = state.range !== 'custom';
  if (state.range === 'custom' && !$('#from').value) {
    $('#from').value = isoDay(startOfDay(-6));
    $('#to').value = isoDay(new Date());
  }
  reload();
});

$('#visit-category').addEventListener('click', (e) => {
  const b = e.target.closest('button[data-category]');
  if (!b) return;
  state.visitCategory = b.dataset.category;
  $$('#visit-category button').forEach((x) => x.classList.toggle('active', x === b));
  guarded(null, loadVisits);
});

for (const id of ['#from', '#to', '#machine']) $(id).addEventListener('change', reload);
$('#refresh').addEventListener('click', reload);

function debounce(fn, ms) {
  let t;
  return () => { clearTimeout(t); t = setTimeout(fn, ms); };
}
$('#visit-domain').addEventListener('input', debounce(() => guarded(null, loadVisits), 300));
$('#app-filter').addEventListener('input', debounce(() => guarded(null, loadApps), 300));

// The overview and the computer list refresh themselves once a minute, and
// only while the tab is actually being looked at.
setInterval(() => {
  // The Organisations page too, so a roll-out can be watched; but never while a name is being typed there.
  const typing = document.activeElement && document.activeElement.matches('.org-edit, #org-name, #agent-password');
  const watching = state.page === 'overview' || state.page === 'machines' || (state.page === 'orgs' && !typing);
  if (document.visibilityState === 'visible' && !$('#app').hidden && watching && !$('#titles-dialog').open && !$('#org-remove-dialog').open && !$('#apps-dialog').open && !$('#power-dialog').open && !$('#logs-dialog').open && !$('#access-dialog').open && !$('#userpw-dialog').open) reload();
}, 60000);

// ---------------------------------------------------------------------------
// Sign-in
// ---------------------------------------------------------------------------

function showLogin() {
  $('#app').hidden = true;
  $('#login').hidden = false;
  $('#login-user').focus();
}

async function showApp() {
  const me = await api('/me');
  state.me = me;
  $('#login').hidden = true;
  $('#app').hidden = false;
  $('#who').textContent = me.username + (me.role === 'owner' ? '' : ' (member)');
  applyRole();
  try {
    await loadOrgs();
  } catch (err) {
    if (err.message !== 'Signed out.') banner(err.message);
  }
  go(location.hash.slice(1) || 'overview');
}

$('#login-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const err = $('#login-error');
  err.hidden = true;
  try {
    const res = await api('/login', { method: 'POST', body: { username: $('#login-user').value, password: $('#login-pass').value } });
    $('#login-pass').value = '';
    await showApp();
  } catch (ex) {
    err.textContent = ex.message;
    err.hidden = false;
  }
});

$('#logout').addEventListener('click', async () => {
  try { await api('/logout', { method: 'POST' }); } catch { /* signing out regardless */ }
  showLogin();
});

(async function start() {
  try {
    await showApp();
  } catch {
    showLogin();
  }
})();
