'use strict';
(function () {
  const $ = (id) => document.getElementById(id);
  const state = { apis: [], range: '24h', apiId: '', nextBefore: null, events: [], selectedApi: null };
  const SVG_NS = 'http://www.w3.org/2000/svg';

  function showError(err) {
    const box = $('page-error');
    box.textContent = err ? err.message : '';
    box.classList.toggle('hidden', !err);
  }
  const q = () => `range=${encodeURIComponent(state.range)}${state.apiId ? `&apiId=${encodeURIComponent(state.apiId)}` : ''}`;
  const num = (n) => Number(n || 0).toLocaleString();

  /* ---------- summary ---------- */
  function renderStats(t) {
    $('s-inspected').textContent = num(t.inspected);
    $('s-allowed').textContent = num(t.allowed);
    $('s-blocked').textContent = num(t.blocked);
    $('s-suspicious').textContent = num(t.suspicious);
    $('s-errors').textContent = num(t.errors);
  }

  function renderHBars(target, rows, colorClass, emptyText) {
    clear(target);
    const total = rows.reduce((s, r) => s + r.count, 0);
    if (!total) { target.append(h('div', { class: 'empty' }, emptyText)); return; }
    for (const r of rows) {
      target.append(h('div', { class: 'hbar' }, h('span', null, r.label), h('div', { class: 'track' }, (() => {
        const f = h('div', { class: `fill ${r.cls || colorClass}` });
        f.setAttribute('data-pct', String(Math.round((r.count / total) * 100)));
        f.style.width = `${(r.count / total) * 100}%`; // CSSOM assignment is permitted under CSP
        return f;
      })()), h('span', null, num(r.count))));
    }
  }

  function renderAllowedBlocked(t) {
    const rows = [
      { label: 'Allowed', count: t.allowed, cls: 'i-ok' },
      { label: 'Blocked', count: t.blocked, cls: 'i-blk' },
    ];
    renderHBars($('chart-ab'), rows, 'i-ok', 'No inspected requests in this range yet.');
  }

  function renderCategories(rows) {
    const label = { sql_injection: 'SQL injection', xss: 'Cross-site scripting' };
    renderHBars($('chart-cat'), rows.map((r) => ({ label: label[r.category] || r.category, count: r.count, cls: 'i-sus' })), 'i-sus', 'No security events in this range.');
  }

  /* ---------- time series (inline SVG, no library) ---------- */
  function svg(tag, attrs) {
    const el = document.createElementNS(SVG_NS, tag);
    for (const [k, v] of Object.entries(attrs || {})) el.setAttribute(k, String(v));
    return el;
  }
  function renderTimeSeries(data) {
    const target = $('chart-time');
    clear(target);
    const pts = data.points;
    const max = Math.max(1, ...pts.map((p) => p.inspected));
    if (!pts.some((p) => p.inspected > 0)) { target.append(h('div', { class: 'empty' }, 'No traffic recorded in this range yet.')); return; }
    const W = 640; const H = 210; const padL = 36; const padB = 24; const padT = 8;
    const innerW = W - padL - 6; const innerH = H - padB - padT;
    const slot = innerW / pts.length; const bw = Math.max(2, slot * 0.8);
    const root = svg('svg', { viewBox: `0 0 ${W} ${H}`, role: 'img', 'aria-label': 'Requests over time' });
    root.append(svg('line', { class: 'axis', x1: padL, y1: padT + innerH, x2: W - 6, y2: padT + innerH }));
    const yl = svg('text', { x: padL - 6, y: padT + 9, 'text-anchor': 'end' }); yl.textContent = num(max); root.append(yl);
    const y0 = svg('text', { x: padL - 6, y: padT + innerH, 'text-anchor': 'end' }); y0.textContent = '0'; root.append(y0);
    pts.forEach((p, i) => {
      const x = padL + i * slot + (slot - bw) / 2;
      const bar = (v, cls, frac) => {
        if (!v) return;
        const hh = (v / max) * innerH; const w = bw * frac;
        const r = svg('rect', { class: cls, x: x + (bw - w) / 2, y: padT + innerH - hh, width: w, height: hh });
        const t = svg('title'); t.textContent = `${new Date(p.t).toLocaleString()}: ${p.inspected} inspected, ${p.suspicious} suspicious, ${p.blocked} blocked`;
        r.append(t); root.append(r);
      };
      bar(p.inspected, 'bar-all', 1); bar(p.suspicious, 'bar-sus', 0.6); bar(p.blocked, 'bar-blk', 0.3);
    });
    const fmt = (t) => new Date(t).toLocaleString([], data.bucketMs >= 864e5 ? { month: 'short', day: 'numeric' } : { month: 'short', day: 'numeric', hour: '2-digit' });
    [[0, 'start'], [Math.floor(pts.length / 2), 'middle'], [pts.length - 1, 'end']].forEach(([i, anchor]) => {
      const lab = svg('text', { x: padL + i * slot + slot / 2, y: H - 6, 'text-anchor': anchor }); lab.textContent = fmt(pts[i].t); root.append(lab);
    });
    target.append(root);
  }

  /* ---------- APIs ---------- */
  function renderApis(apis) {
    const target = $('apis');
    clear(target);
    if (!apis.length) { target.append(h('div', { class: 'empty' }, 'No APIs registered yet. Choose “Add API” to register your first one.')); return; }
    target.append(h('table', null,
      h('thead', null, h('tr', null, ['Name', 'Environment', 'Mode', 'Connection', 'Upstream health', 'Last request', 'Inspected', 'Blocked', ''].map((c) => h('th', null, c)))),
      h('tbody', null, apis.map((a) => h('tr', null,
        h('td', null, a.name), h('td', null, a.environment), h('td', null, badge(a.mode, a.mode === 'blocking' ? 'blocked' : 'logged')),
        h('td', null, badge(a.connectionStatus)), h('td', null, badge(a.health)), h('td', null, fmtTime(a.lastSeenAt)),
        h('td', null, num(a.totals.inspected)), h('td', null, num(a.totals.blocked)),
        h('td', null, h('button', { class: 'btn secondary small', type: 'button', onclick: () => openApi(a) }, 'Manage')))))));
    const sel = $('api-filter'); const current = state.apiId;
    clear(sel); sel.append(h('option', { value: '' }, 'All APIs'));
    apis.forEach((a) => sel.append(h('option', { value: a.id }, a.name)));
    sel.value = apis.some((a) => a.id === current) ? current : '';
    state.apiId = sel.value;
  }

  function secretBox(apiObj, key, title) {
    const box = $('secret-box');
    clear(box);
    const base = location.origin + apiObj.gatewayPath;
    box.append(h('div', { class: 'panel' },
      h('h2', null, title),
      h('div', { class: 'secret' }, h('strong', null, 'Copy this API key now. It is shown only once and cannot be retrieved later.'), h('pre', null, key)),
      h('p', null, 'Send traffic through the gateway instead of directly to your backend, with this key in the X-Guard-Key header:'),
      h('pre', null, `curl "${base}/your/endpoint?param=value" \\\n  -H "X-Guard-Key: ${key}"`),
      h('p', { class: 'hint' }, 'Your API is protected only while requests actually go through this address. Until the first request arrives, the connection status stays “awaiting traffic”. Keep the key on your server; never put it in browser code.'),
      h('button', { class: 'btn secondary small', type: 'button', onclick: () => box.classList.add('hidden') }, 'I have saved the key')));
    box.classList.remove('hidden');
    box.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  function openApi(a) {
    state.selectedApi = a;
    const box = $('api-detail'); clear(box); box.classList.remove('hidden');
    const base = location.origin + a.gatewayPath;
    const mode = h('select', { id: 'd-mode' }, h('option', { value: 'monitoring' }, 'Monitoring (record only)'), h('option', { value: 'blocking' }, 'Blocking (reject matches with 403)'));
    mode.value = a.mode;
    const thr = h('select', { id: 'd-thr' }, h('option', { value: 'low' }, 'Low and above'), h('option', { value: 'medium' }, 'Medium and above'), h('option', { value: 'high' }, 'High only'));
    thr.value = a.blockThreshold;
    const confirmBox = h('input', { type: 'checkbox', id: 'd-confirm' });
    const confirmRow = h('label', { class: 'checkrow hidden' }, confirmBox, h('span', null, 'I understand blocking mode rejects matching requests, including false positives, before they reach my backend.'));
    mode.addEventListener('change', () => confirmRow.classList.toggle('hidden', !(mode.value === 'blocking' && a.mode !== 'blocking')));
    const msg = h('div', { class: 'msg hidden', role: 'status' });
    const say = (text, cls) => { msg.textContent = text; msg.className = `msg ${cls}`; };
    box.append(
      h('div', { class: 'panel-head' }, h('h2', null, `Manage: ${a.name}`), h('button', { class: 'btn secondary small', type: 'button', onclick: () => { box.classList.add('hidden'); } }, 'Close')),
      h('dl', { class: 'kv' },
        h('dt', null, 'API ID'), h('dd', null, h('code', null, a.id)),
        h('dt', null, 'Gateway address'), h('dd', null, h('code', null, base)),
        h('dt', null, 'Backend'), h('dd', null, h('code', null, a.upstreamUrl)),
        h('dt', null, 'API key'), h('dd', null, h('code', null, `${a.keyPrefix}…`), ' (full key shown only when issued)'),
        h('dt', null, 'Connection'), h('dd', null, badge(a.connectionStatus), ' ', a.connectionStatus === 'awaiting_traffic' ? 'No request has come through the gateway yet, so this API is not yet protected.' : `Last request ${fmtTime(a.lastSeenAt)}`),
        h('dt', null, 'Upstream health'), h('dd', null, badge(a.health), ' based on the last 20 forwarded requests')),
      h('p', null, 'Test the connection:'),
      h('pre', null, `curl -i "${base}/your/endpoint" \\\n  -H "X-Guard-Key: <your API key>"`),
      h('div', { class: 'inline-form' }, h('div', null, h('label', { for: 'd-mode' }, 'Enforcement mode'), mode), h('div', null, h('label', { for: 'd-thr' }, 'Block threshold'), thr)),
      confirmRow, msg,
      h('div', { class: 'row-actions' },
        h('button', { class: 'btn small', type: 'button', onclick: async () => {
          try {
            await api('PATCH', `/api/apis/${a.id}`, { mode: mode.value, blockThreshold: thr.value, confirmBlocking: confirmBox.checked });
            say('Settings saved.', 'ok'); await loadAll();
          } catch (err) { say(err.message, 'error'); }
        } }, 'Save settings'),
        h('button', { class: 'btn secondary small', type: 'button', onclick: async () => {
          if (!confirm('Rotate the API key? The current key stops working immediately.')) return;
          try { const r = await api('POST', `/api/apis/${a.id}/rotate-key`); secretBox(r.api, r.apiKey, 'New API key'); await loadAll(); } catch (err) { say(err.message, 'error'); }
        } }, 'Rotate key'),
        h('button', { class: 'btn danger small', type: 'button', onclick: async () => {
          if (!confirm(`Delete “${a.name}” and all of its recorded events? This cannot be undone.`)) return;
          try { await api('DELETE', `/api/apis/${a.id}`); box.classList.add('hidden'); await loadAll(); } catch (err) { say(err.message, 'error'); }
        } }, 'Delete API')));
    box.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }

  /* ---------- events ---------- */
  function renderEvents(reset) {
    const target = $('events'); clear(target);
    $('more-events').classList.toggle('hidden', !state.nextBefore);
    if (!state.events.length) {
      target.append(h('div', { class: 'empty' }, state.apis.length ? 'No security events recorded yet. Events appear when a request through the gateway matches a detection rule.' : 'Register and connect an API to start recording events.'));
      return;
    }
    target.append(h('table', null,
      h('thead', null, h('tr', null, ['Time', 'API', 'Category', 'Severity', 'Rule', 'Action', 'Status'].map((c) => h('th', null, c)))),
      h('tbody', null, state.events.map((e) => h('tr', { class: 'clickable', tabindex: '0', onclick: () => openEvent(e.id), onkeydown: (ev) => { if (ev.key === 'Enter') openEvent(e.id); } },
        h('td', null, fmtTime(e.ts)), h('td', null, e.apiName), h('td', null, e.category.replace('_', ' ')), h('td', null, badge(e.severity)),
        h('td', null, h('code', null, e.ruleId)), h('td', null, badge(e.action)), h('td', null, e.responseStatus))))));
  }

  async function loadEvents(append) {
    const params = new URLSearchParams({ limit: '15' });
    if (state.apiId) params.set('apiId', state.apiId);
    if (append && state.nextBefore) params.set('before', String(state.nextBefore));
    const r = await api('GET', `/api/events?${params}`);
    state.events = append ? state.events.concat(r.events) : r.events;
    state.nextBefore = r.nextBefore;
    renderEvents();
  }

  async function openEvent(id) {
    const box = $('event-detail'); clear(box); box.classList.remove('hidden');
    try {
      const { event: e } = await api('GET', `/api/events/${encodeURIComponent(id)}`);
      const outcomeText = { blocked: 'Blocked. The gateway rejected the request before it reached your backend.', logged: 'Allowed and logged. The request was forwarded to your backend.' }[e.action] || e.action;
      box.append(
        h('div', { class: 'panel-head' }, h('h2', null, 'Event details'), h('button', { class: 'btn secondary small', type: 'button', onclick: () => box.classList.add('hidden') }, 'Close')),
        h('dl', { class: 'kv' },
          h('dt', null, 'Time'), h('dd', null, fmtTime(e.ts)),
          h('dt', null, 'Request ID'), h('dd', null, h('code', null, e.requestId)),
          h('dt', null, 'API'), h('dd', null, `${e.apiName} (${e.environment})`),
          h('dt', null, 'Category'), h('dd', null, e.category.replace('_', ' ')),
          h('dt', null, 'Severity'), h('dd', null, badge(e.severity)),
          h('dt', null, 'Rule'), h('dd', null, h('code', null, e.ruleId)),
          h('dt', null, 'Why it matched'), h('dd', null, e.explanation),
          h('dt', null, 'Where'), h('dd', null, h('code', null, e.location)),
          h('dt', null, 'Request'), h('dd', null, h('code', null, `${e.method} ${e.path}`)),
          h('dt', null, 'Enforcement mode'), h('dd', null, e.mode),
          h('dt', null, 'Result'), h('dd', null, outcomeText),
          h('dt', null, 'Response status'), h('dd', null, e.responseStatus),
          h('dt', null, 'Processing time'), h('dd', null, `${e.durationMs} ms`)),
        h('p', { class: 'hint' }, 'Request bodies, headers and credentials are not stored. Detection is heuristic and this match may be a false positive.'));
    } catch (err) { box.append(h('div', { class: 'msg error' }, err.message)); }
    box.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }

  /* ---------- load ---------- */
  async function loadAll() {
    showError(null);
    try {
      const [summary, series] = await Promise.all([api('GET', `/api/dashboard/summary?${q()}`), api('GET', `/api/dashboard/timeseries?${q()}`)]);
      state.apis = summary.apis;
      renderStats(summary.totals); renderAllowedBlocked(summary.totals); renderCategories(summary.byCategory);
      renderTimeSeries(series); renderApis(summary.apis);
      await loadEvents(false);
    } catch (err) { showError(err); }
  }

  /* ---------- wiring ---------- */
  $('range').addEventListener('change', (e) => { state.range = e.target.value; loadAll(); });
  $('api-filter').addEventListener('change', (e) => { state.apiId = e.target.value; loadAll(); });
  $('refresh').addEventListener('click', loadAll);
  $('more-events').addEventListener('click', () => loadEvents(true).catch(showError));
  $('add-api-btn').addEventListener('click', () => { $('add-api').classList.toggle('hidden'); });
  $('add-cancel').addEventListener('click', () => $('add-api').classList.add('hidden'));
  $('f-mode').addEventListener('change', (e) => $('confirm-row').classList.toggle('hidden', e.target.value !== 'blocking'));
  $('logout').addEventListener('click', async () => { try { await api('POST', '/api/auth/logout'); } finally { location.href = '/'; } });

  $('add-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const msg = $('add-msg'); msg.classList.add('hidden');
    try {
      const r = await api('POST', '/api/apis', {
        name: $('f-name').value, environment: $('f-env').value, upstreamUrl: $('f-url').value, mode: $('f-mode').value,
        blockThreshold: $('f-threshold').value, maxBodyKb: parseInt($('f-body').value, 10), confirmBlocking: $('f-confirm').checked,
      });
      $('add-form').reset(); $('confirm-row').classList.add('hidden'); $('add-api').classList.add('hidden');
      secretBox(r.api, r.apiKey, `API registered: ${r.api.name}`);
      await loadAll();
    } catch (err) { msg.textContent = err.message; msg.classList.remove('hidden'); }
  });

  api('GET', '/api/auth/me').then((r) => { $('who').textContent = r.user.email; return loadAll(); }).catch(() => { location.href = '/login'; });
})();
