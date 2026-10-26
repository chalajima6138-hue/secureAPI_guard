'use strict';
/* Shared helpers. All dynamic text is inserted with textContent; never innerHTML. */
async function api(method, path, body) {
  const res = await fetch(path, {
    method,
    headers: body !== undefined ? { 'Content-Type': 'application/json' } : {},
    body: body !== undefined ? JSON.stringify(body) : undefined,
    credentials: 'same-origin',
  });
  let data = null;
  try { data = await res.json(); } catch (_) { /* empty or non-JSON body */ }
  if (res.status === 401 && !location.pathname.match(/^\/(login|register)/) && path !== '/api/auth/me') {
    location.href = '/login';
  }
  if (!res.ok) {
    const err = new Error((data && data.message) || `Request failed (${res.status})`);
    err.status = res.status;
    throw err;
  }
  return data;
}

function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k === 'class') el.className = v;
    else if (k.startsWith('on') && typeof v === 'function') el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v === true ? '' : v);
  }
  for (const child of children.flat()) {
    if (child === null || child === undefined || child === false) continue;
    el.append(child.nodeType ? child : document.createTextNode(String(child)));
  }
  return el;
}

function fmtTime(ts) { return ts ? new Date(ts).toLocaleString() : 'never'; }
function badge(text, cls) { return h('span', { class: `badge ${cls || text}` }, String(text).replace(/_/g, ' ')); }
function clear(el) { while (el.firstChild) el.removeChild(el.firstChild); }
