'use strict';
const dns = require('node:dns');
const net = require('node:net');

const BLOCKED_HOSTNAMES = new Set(['localhost', 'metadata.google.internal', 'metadata', 'instance-data']);

function ipv4ToInt(ip) {
  return ip.split('.').reduce((acc, o) => (acc << 8) + parseInt(o, 10), 0) >>> 0;
}

const V4_BLOCKS = [
  ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8], ['169.254.0.0', 16],
  ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.0.2.0', 24], ['192.168.0.0', 16], ['198.18.0.0', 15],
  ['198.51.100.0', 24], ['203.0.113.0', 24], ['224.0.0.0', 4], ['240.0.0.0', 4],
].map(([base, bits]) => ({ base: ipv4ToInt(base), mask: bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0 }));

/** True when the address is loopback, private, link-local (incl. cloud metadata), multicast or reserved. */
function isPrivateAddress(ip) {
  if (net.isIPv4(ip)) {
    const n = ipv4ToInt(ip);
    return V4_BLOCKS.some((b) => (n & b.mask) >>> 0 === b.base);
  }
  if (net.isIPv6(ip)) {
    const lower = ip.toLowerCase();
    const mapped = lower.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
    if (mapped) return isPrivateAddress(mapped[1]);
    const hexMapped = lower.match(/^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/);
    if (hexMapped) {
      const hi = parseInt(hexMapped[1], 16);
      const lo = parseInt(hexMapped[2], 16);
      return isPrivateAddress(`${hi >> 8}.${hi & 255}.${lo >> 8}.${lo & 255}`);
    }
    if (lower === '::' || lower === '::1') return true;
    if (/^f[cd]/.test(lower)) return true; // fc00::/7 unique local
    if (/^fe[89ab]/.test(lower)) return true; // fe80::/10 link-local
    if (/^ff/.test(lower)) return true; // multicast
    if (/^64:ff9b:/.test(lower)) return true; // NAT64
    if (/^2001:db8/.test(lower)) return true; // documentation
    return false;
  }
  return true; // not a valid IP: refuse
}

const ALWAYS_V4 = [['0.0.0.0', 8], ['169.254.0.0', 16], ['224.0.0.0', 4], ['240.0.0.0', 4]]
  .map(([base, bits]) => ({ base: ipv4ToInt(base), mask: (~0 << (32 - bits)) >>> 0 }));

/** Never reachable, even in development: link-local (cloud metadata), unspecified, multicast, reserved. */
function isAlwaysBlockedAddress(ip) {
  if (net.isIPv4(ip)) {
    const n = ipv4ToInt(ip);
    return ALWAYS_V4.some((b) => (n & b.mask) >>> 0 === b.base);
  }
  if (net.isIPv6(ip)) {
    const lower = ip.toLowerCase();
    const mapped = lower.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
    if (mapped) return isAlwaysBlockedAddress(mapped[1]);
    const hex = lower.match(/^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/);
    if (hex) {
      const hi = parseInt(hex[1], 16); const lo = parseInt(hex[2], 16);
      return isAlwaysBlockedAddress(`${hi >> 8}.${hi & 255}.${lo >> 8}.${lo & 255}`);
    }
    return lower === '::' || /^fe[89ab]/.test(lower) || /^ff/.test(lower);
  }
  return true;
}

/** Whether connecting to this address is prohibited under the given configuration. */
function isProhibitedAddress(ip, config) {
  return isAlwaysBlockedAddress(ip) || (!config.allowPrivateUpstreams && isPrivateAddress(ip));
}

/** Syntactic validation of a customer-supplied upstream. Returns {ok, url?, error?}. */
function parseUpstreamUrl(input, config) {
  if (typeof input !== 'string' || input.length > 2048) return { ok: false, error: 'Upstream URL is required.' };
  let url;
  try {
    url = new URL(input.trim());
  } catch (_) {
    return { ok: false, error: 'Upstream URL is not a valid URL.' };
  }
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && config.allowHttpUpstreams)) {
    return { ok: false, error: config.allowHttpUpstreams ? 'Upstream must use http or https.' : 'Upstream must use https.' };
  }
  if (url.username || url.password) return { ok: false, error: 'Credentials in the upstream URL are not allowed.' };
  if (url.hash) return { ok: false, error: 'Upstream URL must not contain a fragment.' };
  if (url.search) return { ok: false, error: 'Upstream URL must not contain a query string.' };
  const host = url.hostname.replace(/^\[|\]$/g, '').toLowerCase();
  if (host === 'metadata.google.internal' || host === 'metadata' || host === 'instance-data') {
    return { ok: false, error: 'This upstream host is not allowed.' };
  }
  if (!config.allowPrivateUpstreams && (BLOCKED_HOSTNAMES.has(host) || host.endsWith('.localhost') || host.endsWith('.internal') || host.endsWith('.local'))) {
    return { ok: false, error: 'This upstream host is not allowed.' };
  }
  if (net.isIP(host) && isProhibitedAddress(host, config)) return { ok: false, error: 'Private, loopback and link-local addresses are not allowed.' };
  const base = url.pathname.replace(/\/+$/, '');
  return { ok: true, url, normalized: `${url.protocol}//${url.host}${base}` };
}

/** DNS lookup that refuses private results. Used at registration time and as the socket-level lookup when connecting. */
function createSafeLookup(config) {
  return function safeLookup(hostname, options, callback) {
    const opts = typeof options === 'function' ? {} : options || {};
    const cb = typeof options === 'function' ? options : callback;
    dns.lookup(hostname, { ...opts, all: true }, (err, addresses) => {
      if (err) return cb(err);
      const bad = addresses.find((a) => isProhibitedAddress(a.address, config));
      if (bad) {
        const e = new Error('Upstream resolves to a prohibited address');
        e.code = 'ESSRF';
        return cb(e);
      }
      if (opts.all) return cb(null, addresses);
      return cb(null, addresses[0].address, addresses[0].family);
    });
  };
}

function resolveAndCheck(hostname, config) {
  return new Promise((resolve) => {
    const host = hostname.replace(/^\[|\]$/g, '');
    if (net.isIP(host)) return resolve(!isProhibitedAddress(host, config));
    return createSafeLookup(config)(host, { all: true }, (err) => resolve(!err));
  });
}

module.exports = { isPrivateAddress, isAlwaysBlockedAddress, isProhibitedAddress, parseUpstreamUrl, createSafeLookup, resolveAndCheck };
