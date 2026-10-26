'use strict';

/**
 * Heuristic SQL injection and XSS detection.
 *
 * IMPORTANT: this is pattern matching. It produces false positives and false
 * negatives and must never be treated as a complete defence. Applications still
 * need parameterized queries, output encoding, authN/authZ and input validation.
 */

const SEVERITY_RANK = { low: 1, medium: 2, high: 3 };

const RULES = [
  // ---- SQL injection -------------------------------------------------------
  {
    id: 'sqli-union-select',
    category: 'sql_injection',
    severity: 'high',
    explanation: 'UNION SELECT pattern commonly used to extract data from other tables',
    re: /\bunion\b(\s+all)?\s+select\b/,
  },
  {
    id: 'sqli-tautology-quoted',
    category: 'sql_injection',
    severity: 'high',
    explanation: 'Quote followed by OR/AND and an equality comparison (always-true condition)',
    re: /['"`)]\s*(or|and)\s+['"`(]?\w+['"`)]?\s*(=|<|>|like\b)/,
  },
  {
    id: 'sqli-tautology-numeric',
    category: 'sql_injection',
    severity: 'medium',
    explanation: 'OR/AND with a self-equal numeric or string comparison (for example 1=1)',
    re: /\b(or|and)\s+(\d+)\s*=\s*\2\b|\b(or|and)\s+(['"])(\w*)\4\s*=\s*\4\5\4/,
  },
  {
    id: 'sqli-stacked-query',
    category: 'sql_injection',
    severity: 'high',
    explanation: 'Statement separator followed by a data-modifying or administrative SQL keyword',
    re: /;\s*(drop|delete|insert|update|alter|create|truncate|exec|execute|grant)\b/,
  },
  {
    id: 'sqli-comment-terminator',
    category: 'sql_injection',
    severity: 'medium',
    explanation: 'Quote followed by a SQL comment marker used to truncate the rest of a query',
    re: /['"`]\s*(--|#|\/\*)/,
  },
  {
    id: 'sqli-time-based',
    category: 'sql_injection',
    severity: 'high',
    explanation: 'Time-delay function used in blind SQL injection',
    re: /\b(sleep\s*\(\s*\d+|pg_sleep\s*\(|waitfor\s+delay|benchmark\s*\(\s*\d+)/,
  },
  {
    id: 'sqli-schema-probe',
    category: 'sql_injection',
    severity: 'medium',
    explanation: 'Reference to database metadata tables used for schema discovery',
    re: /\b(information_schema|sqlite_master|pg_catalog|sysobjects|sys\.tables)\b/,
  },
  {
    id: 'sqli-dangerous-function',
    category: 'sql_injection',
    severity: 'high',
    explanation: 'Database function that reads files or runs OS commands',
    re: /\b(load_file\s*\(|into\s+(out|dump)file|xp_cmdshell)\b/,
  },

  // ---- Cross-Site Scripting ------------------------------------------------
  {
    id: 'xss-script-tag',
    category: 'xss',
    severity: 'high',
    explanation: 'HTML script tag in request data',
    re: /<\s*\/?\s*script\b/,
  },
  {
    id: 'xss-event-handler',
    category: 'xss',
    severity: 'high',
    explanation: 'HTML tag carrying an inline event handler attribute (onerror=, onload=, ...)',
    re: /<[^>]{0,200}?[\s"'\/]on[a-z]{3,20}\s*=/,
  },
  {
    id: 'xss-javascript-uri',
    category: 'xss',
    severity: 'high',
    explanation: 'javascript: or data:text/html URI scheme',
    re: /\bjavascript\s*:|\bdata\s*:\s*text\/html|\bvbscript\s*:/,
  },
  {
    id: 'xss-embedding-tag',
    category: 'xss',
    severity: 'medium',
    explanation: 'Embedding tag (iframe, object, embed, svg, math) that can load active content',
    re: /<\s*(iframe|object|embed|svg|math|base|meta)[\s\/>]/,
  },
  {
    id: 'xss-dom-sink',
    category: 'xss',
    severity: 'low',
    explanation: 'Reference to a DOM API commonly abused after injection (document.cookie, eval, innerHTML)',
    re: /\b(document\s*\.\s*(cookie|write|domain)|window\s*\.\s*location|eval\s*\(|innerhtml\s*=)/,
  },
];

const LIMITS = {
  maxDecodePasses: 3,
  maxStringLength: 20000, // characters inspected per string value
  maxNodes: 5000, // object nodes walked per request
  maxDepth: 12,
};

const INSPECTED_HEADERS = ['user-agent', 'referer', 'origin', 'x-forwarded-host'];

function safeDecode(value) {
  let out = value;
  for (let i = 0; i < LIMITS.maxDecodePasses; i += 1) {
    let next;
    try {
      next = decodeURIComponent(out.replace(/\+/g, ' '));
    } catch (_) {
      next = out;
    }
    next = next
      .replace(/&#x([0-9a-f]+);?/gi, (m, h) => safeFromCode(parseInt(h, 16), m))
      .replace(/&#(\d+);?/g, (m, d) => safeFromCode(parseInt(d, 10), m))
      .replace(/&lt;/gi, '<')
      .replace(/&gt;/gi, '>')
      .replace(/&quot;/gi, '"')
      .replace(/&apos;/gi, "'");
    if (next === out) break;
    out = next;
  }
  return out;
}

function safeFromCode(code, fallback) {
  if (!Number.isFinite(code) || code < 0 || code > 0x10ffff) return fallback;
  try {
    return String.fromCodePoint(code);
  } catch (_) {
    return fallback;
  }
}

/** Canonical form used for matching: decoded, lower-cased, comments/whitespace collapsed. */
function normalize(value) {
  let s = String(value).slice(0, LIMITS.maxStringLength);
  s = s.replace(/\u0000/g, '');
  s = safeDecode(s);
  s = s.replace(/\/\*[\s\S]*?\*\//g, ' '); // inline SQL comments used to split keywords
  s = s.replace(/[\t\r\n\f\v]+/g, ' ').replace(/ {2,}/g, ' ');
  return s.toLowerCase();
}

function matchString(value, location, findings) {
  if (typeof value !== 'string' || value.length === 0) return;
  const normalized = normalize(value);
  for (const rule of RULES) {
    if (rule.re.test(normalized)) {
      findings.push({
        ruleId: rule.id,
        category: rule.category,
        severity: rule.severity,
        explanation: rule.explanation,
        location,
      });
    }
  }
}

function walk(node, location, findings, state, depth = 0) {
  if (state.nodes >= LIMITS.maxNodes || depth > LIMITS.maxDepth) {
    state.truncated = true;
    return;
  }
  state.nodes += 1;
  if (node === null || node === undefined) return;
  if (typeof node === 'string') {
    matchString(node, location, findings);
  } else if (Array.isArray(node)) {
    node.forEach((item, i) => walk(item, `${location}[${i}]`, findings, state, depth + 1));
  } else if (typeof node === 'object') {
    for (const [key, val] of Object.entries(node)) {
      matchString(key, `${location}.<key>`, findings);
      walk(val, `${location}.${key.slice(0, 40)}`, findings, state, depth + 1);
    }
  }
}

/**
 * @param {{path?:string, query?:object|string, headers?:object, body?:any}} req
 * @returns {{findings:Array, truncated:boolean}}
 */
function inspect(req) {
  const findings = [];
  const state = { nodes: 0, truncated: false };

  matchString(req.path, 'path', findings);

  if (typeof req.query === 'string') matchString(req.query, 'query', findings);
  else if (req.query && typeof req.query === 'object') walk(req.query, 'query', findings, state);

  const headers = req.headers || {};
  for (const name of INSPECTED_HEADERS) {
    if (typeof headers[name] === 'string') matchString(headers[name], `header:${name}`, findings);
  }

  if (req.body !== undefined && req.body !== null) walk(req.body, 'body', findings, state);

  // De-duplicate identical rule+location pairs.
  const seen = new Set();
  const unique = findings.filter((f) => {
    const k = `${f.ruleId}|${f.location}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
  return { findings: unique, truncated: state.truncated };
}

function highestSeverity(findings) {
  let best = null;
  for (const f of findings) {
    if (!best || SEVERITY_RANK[f.severity] > SEVERITY_RANK[best]) best = f.severity;
  }
  return best;
}

/** True when any finding meets or exceeds the threshold severity. */
function meetsThreshold(findings, threshold) {
  const min = SEVERITY_RANK[threshold] || SEVERITY_RANK.medium;
  return findings.some((f) => SEVERITY_RANK[f.severity] >= min);
}

module.exports = { inspect, normalize, highestSeverity, meetsThreshold, RULES, SEVERITY_RANK, LIMITS };
