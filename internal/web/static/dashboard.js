'use strict';
// Exalm dashboard — base44-style multi-page shell over the real backend
// (/api/dashboard). A left sidebar routes between client-rendered pages
// (Dashboard / Log Explorer / AI Analysis / Alerts / Settings); all pages reuse
// the same computeVals() + the shared window.Exalm API. No backend change — the
// namespace selector, fix/investigate panels, log viewer, charts, and
// auto-refresh all behave exactly as before, just reorganized.

(function () {
  var THEME_KEY = 'exalm.theme';
  var PAGE_KEY = 'exalm.page';
  var GROUP_ORDER = ['Other', 'Pods', 'Resources', 'Security', 'Services', 'Workloads'];
  var PAGES = ['dashboard', 'explorer', 'ai', 'alerts', 'settings'];
  // Explorer table sort. SEV_RANK gives severity a total order for numeric
  // comparison; SORT_DEFAULT_DIR picks a sensible first direction per column
  // (severity starts high-to-low, text columns start A-to-Z).
  var SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1, other: 0 };
  var SORT_DEFAULT_DIR = { sev: 'desc', ns: 'asc', title: 'asc', group: 'asc' };
  // Text inputs that should keep focus + caret position across a re-render
  // (render() rebuilds app.innerHTML from scratch on every state change).
  var REFOCUS_TEXT_IDS = ['finding-search', 'incident-title', 'incident-namespace', 'incident-service'];

  var THEMES = {
    dark: {
      '--bg': '#080c15', '--panel': '#152238', '--panel2': '#1d2c46', '--border': '#2a3a57',
      '--sidebar': '#0a1020', '--track': '#182740', '--code': '#070c15', '--codeFg': '#aabfd8', '--scroll': '#26374f',
      '--fg': '#eaf0f8', '--body': '#c6d2e2', '--muted': '#93a2be', '--faint': '#6b7a95',
      '--accent': '#28c0ea', '--accentGlow': 'rgba(40,192,234,.40)', '--accentSoft': 'rgba(40,192,234,.15)',
      '--crit': '#ff5d5d', '--high': '#ff9f45', '--med': '#f5c542', '--low': '#5b9bff', '--good': '#3ddc97',
      '--critSoft': 'rgba(255,93,93,.14)', '--critLine': 'rgba(255,93,93,.3)',
      '--highSoft': 'rgba(255,159,69,.14)', '--highLine': 'rgba(255,159,69,.28)',
      '--medSoft': 'rgba(245,197,66,.14)', '--medLine': 'rgba(245,197,66,.28)',
      '--lowSoft': 'rgba(91,155,255,.14)', '--lowLine': 'rgba(91,155,255,.28)'
    },
    light: {
      '--bg': '#eef2f8', '--panel': '#ffffff', '--panel2': '#f4f8fc', '--border': '#dfe6ef',
      '--sidebar': '#0e1626', '--track': '#eaf0f7', '--code': '#0b1220', '--codeFg': '#aebccf', '--scroll': '#cbd5e1',
      '--fg': '#0f1d33', '--body': '#39475e', '--muted': '#5a6b82', '--faint': '#90a0b5',
      '--accent': '#0e9bc4', '--accentGlow': 'rgba(14,155,196,.26)', '--accentSoft': 'rgba(14,155,196,.1)',
      '--crit': '#dc2626', '--high': '#ea7317', '--med': '#c2870a', '--low': '#2563eb', '--good': '#0f9d6b',
      '--critSoft': 'rgba(220,38,38,.09)', '--critLine': 'rgba(220,38,38,.2)',
      '--highSoft': 'rgba(234,115,23,.1)', '--highLine': 'rgba(234,115,23,.22)',
      '--medSoft': 'rgba(194,135,10,.11)', '--medLine': 'rgba(194,135,10,.24)',
      '--lowSoft': 'rgba(37,99,235,.09)', '--lowLine': 'rgba(37,99,235,.2)'
    }
  };
  // The light theme keeps a dark sidebar (base44 style); use a fixed light text
  // colour for sidebar contents regardless of theme.
  var SIDEBAR_FG = '#e8eef6', SIDEBAR_MUTED = '#8294aa';

  var data = window.__DASH__ || { namespaces: [], findings: [], raw: '', provider: 'llm', autoRefresh: false };
  var DASH_KEY = 'exalm.dash';
  // Registry mode: the payload carries the settings-filtered dashboard list
  // and the SPA builds navigation from it. Legacy mode (no registry — e.g.
  // a single-analyzer --open run) keeps the hardcoded nav unchanged.
  function dashList() { return (data.dashboards && data.dashboards.length) ? data.dashboards : null; }
  function dashById(id) {
    var list = dashList() || [];
    for (var i = 0; i < list.length; i++) if (list[i].id === id) return list[i];
    return null;
  }
  function defaultDash() {
    var list = dashList() || [];
    if (data.analyzer && dashById(data.analyzer)) return data.analyzer;
    for (var i = 0; i < list.length; i++) if (!list[i].standalone) return list[i].id;
    return list.length ? list[0].id : '';
  }
  var savedTheme = 'dark', savedPage = 'dashboard', savedDash = '';
  try { var t0 = localStorage.getItem(THEME_KEY); if (t0 === 'light' || t0 === 'dark') savedTheme = t0; } catch (e) {}
  try { var p0 = localStorage.getItem(PAGE_KEY); if (PAGES.indexOf(p0) !== -1) savedPage = p0; } catch (e) {}
  try { var d0 = localStorage.getItem(DASH_KEY); if (d0) savedDash = d0; } catch (e) {}

  var state = {
    theme: savedTheme, page: savedPage, query: '', filter: 'all', range: '24h',
    freqScope: 'cluster', selectedNs: 'all', nsMenuOpen: false,
    sort: { by: 'sev', dir: 'desc' },
    openGroups: { Pods: true, Resources: true }, openFinding: null,
    fixed: {}, fixing: {},
    dash: savedDash, // selected dashboard id (registry mode); resolved lazily
    incidentDraft: { title: '', severity: 'medium', namespace: '', service: '' },
    incidentBusy: {}, incidentError: '', incidentFilter: ''
  };

  // ── Helpers ──
  function esc(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }
  function fmt(n) { return Number(n || 0).toLocaleString('en-US'); }
  function camelToKebab(s) { return s.replace(/[A-Z]/g, function (m) { return '-' + m.toLowerCase(); }); }
  function css(o) { var out = ''; for (var k in o) { var v = o[k]; if (v === '' || v == null) continue; out += camelToKebab(k) + ':' + v + ';'; } return out; }

  function sevMeta(sev) {
    var map = {
      critical: { label: 'CRITICAL', c: 'var(--crit)', soft: 'var(--critSoft)', line: 'var(--critLine)' },
      high: { label: 'HIGH', c: 'var(--high)', soft: 'var(--highSoft)', line: 'var(--highLine)' },
      medium: { label: 'MEDIUM', c: 'var(--med)', soft: 'var(--medSoft)', line: 'var(--medLine)' },
      low: { label: 'LOW', c: 'var(--low)', soft: 'var(--lowSoft)', line: 'var(--lowLine)' },
      other: { label: 'OTHER', c: 'var(--low)', soft: 'var(--lowSoft)', line: 'var(--lowLine)' }
    };
    return map[sev] || map.other;
  }

  // sortRows returns a NEW array (never mutates the input) ordered by
  // sortState.by/dir. 'sev' compares SEV_RANK numerically; every other key
  // compares the field as a case-insensitive string. Ties fall back to the
  // original (group) order for a stable sort.
  function sortRows(rows, sortState) {
    var by = (sortState && sortState.by) || 'sev', dir = (sortState && sortState.dir) === 'asc' ? 1 : -1;
    return rows.map(function (f, i) { return { f: f, i: i }; }).sort(function (a, b) {
      var av, bv;
      if (by === 'sev') { av = SEV_RANK[a.f.sev] || 0; bv = SEV_RANK[b.f.sev] || 0; }
      else { av = String(a.f[by] || '').toLowerCase(); bv = String(b.f[by] || '').toLowerCase(); }
      if (av < bv) return -1 * dir;
      if (av > bv) return 1 * dir;
      return a.i - b.i;
    }).map(function (x) { return x.f; });
  }

  function buildSeries(scale) {
    var seed = 7;
    function rng() { seed = (seed * 1103515245 + 12345) & 0x7fffffff; return seed / 0x7fffffff; }
    var out = [];
    for (var i = 0; i < 24; i++) {
      var wave = 0.5 + 0.5 * Math.sin(i / 24 * Math.PI * 2 - 1.1);
      var base = wave * 55 + 12;
      var med = Math.max(0, Math.round(base * (0.5 + rng() * 0.4) * scale));
      var high = Math.max(0, Math.round(base * (0.25 + rng() * 0.2) * scale));
      var low = Math.max(0, Math.round(base * (0.1 + rng() * 0.15) * scale));
      var crit = Math.round((rng() < 0.16 ? (1 + rng() * 3) : 0) * scale);
      out.push({ crit: crit, high: high, med: med, low: low, hour: i });
    }
    return out;
  }

  function mdInline(s) {
    s = esc(s);
    s = s.replace(/`([^`]+)`/g, '<code style="font-family:var(--font-mono),monospace;font-size:11.5px;background:var(--track);padding:1px 6px;border-radius:5px;color:var(--accent);">$1</code>');
    s = s.replace(/\*\*([^*]+)\*\*/g, '<strong style="color:var(--fg)">$1</strong>');
    return s;
  }
  function mdToHtml(md) {
    if (!md) return '<em style="color:var(--muted)">No analysis narrative available for this scope.</em>';
    var lines = String(md).split('\n'), html = '', listOpen = '';
    function closeList() { if (listOpen) { html += '</' + listOpen + '>'; listOpen = ''; } }
    for (var i = 0; i < lines.length; i++) {
      var t = lines[i].trim();
      if (!t) { closeList(); continue; }
      var h = t.match(/^(#{1,4})\s+(.*)$/);
      if (h) { closeList(); html += '<h4 style="margin:16px 0 7px;font-size:12.5px;color:var(--fg);">' + mdInline(h[2]) + '</h4>'; continue; }
      var ol = t.match(/^\d+\.\s+(.*)$/), ul = t.match(/^[-*]\s+(.*)$/);
      if (ol) { if (listOpen !== 'ol') { closeList(); listOpen = 'ol'; html += '<ol style="margin:0 0 8px;padding-left:18px;">'; } html += '<li style="margin-bottom:6px;">' + mdInline(ol[1]) + '</li>'; continue; }
      if (ul) { if (listOpen !== 'ul') { closeList(); listOpen = 'ul'; html += '<ul style="margin:0 0 8px;padding-left:18px;">'; } html += '<li style="margin-bottom:6px;">' + mdInline(ul[1]) + '</li>'; continue; }
      closeList();
      html += '<p style="margin:0 0 12px;">' + mdInline(t) + '</p>';
    }
    closeList();
    return html;
  }

  function applyTheme() {
    var vars = THEMES[state.theme] || THEMES.dark, root = document.documentElement;
    for (var k in vars) root.style.setProperty(k, vars[k]);
    document.body.style.background = vars['--bg'];
    document.body.style.color = vars['--fg'];
  }

  // ── Actions ──
  function fix(id) {
    if (state.fixed[id] || state.fixing[id] || !data.canFix) return;
    state.fixing[id] = true; render();
    fetch('/api/findings/' + encodeURIComponent(id) + '/fix', { method: 'POST', headers: { 'X-Exalm-Request': 'true' } })
      .then(function (r) { return r.ok; })
      .then(function (ok) {
        delete state.fixing[id];
        if (ok) { state.fixed[id] = true; render(); setTimeout(refresh, 1200); } else { render(); }
      })
      .catch(function () { delete state.fixing[id]; render(); });
  }
  function fixAll() {
    if (!data.canFix) return;
    data.findings.filter(function (f) { return f.fix && !state.fixed[f.id] && !state.fixing[f.id]; })
      .forEach(function (f, i) { setTimeout(function () { fix(f.id); }, i * 220); });
  }
  function refresh() {
    fetch('/api/dashboard').then(function (r) { return r.json(); }).then(function (next) {
      if (!next || !Array.isArray(next.findings)) return;
      next.canFix = data.canFix; next.canCreatePR = data.canCreatePR;
      data = next;
      var ids = {}; data.findings.forEach(function (f) { ids[f.id] = true; });
      ['fixed', 'fixing'].forEach(function (m) { for (var id in state[m]) if (!ids[id]) delete state[m][id]; });
      render();
    }).catch(function () {});
  }

  // ── Compute (port of renderVals) ──
  function computeVals() {
    var s = state, NS = data.namespaces || [];
    var allMode = s.selectedNs === 'all';
    var nsObj = NS.filter(function (n) { return n.key === s.selectedNs; })[0];
    if (!allMode && !nsObj) { allMode = true; s.selectedNs = 'all'; }

    var agg = { crit: 0, high: 0, med: 0, low: 0, pods: 0, findings: 0 };
    (allMode ? NS : [nsObj]).forEach(function (n) {
      agg.crit += n.crit; agg.high += n.high; agg.med += n.med; agg.low += n.low; agg.pods += n.pods; agg.findings += n.findings;
    });
    var sevCounts = { crit: agg.crit, high: agg.high, med: agg.med, low: agg.low };
    var podCount = allMode ? (data.pods || agg.pods) : (nsObj.pods || 0);
    var unhealthy = (allMode && data.unhealthy) ? data.unhealthy : Math.round(podCount * 0.085);
    var errorRate = ((agg.crit * 3 + agg.high) / Math.max(podCount, 1) * 1.4).toFixed(1) + '%';
    var bigNumber = fmt(Math.round(1617017 * (podCount / 165)));

    var C = 213.6, gap = 1.5;
    var donutTotal = NS.reduce(function (a, n) { return a + n.findings; }, 0) || 1;
    var acc = 0;
    var donutSegs = NS.map(function (n) {
      var len = (n.findings / donutTotal) * C;
      var seg = { color: n.color, dash: Math.max(0, len - gap) + ' ' + (C - Math.max(0, len - gap)), offset: -acc, opacity: (allMode || s.selectedNs === n.key) ? 1 : 0.22, key: n.key };
      acc += len; return seg;
    });

    var ringTotal = Math.max(1, agg.crit + agg.high + agg.med + agg.low), racc = 0;
    var ringSegs = [['var(--crit)', agg.crit], ['var(--high)', agg.high], ['var(--med)', agg.med], ['var(--low)', agg.low]]
      .filter(function (x) { return x[1] > 0; }).map(function (x) { var len = (x[1] / ringTotal) * C, seg = { color: x[0], dash: len + ' ' + (C - len), offset: -racc }; racc += len; return seg; });

    var healthScore = Math.max(12, Math.round(100 - (agg.crit * 6 + agg.high * 0.4 + agg.med * 0.1)));
    var healthColor = healthScore < 40 ? 'var(--crit)' : healthScore < 70 ? 'var(--high)' : 'var(--good)';

    var nsScopeFreq = (s.freqScope === 'namespace' && !allMode);
    var scale = (allMode || !nsScopeFreq) ? 1 : Math.max(0.35, podCount / 92);
    var series = buildSeries(scale);
    var maxTot = Math.max.apply(null, series.map(function (b) { return b.crit + b.high + b.med + b.low; }).concat([1]));
    var H = 116, segColor = { crit: 'var(--crit)', high: 'var(--high)', med: 'var(--med)', low: 'var(--low)' };
    var tsBars = series.map(function (b) {
      var total = b.crit + b.high + b.med + b.low;
      var segs = [['crit', b.crit], ['high', b.high], ['med', b.med], ['low', b.low]].filter(function (x) { return x[1] > 0; })
        .map(function (x, i) { return { h: Math.max(1, (x[1] / maxTot) * H), bg: segColor[x[0]], first: i === 0 }; });
      return { title: b.hour + ':00 · ' + total + ' findings', segs: segs };
    });

    var q = s.query.trim().toLowerCase();
    var matchSev = function (sev) { return s.filter === 'all' ? true : (s.filter === 'med' ? sev === 'medium' : (s.filter === 'low' ? (sev === 'low' || sev === 'other') : sev === s.filter)); };
    var matchQ = function (f) { return !q || (f.title + ' ' + f.ns + ' ' + f.reason).toLowerCase().indexOf(q) !== -1; };
    var base = (data.findings || []).filter(function (f) { return (allMode || f.nsKey === s.selectedNs) && matchQ(f); });

    var shownTotal = 0;
    var groups = GROUP_ORDER.map(function (name) {
      var items = base.filter(function (f) { return f.group === name && matchSev(f.sev); });
      shownTotal += items.length;
      return { name: name, shown: items.length, items: items, open: !!s.openGroups[name] };
    }).filter(function (g) { return g.items.length > 0; });

    // Flattened, filtered rows in group order, then re-sorted per state.sort
    // for the Log Explorer table (grouping itself isn't shown there — it's a
    // flat table, so re-sorting the flattened list is safe).
    var rows = [];
    groups.forEach(function (g) { g.items.forEach(function (f) { rows.push(f); }); });
    rows = sortRows(rows, s.sort);

    var fixableCount = base.filter(function (f) { return f.fix && !s.fixed[f.id]; }).length;
    var tabCounts = {
      all: base.length,
      critical: base.filter(function (f) { return f.sev === 'critical'; }).length,
      high: base.filter(function (f) { return f.sev === 'high'; }).length,
      med: base.filter(function (f) { return f.sev === 'medium'; }).length,
      low: base.filter(function (f) { return f.sev === 'low' || f.sev === 'other'; }).length
    };

    return {
      allMode: allMode, nsObj: nsObj, NS: NS, agg: agg, sevCounts: sevCounts,
      nsLabel: allMode ? 'all namespaces' : nsObj.key, nsDot: allMode ? 'var(--accent)' : nsObj.color,
      totalFindings: agg.findings, podCount: podCount, unhealthy: unhealthy, errorRate: errorRate, bigNumber: bigNumber,
      donutSegs: donutSegs, donutCenter: allMode ? donutTotal : nsObj.findings,
      ringSegs: ringSegs, ringTotal: ringTotal, healthScore: healthScore, healthColor: healthColor,
      healthDash: ((healthScore / 100) * C).toFixed(1) + ' ' + C,
      sloColor: agg.crit > 0 ? 'var(--high)' : 'var(--good)', sloLabel: agg.crit > 0 ? 'SLO at risk' : 'SLO all green',
      tsBars: tsBars, groups: groups, rows: rows, shownTotal: shownTotal, fixableCount: fixableCount, tabCounts: tabCounts
    };
  }

  // ── Legacy narrative sections (verdict/incidents/rbac/prevention) ──
  // These used to be tab-switched on the AI Analysis page; now they're folded
  // into the chat workspace's first assistant message as expandable
  // sections (see legacyNarrativeHTML() below and chat.js).
  function narrativeBox() { return 'padding:12px 14px;border-radius:10px;background:var(--panel2);border:1px solid var(--border);'; }

  function verdictSectionHTML(v) {
    var box = narrativeBox();
    var degraded = v.sevCounts.crit > 0 || v.sevCounts.high > 0;
    var verdict = v.sevCounts.crit > 0 ? 'Action required — degraded' : (v.sevCounts.high > 0 ? 'Attention advised' : 'Healthy');
    return '<div style="padding:14px 16px;border-radius:12px;background:var(--critSoft);border:1px solid var(--critLine);margin-bottom:14px;">' +
      '<div style="font-size:10.5px;text-transform:uppercase;letter-spacing:.7px;color:var(--crit);font-weight:700;">Verdict</div>' +
      '<div style="font-size:18px;font-weight:700;color:var(--fg);margin-top:3px;">' + esc(verdict) + '</div>' +
      '<div style="margin-top:5px;color:var(--muted);">' + v.sevCounts.crit + ' critical and ' + v.sevCounts.high + ' high findings across ' + v.totalFindings + ' total.</div></div>' +
      '<div style="display:flex;flex-direction:column;gap:9px;">' +
      '<div style="display:flex;gap:10px;' + box + '"><span style="color:var(--crit);">●</span><div><strong style="color:var(--fg)">Availability</strong><div style="color:var(--muted)">' + v.unhealthy + ' of ' + v.podCount + ' pods unhealthy.</div></div></div>' +
      '<div style="display:flex;gap:10px;' + box + '"><span style="color:var(--high);">●</span><div><strong style="color:var(--fg)">Severity mix</strong><div style="color:var(--muted)">crit ' + v.sevCounts.crit + ' · high ' + v.sevCounts.high + ' · med ' + v.sevCounts.med + ' · low ' + v.sevCounts.low + '</div></div></div>' +
      '<div style="display:flex;gap:10px;' + box + '"><span style="color:' + (degraded ? 'var(--high)' : 'var(--good)') + ';">●</span><div><strong style="color:var(--fg)">SLO</strong><div style="color:var(--muted)">' + esc(v.sloLabel) + '</div></div></div></div>';
  }

  function incidentsSectionHTML() {
    var box = narrativeBox();
    var inc = (data.findings || []).filter(function (f) { return f.sev === 'critical' || f.sev === 'high'; }).slice(0, 8);
    if (!inc.length) return '<div style="color:var(--muted)">No critical or high incidents in scope.</div>';
    return '<div style="display:flex;flex-direction:column;gap:11px;">' + inc.map(function (f) {
      var m = sevMeta(f.sev);
      return '<div style="' + box + 'border-left:3px solid ' + m.c + ';"><div style="display:flex;justify-content:space-between;gap:10px;"><strong style="color:var(--fg)">' + esc(f.title) + '</strong><span style="font-family:var(--font-mono),monospace;font-size:11px;color:var(--faint);white-space:nowrap;">' + esc(f.restarts !== '—' ? f.restarts + ' restarts' : f.nsKey) + '</span></div><div style="color:var(--muted);margin-top:4px;">' + esc(f.reason) + '</div></div>';
    }).join('') + '</div>';
  }

  function rbacSectionHTML() {
    var box = narrativeBox();
    var sec = (data.findings || []).filter(function (f) { return f.group === 'Security' || /rbac|forbidden|privileg|secret/i.test(f.title); });
    if (!sec.length) return '<div style="color:var(--muted)">No RBAC or security findings detected in scope.</div>';
    return '<div style="display:flex;flex-direction:column;gap:9px;">' + sec.map(function (f) {
      return '<div style="display:flex;gap:10px;' + box + '"><span style="color:var(--high)">⚿</span><div><strong style="color:var(--fg)">' + esc(f.title) + '</strong><div style="color:var(--muted)">' + esc(f.root) + '</div></div></div>';
    }).join('') + '</div>';
  }

  function preventionSectionHTML() {
    var box = narrativeBox();
    var seen = {}, tips = [];
    (data.findings || []).forEach(function (f) { if (f.suggestion && !seen[f.suggestion]) { seen[f.suggestion] = true; tips.push(f.suggestion); } });
    tips = tips.slice(0, 8);
    if (!tips.length) return '<div style="color:var(--muted)">No remediation suggestions available.</div>';
    return '<div style="display:flex;flex-direction:column;gap:9px;">' + tips.map(function (s) {
      return '<div style="display:flex;gap:10px;' + box + '"><span style="color:var(--good)">✓</span><div style="color:var(--body)">' + esc(s) + '</div></div>';
    }).join('') + '</div>';
  }

  // legacyNarrativeHTML stacks the four sections as expandable <details>,
  // used as the body of the chat workspace's first auto-posted message.
  function legacyNarrativeHTML() {
    var v = computeVals();
    function sec(title, inner) {
      return '<details style="margin-top:8px;border-top:1px solid var(--border);padding-top:8px;">' +
        '<summary style="cursor:pointer;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.5px;color:var(--muted);">' + esc(title) + '</summary>' +
        '<div style="margin-top:8px;">' + inner + '</div></details>';
    }
    return '<div style="font-size:13px;line-height:1.65;color:var(--body);">' + mdToHtml(data.raw) + '</div>' +
      sec('Verdict', verdictSectionHTML(v)) +
      sec('Incidents', incidentsSectionHTML()) +
      sec('RBAC & security', rbacSectionHTML()) +
      sec('Prevention & suggestions', preventionSectionHTML());
  }

  // ── Reusable card chrome ──
  function card(inner, pad) { return '<div style="background:var(--panel);border:1px solid var(--border);border-radius:14px;padding:' + (pad || '16px') + ';">' + inner + '</div>'; }
  function cardLabel(t) { return '<div style="font-size:10.5px;letter-spacing:.7px;text-transform:uppercase;color:var(--faint);font-weight:600;">' + esc(t) + '</div>'; }

  // ── Sidebar icons (monochrome, currentColor) ──
  function icon(name) {
    var a = 'width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"';
    switch (name) {
      case 'dashboard': return '<svg ' + a + '><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/></svg>';
      case 'explorer': return '<svg ' + a + '><circle cx="11" cy="11" r="7"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>';
      case 'ai': return '<svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor"><path d="M12 2l1.9 5.5L19.5 9l-5.6 1.5L12 16l-1.9-5.5L4.5 9l5.6-1.5z"/></svg>';
      case 'alerts': return '<svg ' + a + '><path d="M6 8a6 6 0 0112 0c0 7 3 9 3 9H3s3-2 3-9"/><path d="M10 21a2 2 0 004 0"/></svg>';
      case 'settings': return '<svg ' + a + '><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.6 1.6 0 00.3 1.8l.1.1a2 2 0 11-2.8 2.8l-.1-.1a1.6 1.6 0 00-2.7 1.1V21a2 2 0 11-4 0v-.2a1.6 1.6 0 00-2.7-1.1l-.1.1a2 2 0 11-2.8-2.8l.1-.1A1.6 1.6 0 004 15a1.6 1.6 0 00-1.5-1H2a2 2 0 110-4h.2A1.6 1.6 0 004 9a1.6 1.6 0 00-.3-1.8l-.1-.1a2 2 0 112.8-2.8l.1.1A1.6 1.6 0 009 5h.1A1.6 1.6 0 0010 3.5V3a2 2 0 114 0v.2A1.6 1.6 0 0015 5a1.6 1.6 0 001.8-.3l.1-.1a2 2 0 112.8 2.8l-.1.1A1.6 1.6 0 0020 9v.1a1.6 1.6 0 001.5 1H22a2 2 0 110 4h-.2a1.6 1.6 0 00-1.4 1z"/></svg>';
      case 'dora': return '<svg ' + a + '><line x1="18" y1="20" x2="18" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/><line x1="6" y1="20" x2="6" y2="14"/></svg>';
      case 'timeline': return '<svg ' + a + '><line x1="3" y1="12" x2="21" y2="12"/><circle cx="7" cy="12" r="2"/><circle cx="14" cy="12" r="2"/><circle cx="20" cy="12" r="1.5"/></svg>';
    }
    return '';
  }

  // ── Sidebar ──
  function navBtn(active, act, attrs, iconKey, label, dim) {
    return '<button data-act="' + act + '" ' + attrs + ' style="display:flex;align-items:center;gap:12px;width:100%;padding:10px 14px;border:none;border-left:3px solid ' + (active ? 'var(--accent)' : 'transparent') + ';cursor:pointer;font-family:inherit;font-size:13.5px;font-weight:' + (active ? '600' : '500') + ';text-align:left;background:' + (active ? 'var(--accentSoft)' : 'transparent') + ';color:' + (active ? 'var(--accent)' : SIDEBAR_MUTED) + (dim ? ';opacity:.55' : '') + ';">' +
      '<span style="display:flex;width:18px;height:18px;flex:none;">' + icon(iconKey) + '</span><span>' + esc(label) + '</span></button>';
  }
  function navGroupLabel(t) {
    return '<div class="ex-brand-text" style="padding:12px 16px 4px;font-size:9.5px;letter-spacing:1px;text-transform:uppercase;color:' + SIDEBAR_MUTED + ';opacity:.7;">' + esc(t) + '</div>';
  }
  function sidebarNav() {
    var list = dashList();
    if (!list) {
      // Legacy single-dashboard mode: the original five fixed entries.
      var items = [['dashboard', 'Dashboard'], ['explorer', 'Log Explorer'], ['ai', 'AI Analysis'], ['alerts', 'Alerts'], ['settings', 'Settings']];
      return items.map(function (it) {
        return navBtn(state.page === it[0], 'nav', 'data-page="' + it[0] + '"', it[0], it[1], false);
      }).join('');
    }
    // Registry mode: dashboards grouped by category, then utility pages.
    var html = '';
    var groups = [['platform', 'Platform'], ['analyzer', 'Analyzers']];
    groups.forEach(function (g) {
      var members = list.filter(function (d) { return d.category === g[0]; });
      if (!members.length) return;
      html += navGroupLabel(g[1]);
      html += members.map(function (d) {
        if (d.standalone) {
          return '<a href="/' + esc(d.id) + '" style="display:flex;align-items:center;gap:12px;width:100%;padding:10px 14px;border-left:3px solid transparent;font-size:13.5px;font-weight:500;text-decoration:none;color:' + SIDEBAR_MUTED + ';">' +
            '<span style="display:flex;width:18px;height:18px;flex:none;">' + icon(d.icon) + '</span><span>' + esc(d.name) + '</span><span style="margin-left:auto;font-size:10px;opacity:.6;">↗</span></a>';
        }
        var active = state.page === 'dash' && state.dash === d.id;
        return navBtn(active, 'nav-dash', 'data-dash="' + esc(d.id) + '"', d.icon, d.name, !d.live);
      }).join('');
    });
    // Explorer / AI / Alerts read the k8s findings payload; hide them when
    // the k8s dashboard isn't in the registry (e.g. serve --no-k8s). The
    // Explorer entry is additionally capability-gated on the registry's
    // supportsExplorer flag rather than assumed.
    var k8sDash = dashById('k8s');
    var util = [['settings', 'Settings']];
    if (k8sDash) {
      util = [];
      if (k8sDash.supportsExplorer) util.push(['explorer', 'Log Explorer']);
      util.push(['ai', 'AI Analysis'], ['alerts', 'Alerts'], ['settings', 'Settings']);
    }
    html += navGroupLabel('Workspace');
    html += util.map(function (it) {
      return navBtn(state.page === it[0], 'nav', 'data-page="' + it[0] + '"', it[0], it[1], false);
    }).join('');
    return html;
  }
  function sidebar() {
    var subtitle = dashList() ? 'Observability' : 'K8s Analyzer';
    return '<aside class="ex-sidebar" style="width:230px;flex:none;background:var(--sidebar);border-right:1px solid var(--border);display:flex;flex-direction:column;position:sticky;top:0;height:100vh;overflow-y:auto;">' +
      '<div style="display:flex;align-items:center;gap:10px;padding:18px 16px 16px;">' +
      '<div style="width:30px;height:30px;border-radius:8px;background:linear-gradient(135deg,var(--accent),#7b5bff);display:flex;align-items:center;justify-content:center;box-shadow:0 0 16px var(--accentGlow);"><div style="width:11px;height:11px;border-radius:3px;background:#fff;"></div></div>' +
      '<div class="ex-brand-text"><div style="font-weight:700;font-size:15px;letter-spacing:-.2px;color:' + SIDEBAR_FG + ';">Exalm</div><div style="font-size:9.5px;letter-spacing:1px;text-transform:uppercase;color:' + SIDEBAR_MUTED + ';">' + subtitle + '</div></div></div>' +
      '<nav style="display:flex;flex-direction:column;gap:2px;margin-top:6px;">' + sidebarNav() + '</nav>' +
      '<div style="flex:1;"></div>' +
      '<div style="padding:14px 16px;border-top:1px solid var(--border);font-size:11px;color:' + SIDEBAR_MUTED + ';">' +
      '<span style="width:6px;height:6px;border-radius:50%;background:var(--good);display:inline-block;margin-right:6px;animation:ex-pulse 2s ease infinite;"></span>live · ' + esc(data.provider || 'llm') + '</div></aside>';
  }

  // ── Namespace selector (shared in the top bar) ──
  function nsSelector(v) {
    var nsMenuRows = [{ key: 'all', color: '#8294aa', label: 'all namespaces', count: v.NS.reduce(function (a, n) { return a + n.findings; }, 0) }]
      .concat(v.NS.map(function (n) { return { key: n.key, color: n.color, label: n.key, count: n.findings }; }));
    var html = '<div style="position:relative;"><button data-act="ns-toggle" style="display:flex;align-items:center;gap:9px;height:34px;padding:0 11px;border-radius:9px;border:1px solid var(--border);background:var(--panel2);color:var(--fg);font-size:12.5px;font-weight:500;cursor:pointer;">' +
      '<span style="width:8px;height:8px;border-radius:2px;background:' + v.nsDot + ';"></span>' +
      '<span style="font-size:10px;color:var(--faint);text-transform:uppercase;letter-spacing:.5px;">namespace</span>' +
      '<span style="font-family:var(--font-mono),monospace;">' + esc(v.nsLabel) + '</span>' +
      '<span style="font-size:9px;color:var(--faint);transform:' + (state.nsMenuOpen ? 'rotate(180deg)' : 'none') + ';transition:transform .2s;">▾</span></button>';
    if (state.nsMenuOpen) {
      html += '<div style="position:absolute;top:40px;right:0;min-width:230px;background:var(--panel);border:1px solid var(--border);border-radius:10px;box-shadow:0 12px 34px rgba(0,0,0,.45);padding:5px;z-index:50;">';
      nsMenuRows.forEach(function (n) {
        var active = state.selectedNs === n.key;
        html += '<button data-act="ns-select" data-ns="' + esc(n.key) + '" style="display:flex;align-items:center;gap:9px;width:100%;padding:7px 9px;border-radius:7px;border:none;cursor:pointer;background:' + (active ? 'var(--panel2)' : 'transparent') + ';color:var(--fg);">' +
          '<span style="width:8px;height:8px;border-radius:2px;background:' + n.color + ';flex:none;"></span>' +
          '<span style="flex:1;text-align:left;font-family:var(--font-mono),monospace;font-size:12.5px;">' + esc(n.label) + '</span>' +
          '<span style="font-size:11px;color:var(--muted);">' + n.count + '</span>' + (active ? '<span style="color:var(--accent);font-size:12px;">✓</span>' : '') + '</button>';
      });
      html += '</div>';
    }
    return html + '</div>';
  }

  // ── Top bar (page title + shared controls) ──
  function topbar(v) {
    var meta = {
      dashboard: ['Dashboard', 'Cluster health and findings overview'],
      explorer: ['Log Explorer', 'Search and filter all findings'],
      ai: ['AI Analysis', 'LLM-powered root-cause analysis'],
      alerts: ['Alerts', 'Critical and high-severity findings'],
      settings: ['Settings', 'Theme, dashboards, and environment']
    }[state.page] || ['Dashboard', ''];
    if (state.page === 'dash') {
      var dd = dashById(state.dash);
      meta = dd ? [dd.name, dd.description || ''] : ['Dashboard', ''];
    }
    var actions = '';
    if (data.canFix && (state.page === 'dashboard' || state.page === 'explorer')) {
      actions += '<button data-act="fixall" style="display:flex;align-items:center;gap:8px;height:34px;padding:0 15px;border-radius:9px;border:none;background:var(--accent);color:#04222b;font-size:12.5px;font-weight:700;cursor:pointer;box-shadow:0 2px 12px var(--accentGlow);"><span style="width:7px;height:7px;border-radius:2px;background:#04222b;"></span>Fix all (' + v.fixableCount + ')</button>';
    }
    return '<header style="display:flex;align-items:center;gap:14px;padding:16px 22px;border-bottom:1px solid var(--border);background:var(--bg);position:sticky;top:0;z-index:30;">' +
      '<div style="flex:1;min-width:0;"><div style="font-size:21px;font-weight:700;letter-spacing:-.3px;">' + esc(meta[0]) + '</div><div style="font-size:12.5px;color:var(--muted);margin-top:1px;">' + esc(meta[1]) + '</div></div>' +
      nsSelector(v) +
      '<button data-act="logs" title="Open the log viewer" style="display:flex;align-items:center;gap:7px;height:34px;padding:0 12px;border-radius:9px;border:1px solid var(--border);background:var(--panel2);color:var(--fg);font-size:12.5px;font-weight:500;cursor:pointer;"><span style="font-size:13px;">▤</span><span>Logs</span></button>' +
      '<button data-act="theme" title="Toggle theme" style="display:flex;align-items:center;justify-content:center;width:34px;height:34px;border-radius:9px;border:1px solid var(--border);background:var(--panel2);color:var(--fg);font-size:14px;cursor:pointer;">' + (state.theme === 'dark' ? '☀' : '☾') + '</button>' +
      actions + '</header>';
  }

  // ── Stat cards (shared widget library) ──
  function statCards(v) { return window.ExalmWidgets.statCards(v); }

  // ── Severity donut / namespace bars / error frequency (shared library) ──
  function severityDonut(v) { return window.ExalmWidgets.severityDonut(v); }
  function nsBars(v) { return window.ExalmWidgets.nsBars(v); }
  function errorFreq(v) { return window.ExalmWidgets.errorFreq(v); }

  // ── Page: Dashboard ──
  function pageDashboard(v) {
    return statCards(v) +
      '<div class="ex-2col" style="display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:16px;">' + severityDonut(v) + nsBars(v) + '</div>' +
      errorFreq(v);
  }

  // ── Page: Log Explorer (findings table) ──
  function pageExplorer(v) {
    var filters = '<div style="display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin-bottom:14px;">' +
      '<div style="position:relative;flex:1;min-width:220px;"><span style="position:absolute;left:11px;top:50%;transform:translateY(-50%);color:var(--faint);font-size:13px;">⌕</span>' +
      '<input id="finding-search" value="' + esc(state.query) + '" placeholder="Search findings, namespaces, reasons…" autocomplete="off" style="width:100%;height:36px;padding:0 12px 0 30px;border-radius:9px;border:1px solid var(--border);background:var(--panel2);color:var(--fg);font-family:inherit;font-size:13px;outline:none;"></div>' +
      [['all', 'All'], ['critical', 'Critical'], ['high', 'High'], ['med', 'Med'], ['low', 'Low']].map(function (x) {
        var a = state.filter === x[0];
        return '<button data-act="filter" data-f="' + x[0] + '" style="display:flex;align-items:center;gap:6px;padding:7px 12px;border-radius:8px;font-size:12px;font-weight:500;cursor:pointer;border:1px solid ' + (a ? 'var(--accent)' : 'var(--border)') + ';background:' + (a ? 'var(--accent)' : 'transparent') + ';color:' + (a ? '#04222b' : 'var(--muted)') + ';">' + x[1] + '<span style="font-size:10px;font-weight:700;padding:0 6px;border-radius:10px;background:' + (a ? 'rgba(0,0,0,.18)' : 'var(--track)') + ';color:' + (a ? '#04222b' : 'var(--muted)') + ';">' + v.tabCounts[x[0]] + '</span></button>';
      }).join('') + '</div>';

    var th = 'text-align:left;padding:10px 14px;font-size:10px;letter-spacing:.6px;text-transform:uppercase;color:var(--faint);font-weight:600;border-bottom:1px solid var(--border);';
    // sortTh renders a clickable header cell with an arrow on the active
    // sort column; non-sortable headers (Action) pass key === null.
    function sortTh(label, key, extra) {
      extra = extra || '';
      if (!key) return '<th style="' + th + extra + '">' + esc(label) + '</th>';
      var active = state.sort.by === key;
      var arrow = active ? (state.sort.dir === 'asc' ? ' ▲' : ' ▼') : '';
      return '<th data-act="sort" data-key="' + key + '" style="' + th + extra + 'cursor:pointer;user-select:none;color:' + (active ? 'var(--accent)' : 'var(--faint)') + ';">' + esc(label) + arrow + '</th>';
    }
    var head = '<tr>' + sortTh('Severity', 'sev') + sortTh('Namespace / Pod', 'ns') + sortTh('Message', 'title', 'width:42%;') + sortTh('Category', 'group') + sortTh('Action', null, 'text-align:right;') + '</tr>';
    var rows = v.rows.map(function (f) {
      var m = sevMeta(f.sev), isFixed = !!state.fixed[f.id], isFixing = !!state.fixing[f.id];
      var td = 'padding:11px 14px;border-bottom:1px solid var(--border);vertical-align:top;';
      var status = isFixed ? '<span style="font-size:9.5px;font-weight:700;color:var(--good);background:var(--track);padding:2px 8px;border-radius:20px;">FIXED ✓</span>' : '';
      return '<tr data-act="remediate" data-id="' + esc(f.id) + '" style="cursor:pointer;" class="ex-row">' +
        '<td style="' + td + '"><span style="font-size:9px;font-weight:700;letter-spacing:.5px;padding:2px 7px;border-radius:5px;color:' + m.c + ';background:' + m.soft + ';border:1px solid ' + m.line + ';white-space:nowrap;">' + m.label + '</span></td>' +
        '<td style="' + td + 'font-family:var(--font-mono),monospace;font-size:11px;color:var(--muted);white-space:nowrap;">' + esc(f.ns) + '</td>' +
        '<td style="' + td + 'color:var(--fg);font-size:12.5px;">' + esc(f.title) + (f.reason && f.reason !== f.title ? '<div style="color:var(--faint);font-size:11px;margin-top:2px;">' + esc(f.reason) + '</div>' : '') + '</td>' +
        '<td style="' + td + 'font-size:11.5px;color:var(--muted);">' + esc(f.group) + '</td>' +
        '<td style="' + td + 'text-align:right;white-space:nowrap;">' + status +
        ' <button data-act="investigate" data-id="' + esc(f.id) + '" title="Investigate" style="border:1px solid var(--accent);background:transparent;color:var(--accent);border-radius:7px;cursor:pointer;font-size:11px;font-weight:600;padding:4px 9px;">✦</button>' +
        (f.fix ? ' ' + fixBtn(f, isFixed, isFixing, false) : '') + '</td></tr>';
    }).join('');
    var table = v.rows.length
      ? '<div style="overflow-x:auto;"><table style="width:100%;border-collapse:collapse;">' + head + rows + '</table></div>'
      : '<div style="padding:50px 20px;text-align:center;color:var(--faint);font-size:13px;">No findings match your filters.</div>';
    return filters +
      '<div style="background:var(--panel);border:1px solid var(--border);border-radius:14px;overflow:hidden;">' +
      '<div style="padding:11px 15px;border-bottom:1px solid var(--border);font-size:12px;color:var(--muted);">' + v.shownTotal + ' results · ' + esc(v.nsLabel) + '</div>' +
      table + '</div>';
  }

  // ── Page: Analyzer dashboard (syslog/httplog/eventlog/iis/logs) ──
  // Rendered when the payload carries data.analyzer; the k8s dashboard page
  // is untouched. Panels + drilldown live in analyzer.js (AnalyzerDash).
  function pageAnalyzer(v, desc) {
    var title = desc ? desc.name : (data.analyzer || '').toUpperCase() + ' analysis';
    var sub = desc ? (desc.description || '') + ' · click any chart to open the matching log lines'
      : v.totalFindings + ' findings · click any chart to open the matching log lines';
    var header = '<div style="display:flex;align-items:center;gap:12px;margin-bottom:14px;">' +
      '<span style="width:34px;height:34px;border-radius:9px;background:linear-gradient(135deg,#7b5bff,var(--accent));display:flex;align-items:center;justify-content:center;color:#fff;">' + icon('dashboard') + '</span>' +
      '<div style="flex:1;"><div style="font-size:14px;font-weight:700;">' + esc(title) + '</div>' +
      '<div style="font-size:12px;color:var(--muted);">' + esc(sub) + '</div></div></div>';
    // Hub mode: the analyzer page carries the full investigation workspace
    // (tree + chat + timeline + embedded corpus explorer — same composition
    // as the k8s AI page, scoped to this analyzer's routes). Hidden when AI
    // is disabled; the chart drilldown stays the non-AI log surface.
    var ai = '';
    if (desc && desc.supportsAI && data.supportsAI !== false) {
      ai = '<details open style="margin-top:14px;"><summary style="cursor:pointer;font-size:10.5px;font-weight:700;letter-spacing:.7px;text-transform:uppercase;color:var(--faint);padding:4px 0;">AI Investigation</summary>' +
        card(workspaceHTML({ analyzerId: desc.id }), '14px 16px') + '</details>';
    }
    return header + analyzerFindingsHTML() + '<div id="analyzer-dash-root"></div>' + ai;
  }

  // analyzerFindingsHTML renders the structured findings promoted from the
  // analyzer's symptom catalog (severity, likely cause, suggestion) as a
  // collapsible panel above the charts. Each card opens the shared
  // remediation panel (data-act="remediate") — the same explainable panel the
  // k8s dashboard uses — so proposed shell fixes render with copy buttons and
  // an "Apply" action that is gated server-side (applicableKinds). Empty when
  // the analyzer emitted no findings.
  var SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, other: 4 };
  function analyzerFindingsHTML() {
    var fs = data.findings || [];
    if (!fs.length) return '';
    var sorted = fs.slice().sort(function (a, b) {
      var ra = SEV_ORDER[a.sev]; var rb = SEV_ORDER[b.sev];
      return (ra == null ? 9 : ra) - (rb == null ? 9 : rb);
    });
    var cards = sorted.map(function (f) {
      var m = sevMeta(f.sev);
      var chip = '<span style="font-size:9px;font-weight:700;letter-spacing:.5px;padding:2px 7px;border-radius:5px;color:' + m.c + ';background:' + m.soft + ';border:1px solid ' + m.line + ';white-space:nowrap;">' + m.label + '</span>';
      var conf = f.confidence ? '<span style="font-size:9px;font-weight:700;text-transform:uppercase;letter-spacing:.4px;color:' + confColor(f.confidence) + ';">' + esc(f.confidence) + ' confidence</span>' : '';
      var fixTag = f.fix ? '<span style="font-size:9px;font-weight:700;letter-spacing:.4px;color:var(--accent);">FIX AVAILABLE</span>' : '';
      var body = '';
      if (f.reason) body += '<div style="font-size:12px;color:var(--muted);margin-top:5px;">' + esc(f.reason) + '</div>';
      if (f.root) body += '<div style="font-size:11.5px;color:var(--faint);margin-top:3px;"><b style="color:var(--muted);">Likely cause:</b> ' + esc(f.root) + '</div>';
      if (f.suggestion) body += '<div style="font-size:11.5px;color:var(--good);margin-top:4px;">💡 ' + esc(f.suggestion) + '</div>';
      return '<div data-act="remediate" data-id="' + esc(f.id) + '" class="ex-row" title="Open remediation details" style="background:var(--panel);border:1px solid var(--border);border-left:3px solid ' + m.c + ';border-radius:12px;padding:14px 16px;margin-bottom:10px;cursor:pointer;box-shadow:0 1px 2px rgba(0,0,0,.18);">' +
        '<div style="display:flex;align-items:center;gap:9px;flex-wrap:wrap;">' + chip + conf + fixTag + '</div>' +
        '<div style="font-size:13px;font-weight:600;color:var(--fg);margin-top:6px;">' + esc(f.title) + '</div>' + body + '</div>';
    }).join('');
    return '<details open style="margin-bottom:14px;">' +
      '<summary style="cursor:pointer;font-size:10.5px;font-weight:700;letter-spacing:.7px;text-transform:uppercase;color:var(--faint);padding:4px 0;">Findings (' + fs.length + ')</summary>' +
      '<div style="margin-top:8px;">' + cards + '</div></details>';
  }

  // fillAnalyzerDash paints the analyzer panels after every re-render.
  // Legacy mode reads the payload-embedded analyzer/stats; hub mode fetches
  // the selected dashboard's stats from its scoped route (cached per id).
  var hubStatsCache = {};
  function invalidateDashCache(id) { delete hubStatsCache[id]; }
  function fillAnalyzerDash() {
    var dd = state.page === 'dash' ? dashById(state.dash) : null;
    if (dd && dd.id === 'incidents') { fillIncidentsRoot(); return; }
    if (!window.AnalyzerDash) return;
    var root = document.getElementById('analyzer-dash-root');
    if (!root) return;
    if (data.analyzer) {
      root.innerHTML = window.AnalyzerDash.render(data);
      window.AnalyzerDash.attach();
      return;
    }
    var d = dd;
    if (!d || !d.live || d.category !== 'analyzer') return;
    var cached = hubStatsCache[d.id];
    if (cached) {
      root.innerHTML = window.AnalyzerDash.render(cached);
      window.AnalyzerDash.attach();
      return;
    }
    root.innerHTML = '<div style="padding:30px;color:var(--faint);font-size:12.5px;">Loading ' + esc(d.name) + '…</div>';
    fetch('/api/dashboards/' + encodeURIComponent(d.id) + '/stats')
      .then(function (r) { if (!r.ok) throw new Error('http ' + r.status); return r.json(); })
      .then(function (json) {
        hubStatsCache[d.id] = json;
        if (state.page === 'dash' && state.dash === d.id) fillAnalyzerDash();
      })
      .catch(function () {
        root.innerHTML = '<div style="padding:30px;color:var(--faint);font-size:12.5px;">Could not load this dashboard’s data.</div>';
      });
  }

  // ── Incidents dashboard (v2: open/close/reopen + cross-links) ──
  function fillIncidentsRoot() {
    var root = document.getElementById('incidents-dash-root');
    if (!root) return;
    var cached = hubStatsCache.incidents;
    if (cached) { root.innerHTML = renderIncidents(cached); return; }
    root.innerHTML = '<div style="padding:30px;color:var(--faint);font-size:12.5px;">Loading incidents…</div>';
    fetch('/api/dashboards/incidents/stats')
      .then(function (r) { if (!r.ok) throw new Error('http ' + r.status); return r.json(); })
      .then(function (json) {
        hubStatsCache.incidents = (json && json.stats) ? json.stats : json;
        if (state.page === 'dash' && state.dash === 'incidents') fillIncidentsRoot();
      })
      .catch(function () {
        root.innerHTML = '<div style="padding:30px;color:var(--faint);font-size:12.5px;">Could not load incidents.</div>';
      });
  }

  function renderIncidents(stats) {
    if (!stats || stats.error) {
      return card('<div style="padding:6px 0;color:var(--muted);font-size:12.5px;">' + esc((stats && stats.error) || 'Incidents unavailable.') + '</div>', '16px 18px');
    }
    // Each tile filters the list below by status on click; clicking the
    // active tile (or Total) clears back to showing everything.
    var counts = '<div style="display:flex;gap:10px;margin-bottom:14px;">' +
      incidentCounter('Open', stats.open, 'var(--crit)', 'open') +
      incidentCounter('Mitigated', stats.mitigated, 'var(--med)', 'mitigated') +
      incidentCounter('Closed', stats.closed, 'var(--good)', 'closed') +
      incidentCounter('Total', stats.total, 'var(--muted)', '') +
      '</div>';

    var d = state.incidentDraft;
    var form = card(cardLabel('Open a new incident') +
      '<div style="display:flex;flex-wrap:wrap;gap:10px;margin-top:10px;align-items:flex-end;">' +
        incField('incident-title', 'Title', d.title, 220) +
        incSelect() +
        incField('incident-namespace', 'Namespace (optional)', d.namespace, 160) +
        incField('incident-service', 'Service (optional)', d.service, 160) +
        '<button data-act="incident-open" style="height:36px;padding:0 16px;border-radius:9px;border:none;background:var(--accent);color:#04222b;font-size:12.5px;font-weight:700;cursor:pointer;">Open incident</button>' +
      '</div>' +
      (state.incidentError ? '<div style="margin-top:8px;font-size:11.5px;color:var(--crit);">' + esc(state.incidentError) + '</div>' : ''),
      '16px 18px');

    var all = stats.incidents || [];
    var filter = state.incidentFilter;
    var shown = filter ? all.filter(function (inc) { return inc.status === filter; }) : all;
    var rows = shown.map(incidentRow).join('');
    var tableLabel = cardLabel('Incidents') + (filter
      ? '<span style="font-size:11px;color:var(--muted);font-weight:400;text-transform:none;letter-spacing:0;"> · filtered to ' + esc(filter) + ' (' + shown.length + ')</span>'
      : '');
    var table = card(tableLabel +
      (rows ? '<div style="margin-top:10px;">' + rows + '</div>'
        : '<div style="padding:30px 0;text-align:center;color:var(--faint);font-size:12.5px;">' +
          (all.length ? 'No ' + esc(filter) + ' incidents.' : 'No incidents recorded. Open one above, or run <code>exalm incident open</code>.') + '</div>'),
      '16px 18px');

    return counts + form + '<div style="height:14px;"></div>' + table;
  }

  function incidentCounter(label, n, color, status) {
    var active = state.incidentFilter === status && status !== '';
    return '<div class="ex-row" data-act="incident-filter" data-status="' + esc(status) + '" style="flex:1;background:var(--panel);border:1px solid ' + (active ? 'var(--accent)' : 'var(--border)') + ';border-radius:12px;padding:12px 14px;cursor:pointer;">' +
      '<div style="font-size:10.5px;letter-spacing:.6px;text-transform:uppercase;color:var(--faint);font-weight:600;">' + esc(label) + '</div>' +
      '<div style="font-size:20px;font-weight:700;color:' + color + ';margin-top:3px;">' + fmt(n || 0) + '</div></div>';
  }

  function incField(id, placeholder, val, w) {
    return '<input id="' + id + '" value="' + esc(val || '') + '" placeholder="' + esc(placeholder) + '" autocomplete="off" style="width:' + w + 'px;height:36px;padding:0 12px;border-radius:9px;border:1px solid var(--border);background:var(--panel2);color:var(--fg);font-family:inherit;font-size:12.5px;outline:none;">';
  }

  function incSelect() {
    var sevs = ['critical', 'high', 'medium', 'low', 'info'];
    return '<select id="incident-severity" style="height:36px;padding:0 10px;border-radius:9px;border:1px solid var(--border);background:var(--panel2);color:var(--fg);font-family:inherit;font-size:12.5px;">' +
      sevs.map(function (s) { return '<option value="' + s + '"' + (state.incidentDraft.severity === s ? ' selected' : '') + '>' + s + '</option>'; }).join('') +
      '</select>';
  }

  function fmtTime(iso) {
    if (!iso) return '';
    var d2 = new Date(iso);
    return isNaN(d2.getTime()) ? iso : d2.toLocaleString('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
  }

  // relatedDashLinks: jump-to buttons for currently-attached analyzer
  // dashboards. This is an honest cross-link, not automatic service/
  // namespace correlation — the operator judges relevance and clicks
  // through to compare.
  function relatedDashLinks(inc) {
    var live = (data.dashboards || []).filter(function (dd) { return dd.category === 'analyzer' && dd.live; });
    if (!live.length) return '';
    return live.map(function (dd) {
      return '<button data-act="nav-dash" data-dash="' + esc(dd.id) + '" style="font-size:10.5px;font-weight:600;color:var(--accent);background:none;border:none;padding:0 8px 0 0;cursor:pointer;">→ ' + esc(dd.name) + '</button>';
    }).join('');
  }

  function incidentRow(inc) {
    var m = sevMeta(inc.severity);
    var busy = state.incidentBusy[inc.id];
    var canClose = inc.status === 'open' || inc.status === 'mitigated';
    var canReopen = inc.status === 'closed';
    var actBtn = busy
      ? '<span style="font-size:11px;color:var(--muted);">…</span>'
      : canClose
        ? '<button data-act="incident-close" data-id="' + esc(inc.id) + '" style="height:28px;padding:0 12px;border-radius:7px;border:1px solid var(--border);background:var(--panel2);color:var(--fg);font-size:11px;font-weight:600;cursor:pointer;">Close</button>'
        : canReopen
          ? '<button data-act="incident-reopen" data-id="' + esc(inc.id) + '" style="height:28px;padding:0 12px;border-radius:7px;border:1px solid var(--border);background:var(--panel2);color:var(--fg);font-size:11px;font-weight:600;cursor:pointer;">Reopen</button>'
          : '';
    var links = relatedDashLinks(inc);
    return '<div class="ex-row" style="display:flex;align-items:center;gap:10px;padding:10px 0;border-bottom:1px solid var(--border);">' +
      '<span style="font-size:9px;font-weight:700;letter-spacing:.5px;padding:2px 7px;border-radius:5px;color:' + m.c + ';background:' + m.soft + ';border:1px solid ' + m.line + ';flex:none;">' + m.label + '</span>' +
      '<div style="flex:1;min-width:0;">' +
      '<div style="font-size:12.5px;font-weight:600;color:var(--fg);">' + esc(inc.title) + '</div>' +
      '<div style="font-family:var(--font-mono),monospace;font-size:10.5px;color:var(--faint);margin-top:2px;">' + esc(inc.id) + ' · ' + esc(inc.status) +
      (inc.service ? ' · ' + esc(inc.service) : '') + (inc.namespace ? ' · ' + esc(inc.namespace) : '') +
      ' · opened ' + esc(fmtTime(inc.openedAt)) + (inc.closedAt ? ' · closed ' + esc(fmtTime(inc.closedAt)) : '') + '</div>' +
      (links ? '<div style="margin-top:5px;">' + links + '</div>' : '') +
      '</div>' +
      '<div style="flex:none;">' + actBtn + '</div>' +
      '</div>';
  }

  function postIncidentAction(body) {
    return fetch('/api/dashboards/incidents/action', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Exalm-Request': 'true' },
      body: JSON.stringify(body)
    }).then(function (r) {
      if (!r.ok) return r.text().then(function (t) { throw new Error(t || ('http ' + r.status)); });
      return r.json();
    });
  }

  function refreshIncidents() {
    invalidateDashCache('incidents');
    fillIncidentsRoot();
  }

  function openIncidentDraft() {
    var d = state.incidentDraft;
    if (!d.title || !d.title.trim()) { state.incidentError = 'Title is required.'; render(); return; }
    state.incidentError = '';
    postIncidentAction({ action: 'open', title: d.title, severity: d.severity, namespace: d.namespace, service: d.service })
      .then(function () {
        state.incidentDraft = { title: '', severity: 'medium', namespace: '', service: '' };
        refreshIncidents();
      })
      .catch(function (e) { state.incidentError = String((e && e.message) || e); render(); });
  }

  function closeIncidentAction(id) {
    if (state.incidentBusy[id]) return;
    state.incidentBusy[id] = true; render();
    postIncidentAction({ action: 'close', id: id })
      .then(function () { delete state.incidentBusy[id]; refreshIncidents(); })
      .catch(function (e) { delete state.incidentBusy[id]; state.incidentError = String((e && e.message) || e); render(); });
  }

  function reopenIncidentAction(id) {
    if (state.incidentBusy[id]) return;
    state.incidentBusy[id] = true; render();
    postIncidentAction({ action: 'reopen', id: id })
      .then(function () { delete state.incidentBusy[id]; refreshIncidents(); })
      .catch(function (e) { delete state.incidentBusy[id]; state.incidentError = String((e && e.message) || e); render(); });
  }

  // ── Investigation workspace (shared by the AI page and analyzer pages) ──
  // The tree+chat grid plus collapsible Timeline and Logs panes. The chat
  // seed already carries the analysis summary, so there is no separate
  // Summary card (it would render the same narrative twice). ctx is
  // {analyzerId} for analyzer dashboards, or null for the k8s workspace.
  function workspaceHTML(ctx) {
    function pane(title, inner) {
      return '<details style="margin-top:12px;border-top:1px solid var(--border);padding-top:10px;">' +
        '<summary style="cursor:pointer;font-size:10.5px;font-weight:700;letter-spacing:.7px;text-transform:uppercase;color:var(--faint);">' + esc(title) + '</summary>' +
        '<div style="margin-top:10px;">' + inner + '</div></details>';
    }
    var timelineEmpty = '<div style="font-size:12px;color:var(--faint);">No investigation timeline yet — ask a question first.' +
      (dashById('timeline') ? ' See the <a href="/timeline" style="color:var(--accent);">cross-signal timeline ↗</a> for cluster-wide history.' : '') + '</div>';
    var logsInner = ctx && ctx.analyzerId
      ? '<div id="ai-logs-root"></div>'
      : '<button data-act="logs" style="display:flex;align-items:center;gap:7px;height:32px;padding:0 12px;border-radius:9px;border:1px solid var(--border);background:var(--panel2);color:var(--fg);font-size:12.5px;font-weight:500;cursor:pointer;"><span style="font-size:13px;">▤</span><span>Open the pod log viewer</span></button>';
    return '<div class="ex-ai-grid" style="display:grid;grid-template-columns:minmax(280px,34%) 1fr;gap:16px;">' +
      '<div id="ai-tree-root" style="min-width:0;border-right:1px solid var(--border);padding-right:14px;max-height:62vh;overflow-y:auto;"></div>' +
      '<div id="ai-chat-root" style="min-width:0;"></div>' +
      '</div>' +
      pane('Timeline', '<div id="ai-timeline-root">' + timelineEmpty + '</div>') +
      pane('Logs', logsInner);
  }

  // fillWorkspace paints the workspace's Timeline and Logs panes after each
  // re-render (the chat/tree panes are chat.js's). Explorer filter state is
  // kept per analyzer so render()'s innerHTML rebuild doesn't reset it.
  var wsExplorerFilters = {};
  function fillWorkspace() {
    var tlRoot = document.getElementById('ai-timeline-root');
    if (tlRoot && window.ExalmChat && window.ExalmChat.currentTimeline) {
      var ev = window.ExalmChat.currentTimeline();
      if (ev.length) tlRoot.innerHTML = window.ExalmChat.timelineHTML(ev);
    }
    var logsRoot = document.getElementById('ai-logs-root');
    if (logsRoot && !logsRoot._exWired && window.ExalmLogExplorer && window.AnalyzerDash && window.AnalyzerDash.corpusExplorerConfig) {
      var id = (state.page === 'dash' && state.dash) || data.analyzer || '';
      if (!id) return;
      logsRoot._exWired = true;
      var cfg = window.AnalyzerDash.corpusExplorerConfig(id, wsExplorerFilters[id] || {});
      var origFetch = cfg.fetchLogs;
      cfg.fetchLogs = function (f) { wsExplorerFilters[id] = f; return origFetch(f); };
      window.ExalmLogExplorer.create(logsRoot, cfg);
    }
  }

  // ── Page: AI Analysis — the k8s investigation workspace ──
  function pageAI(v) {
    var header = '<div style="display:flex;align-items:center;gap:12px;margin-bottom:14px;">' +
      '<span style="width:34px;height:34px;border-radius:9px;background:linear-gradient(135deg,#7b5bff,var(--accent));display:flex;align-items:center;justify-content:center;color:#fff;">' + icon('ai') + '</span>' +
      '<div style="flex:1;"><div style="font-size:14px;font-weight:700;">Investigation assistant</div><div style="font-size:12px;color:var(--muted);">Ask follow-ups — Exalm plans the investigation, gathers evidence across the cluster, and remembers it all, scoped to ' + esc(v.nsLabel) + '</div></div>' +
      '<button data-act="reanalyze" style="display:flex;align-items:center;gap:8px;height:36px;padding:0 16px;border-radius:9px;border:none;background:var(--accent);color:#04222b;font-size:12.5px;font-weight:700;cursor:pointer;">✦ Re-analyze ' + v.totalFindings + ' findings</button></div>';
    return card(header + workspaceHTML(null), '18px 20px');
  }

  // ── Page: Alerts (read-only critical+high findings) ──
  function pageAlerts(v) {
    var alerts = (data.findings || []).filter(function (f) {
      return (v.allMode || f.nsKey === state.selectedNs) && (f.sev === 'critical' || f.sev === 'high');
    });
    var head = '<div style="background:var(--panel);border:1px solid var(--border);border-radius:12px;padding:12px 16px;margin-bottom:14px;font-size:12.5px;color:var(--muted);">' +
      '<b style="color:var(--fg);">' + alerts.length + '</b> critical &amp; high alerts · ' + esc(v.nsLabel) + '</div>';
    if (!alerts.length) return head + '<div style="padding:50px;text-align:center;color:var(--faint);font-size:13px;">No critical or high alerts in scope. 🎉</div>';
    var cards = alerts.map(function (f) {
      var m = sevMeta(f.sev);
      return '<div data-act="remediate" data-id="' + esc(f.id) + '" class="ex-row" style="background:var(--panel);border:1px solid var(--border);border-left:3px solid ' + m.c + ';border-radius:12px;padding:13px 16px;margin-bottom:11px;cursor:pointer;">' +
        '<div style="display:flex;align-items:center;gap:9px;"><span style="font-size:9px;font-weight:700;letter-spacing:.5px;padding:2px 7px;border-radius:5px;color:' + m.c + ';background:' + m.soft + ';border:1px solid ' + m.line + ';">' + m.label + '</span>' +
        (f.confidence ? '<span style="font-size:9px;font-weight:700;text-transform:uppercase;letter-spacing:.4px;color:' + confColor(f.confidence) + ';">' + esc(f.confidence) + ' confidence</span>' : '') + '</div>' +
        '<div style="font-size:13.5px;font-weight:600;color:var(--fg);margin-top:7px;">' + esc(f.title) + '</div>' +
        '<div style="font-family:var(--font-mono),monospace;font-size:11px;color:var(--faint);margin-top:4px;">' + esc(f.ns) + '</div></div>';
    }).join('');
    return head + cards;
  }

  // ── Page: Settings ──
  // Appearance + environment stay local; the Dashboards card is persisted
  // server-side via GET/PUT /api/settings (absent => read-only fallback).
  var serverSettings = null;   // last fetched /api/settings document, or null
  var settingsAvail = null;    // null=unknown, true/false after first fetch

  function toggleBtn(on, act, id) {
    return '<button data-act="' + act + '"' + (id ? ' data-id="' + esc(id) + '"' : '') +
      ' style="position:relative;width:38px;height:21px;border-radius:11px;border:1px solid var(--border);cursor:pointer;transition:background .15s;background:' + (on ? 'var(--accent)' : 'var(--track)') + ';">' +
      '<span style="position:absolute;top:1.5px;left:' + (on ? '18px' : '2px') + ';width:16px;height:16px;border-radius:50%;background:#fff;transition:left .15s;"></span></button>';
  }

  function settingsDashRows() {
    if (settingsAvail === false) {
      return '<div style="font-size:12px;color:var(--faint);padding:8px 0;">Dashboard settings are not available on this server — start the hub with <code>exalm serve</code>.</div>';
    }
    if (!serverSettings) return '<div style="font-size:12px;color:var(--faint);padding:8px 0;">Loading…</div>';
    var dashes = data.dashboards || [];
    var s = serverSettings;
    var html = '<div style="display:flex;justify-content:space-between;align-items:center;padding:11px 0;border-bottom:1px solid var(--border);">' +
      '<span style="font-size:12.5px;font-weight:600;">Enable all dashboards</span>' + toggleBtn(!!s.dashboards.enableAll, 'set-enable-all') + '</div>';
    if (!dashes.length) {
      html += '<div style="font-size:12px;color:var(--faint);padding:8px 0;">No registered dashboards to configure on this server.</div>';
    } else {
      var enabledCount = dashes.filter(function (d) { return dashEnabled(d.id); }).length;
      html += dashes.map(function (d) {
        var on = dashEnabled(d.id);
        var lastOn = on && enabledCount <= 1;
        return '<div style="display:flex;justify-content:space-between;align-items:center;padding:10px 0;border-bottom:1px solid var(--border);' + (s.dashboards.enableAll ? 'opacity:.5;' : '') + '">' +
          '<div><div style="font-size:12.5px;font-weight:600;">' + esc(d.name) + '</div>' +
          (d.description ? '<div style="font-size:11px;color:var(--faint);">' + esc(d.description) + '</div>' : '') + '</div>' +
          (s.dashboards.enableAll || lastOn ? toggleBtn(on, 'noop') : toggleBtn(on, 'set-dash', d.id)) + '</div>';
      }).join('');
    }
    html += '<div style="display:flex;justify-content:space-between;align-items:center;padding:11px 0;">' +
      '<div><div style="font-size:12.5px;font-weight:600;">AI features</div><div style="font-size:11px;color:var(--faint);">Chat, investigations, and ✦ analyze actions on every dashboard</div></div>' +
      toggleBtn(!!s.supportsAI, 'set-ai') + '</div>';
    return html;
  }

  function dashEnabled(id) {
    var s = serverSettings;
    if (!s || s.dashboards.enableAll) return true;
    var m = s.dashboards.enabled || {};
    return m[id] !== false;
  }

  function loadServerSettings() {
    fetch('/api/settings').then(function (r) {
      if (r.status === 503) { settingsAvail = false; throw new Error('unavailable'); }
      if (!r.ok) throw new Error('http ' + r.status);
      return r.json();
    }).then(function (json) {
      settingsAvail = true; serverSettings = json;
      if (state.page === 'settings') render();
    }).catch(function () {
      if (settingsAvail === null) settingsAvail = false;
      if (state.page === 'settings') render();
    });
  }

  function putServerSettings(next) {
    serverSettings = next; render(); // optimistic
    fetch('/api/settings', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json', 'X-Exalm-Request': 'true' },
      body: JSON.stringify(next)
    }).then(function (r) { if (r.ok) return r.json(); throw new Error('http ' + r.status); })
      .then(function (json) { serverSettings = json; if (state.page === 'settings') render(); })
      .catch(function () { loadServerSettings(); });
  }

  function pageSettings(v) {
    if (settingsAvail === null) loadServerSettings();
    function row(label, val) { return '<div style="display:flex;justify-content:space-between;padding:11px 0;border-bottom:1px solid var(--border);"><span style="color:var(--muted);font-size:12.5px;">' + esc(label) + '</span><span style="font-weight:600;font-size:12.5px;">' + val + '</span></div>'; }
    return '<div style="max-width:560px;">' +
      card(cardLabel('Appearance') +
        '<div style="display:flex;justify-content:space-between;align-items:center;padding:11px 0;border-bottom:1px solid var(--border);"><span style="color:var(--muted);font-size:12.5px;">Theme</span>' +
        '<button data-act="theme" style="display:flex;align-items:center;gap:7px;height:32px;padding:0 13px;border-radius:8px;border:1px solid var(--border);background:var(--panel2);color:var(--fg);font-size:12.5px;font-weight:500;cursor:pointer;">' + (state.theme === 'dark' ? '☀ Light' : '☾ Dark') + '</button></div>' +
        row('Auto-refresh', data.autoRefresh ? '<span style="color:var(--good)">every 30s</span>' : 'static snapshot'), '18px 20px') +
      '<div style="height:14px;"></div>' +
      card(cardLabel('Dashboards') + settingsDashRows(), '18px 20px') +
      '<div style="height:14px;"></div>' +
      card(cardLabel('Environment') +
        row('LLM provider', esc(data.provider || 'llm')) +
        row('Namespaces', v.NS.length) +
        row('Pods (cluster)', fmt(data.pods || 0)) +
        row('Findings', v.totalFindings), '18px 20px') +
      '</div>';
  }

  // ── Page: registry-selected dashboard (registry mode only) ──
  // k8s renders the classic findings dashboard; a live analyzer renders its
  // analyzer page; anything else shows how to attach data.
  function pageDash(v) {
    var d = dashById(state.dash);
    if (!d) return pageDashboard(v);
    if (d.id === 'k8s') return pageDashboard(v);
    if (d.id === data.analyzer || (d.live && d.category === 'analyzer')) return pageAnalyzer(v, d);
    if (d.id === 'incidents') return pageIncidentsShell(d);
    return pageNotLive(d, 'No analysis session is attached. Run <code>exalm ' + esc(d.id) + ' ' + (d.id === 'eventlog' || d.id === 'logs' ? 'summarize' : 'analyze') + ' … --open</code> while this hub is running to attach one.');
  }
  function pageIncidentsShell(d) {
    var header = '<div style="margin-bottom:14px;"><div style="font-size:15px;font-weight:700;">' + esc(d.name) + '</div>' +
      '<div style="font-size:12px;color:var(--muted);">' + esc(d.description || '') + '</div></div>';
    return header + '<div id="incidents-dash-root"></div>';
  }
  function pageNotLive(d, hint) {
    return '<div style="padding:60px 20px;text-align:center;">' +
      '<div style="font-size:15px;font-weight:700;margin-bottom:8px;">' + esc(d.name) + '</div>' +
      '<div style="font-size:12.5px;color:var(--muted);max-width:480px;margin:0 auto;">' + hint + '</div>' +
      (d.widgets && d.widgets.length ? '<div style="margin-top:18px;font-size:11.5px;color:var(--faint);">Widgets: ' + d.widgets.map(function (w) { return esc(w.title); }).join(' · ') + '</div>' : '') +
      '</div>';
  }

  // ── Render shell + page dispatch ──
  function render() {
    var v = computeVals();
    var shell = '<div style="display:flex;min-height:100vh;background:var(--bg);color:var(--fg);font-family:var(--font-sans),system-ui,sans-serif;font-size:14px;">' +
      sidebar() +
      '<div style="flex:1;min-width:0;display:flex;flex-direction:column;">' +
      topbar(v) +
      '<main id="page" style="flex:1;padding:18px 22px;min-width:0;">';
    switch (state.page) {
      case 'explorer': shell += pageExplorer(v); break;
      case 'ai': shell += pageAI(v); break;
      case 'alerts': shell += pageAlerts(v); break;
      case 'settings': shell += pageSettings(v); break;
      case 'dash': shell += pageDash(v); break;
      default: shell += data.analyzer ? pageAnalyzer(v) : pageDashboard(v);
    }
    shell += '</main>' +
      '<footer style="display:flex;align-items:center;gap:8px;padding:10px 22px;border-top:1px solid var(--border);color:var(--faint);font-size:11.5px;"><span>exalm.com</span><span style="flex:1;"></span>' +
      (data.autoRefresh ? '<span style="display:inline-block;width:11px;height:11px;border:1.6px solid var(--faint);border-top-color:transparent;border-radius:50%;animation:ex-spin 1s linear infinite;"></span><span>auto-refreshes every 30s</span>' : '<span>static snapshot — re-run analyze to update</span>') +
      '</footer></div></div>';

    var app = document.getElementById('app');
    var active = document.activeElement;
    var activeId = active && active.id;
    var refocus = REFOCUS_TEXT_IDS.indexOf(activeId) !== -1;
    var caret = refocus ? active.selectionStart : 0;
    app.innerHTML = shell;
    if (refocus) {
      var inp = document.getElementById(activeId);
      if (inp) { inp.focus(); try { inp.setSelectionRange(caret, caret); } catch (e) {} }
    }
    if (window.ExalmWidgets && window.ExalmWidgets.attachTooltips) window.ExalmWidgets.attachTooltips();
    if (window.ExalmChat && window.ExalmChat.attach) window.ExalmChat.attach();
    fillAnalyzerDash();
    fillWorkspace();
  }

  function fixBtn(f, isFixed, isFixing, large) {
    var base = 'font-family:inherit;font-weight:600;border-radius:7px;cursor:pointer;flex:none;border:1px solid var(--border);transition:all .15s;';
    var label, extra;
    if (isFixed) { extra = 'background:var(--good);color:#06281b;border:none;'; label = 'Fixed ✓'; }
    else if (isFixing) { extra = 'background:var(--track);color:var(--muted);'; label = large ? 'Applying fix…' : 'Fixing…'; }
    else { extra = 'background:var(--accent);color:#04222b;border:none;'; label = large ? 'Apply fix' : 'Fix'; }
    var pad = large ? (isFixed || isFixing ? 'padding:6px 14px;' : 'padding:6px 16px;') : (isFixed || isFixing ? 'padding:4px 10px;' : 'padding:4px 12px;');
    var size = large ? 'font-size:12px;' : 'font-size:11px;';
    // "remediate" opens the explainable remediation panel (does NOT execute);
    // the panel confirms before applying. Falls back to direct apply if the
    // panels module isn't loaded.
    return '<button data-act="remediate" data-id="' + esc(f.id) + '" style="' + base + extra + pad + size + '">' + label + '</button>';
  }

  function confColor(c) {
    return c === 'high' ? 'var(--good)' : c === 'medium' ? 'var(--high)' : 'var(--muted)';
  }

  function setPage(p) {
    if (PAGES.indexOf(p) === -1) return;
    state.page = p; state.nsMenuOpen = false;
    try { localStorage.setItem(PAGE_KEY, p); } catch (e) {}
    render();
  }

  function setDash(id) {
    if (!dashById(id)) return;
    state.page = 'dash'; state.dash = id; state.nsMenuOpen = false;
    try { localStorage.setItem(DASH_KEY, id); localStorage.setItem(PAGE_KEY, 'dashboard'); } catch (e) {}
    render();
  }

  // ── Event delegation ──
  function onClick(e) {
    var el = e.target.closest ? e.target.closest('[data-act]') : null;
    if (!el) {
      if (state.nsMenuOpen) { state.nsMenuOpen = false; render(); }
      return;
    }
    var act = el.getAttribute('data-act');
    switch (act) {
      case 'nav': setPage(el.getAttribute('data-page')); break;
      case 'nav-dash': setDash(el.getAttribute('data-dash')); break;
      case 'ns-toggle': state.nsMenuOpen = !state.nsMenuOpen; render(); break;
      case 'ns-select': state.selectedNs = el.getAttribute('data-ns'); state.nsMenuOpen = false; render(); break;
      case 'theme': state.theme = state.theme === 'dark' ? 'light' : 'dark'; try { localStorage.setItem(THEME_KEY, state.theme); } catch (x) {} applyTheme(); render(); break;
      case 'set-enable-all': if (serverSettings) { var sA = JSON.parse(JSON.stringify(serverSettings)); sA.dashboards.enableAll = !sA.dashboards.enableAll; putServerSettings(sA); } break;
      case 'set-dash': if (serverSettings) { var sD = JSON.parse(JSON.stringify(serverSettings)); sD.dashboards.enabled = sD.dashboards.enabled || {}; var did = el.getAttribute('data-id'); sD.dashboards.enabled[did] = !dashEnabled(did); putServerSettings(sD); } break;
      case 'set-ai': if (serverSettings) { var sI = JSON.parse(JSON.stringify(serverSettings)); sI.supportsAI = !sI.supportsAI; putServerSettings(sI); } break;
      case 'noop': break;
      case 'fixall': fixAll(); break;
      case 'freqscope': state.freqScope = el.getAttribute('data-v'); render(); break;
      case 'reanalyze': refresh(); break;
      case 'finding-toggle': { var id = el.getAttribute('data-id'); state.openFinding = state.openFinding === id ? null : id; render(); break; }
      case 'fix': e.stopPropagation(); fix(el.getAttribute('data-id')); break;
      case 'remediate':
        e.stopPropagation();
        if (window.ExalmPanels) window.ExalmPanels.openRemediation(el.getAttribute('data-id'));
        else fix(el.getAttribute('data-id')); // fallback: direct apply
        break;
      case 'investigate':
        e.stopPropagation();
        if (window.ExalmPanels) window.ExalmPanels.openInvestigation(el.getAttribute('data-id'));
        break;
      case 'logs': if (window.ExalmLogs) window.ExalmLogs.open(); break;
      case 'drilldown': if (window.ExalmPanels) window.ExalmPanels.openDrilldown({ kind: el.getAttribute('data-kind'), label: el.getAttribute('data-label') }); break;
      case 'filter': state.filter = el.getAttribute('data-f'); render(); break;
      case 'sort': {
        var key = el.getAttribute('data-key');
        state.sort = { by: key, dir: state.sort.by === key ? (state.sort.dir === 'asc' ? 'desc' : 'asc') : SORT_DEFAULT_DIR[key] };
        render();
        break;
      }
      case 'statcard':
        state.filter = el.getAttribute('data-f') || 'all';
        state.query = '';
        setPage('explorer');
        break;
      case 'incident-open': openIncidentDraft(); break;
      case 'incident-close': e.stopPropagation(); closeIncidentAction(el.getAttribute('data-id')); break;
      case 'incident-reopen': e.stopPropagation(); reopenIncidentAction(el.getAttribute('data-id')); break;
      case 'incident-filter':
        state.incidentFilter = state.incidentFilter === el.getAttribute('data-status') ? '' : el.getAttribute('data-status');
        render();
        break;
    }
  }
  function onInput(e) {
    if (!e.target) return;
    switch (e.target.id) {
      case 'finding-search': state.query = e.target.value; render(); break;
      case 'incident-title': state.incidentDraft.title = e.target.value; render(); break;
      case 'incident-namespace': state.incidentDraft.namespace = e.target.value; render(); break;
      case 'incident-service': state.incidentDraft.service = e.target.value; render(); break;
      case 'incident-severity': state.incidentDraft.severity = e.target.value; render(); break;
    }
  }

  // ── Shared evidence/fix-card renderers ──
  // Used by panels.js (remediation/investigation panels) AND chat.js (the
  // conversation workspace), so there is exactly one implementation of each.
  var SHARED_CARD = 'background:var(--panel2);border:1px solid var(--border);border-radius:10px;padding:11px 13px;';
  var SHARED_LBL = 'font-size:10px;text-transform:uppercase;letter-spacing:.6px;color:var(--faint);font-weight:600;';

  function sharedSevColor(sev) { return sevMeta(sev).c; }
  function sharedConfBadge(c) {
    if (!c) return '';
    return '<span style="font-size:9px;font-weight:700;text-transform:uppercase;letter-spacing:.4px;padding:2px 8px;border-radius:20px;background:var(--track);color:' + confColor(c) + ';">' + esc(c) + ' confidence</span>';
  }
  function sharedEvidenceHTML(items) {
    if (!items || !items.length) return '<div style="color:var(--muted);font-size:12.5px;">No evidence captured.</div>';
    var icon = { log: '📝', event: '⚡', metric: '📊', change: '↺' };
    return items.map(function (e) {
      var anchor = e.anchor ? '<div style="margin-top:5px;display:flex;gap:6px;align-items:center;"><code style="font-family:var(--font-mono),monospace;font-size:11px;background:var(--track);padding:2px 7px;border-radius:5px;color:var(--accent);flex:1;overflow:auto;">' + esc(e.anchor) + '</code><button class="ex-copy" data-copy="' + esc(e.anchor) + '" style="border:1px solid var(--border);background:var(--panel);color:var(--muted);border-radius:6px;cursor:pointer;font-size:10px;padding:3px 8px;">copy</button></div>' : '';
      return '<div style="' + SHARED_CARD + 'margin-bottom:8px;"><div style="display:flex;gap:8px;align-items:center;"><span>' + (icon[e.kind] || '•') + '</span><span style="' + SHARED_LBL + '">' + esc(e.kind) + ' · ' + esc(e.source) + '</span></div>' +
        (e.excerpt ? '<pre style="margin:6px 0 0;white-space:pre-wrap;font-family:var(--font-mono),monospace;font-size:11px;color:var(--codeFg);line-height:1.45;">' + esc(e.excerpt) + '</pre>' : '') +
        anchor + '</div>';
    }).join('');
  }
  function sharedFixCardHTML(fx, findingID) {
    var preview = [['Risk', fx.risk], ['Downtime', fx.downtime], ['Rollback', fx.rollback], ['Expected', fx.expectedOutcome]]
      .filter(function (p) { return p[1]; })
      .map(function (p) { return '<div><div style="' + SHARED_LBL + '">' + p[0] + '</div><div style="font-size:12px;margin-top:1px;">' + esc(p[1]) + '</div></div>'; })
      .join('');
    var cmd = fx.kubectlCmd ? '<div style="margin-top:8px;display:flex;gap:6px;align-items:center;"><code style="font-family:var(--font-mono),monospace;font-size:11px;background:var(--track);padding:3px 8px;border-radius:5px;color:var(--accent);flex:1;overflow:auto;">' + esc(fx.kubectlCmd) + '</code><button class="ex-copy" data-copy="' + esc(fx.kubectlCmd) + '" style="border:1px solid var(--border);background:var(--panel);color:var(--muted);border-radius:6px;cursor:pointer;font-size:10px;padding:3px 8px;">copy</button></div>' : '';
    var action = fx.applicable
      ? '<button class="ex-apply" data-id="' + esc(findingID) + '" style="margin-top:10px;border:none;background:var(--accent);color:#fff;border-radius:8px;cursor:pointer;font-size:12px;font-weight:600;padding:7px 16px;">Apply this fix</button>'
      : '<div style="margin-top:8px;font-size:11.5px;color:var(--muted);">Review and apply manually — Exalm will not auto-execute this change.</div>';
    return '<div style="' + SHARED_CARD + 'margin-bottom:10px;border-left:3px solid ' + (fx.fixType === 'root-cause' ? 'var(--good)' : 'var(--high)') + ';">' +
      '<div style="font-size:13px;font-weight:600;">' + esc(fx.description || fx.kind) + '</div>' +
      (preview ? '<div style="display:grid;grid-template-columns:repeat(2,1fr);gap:8px;margin-top:9px;">' + preview + '</div>' : '') +
      cmd + action + '</div>';
  }
  function sharedSplitFixes(fixes) {
    var temp = [], root = [];
    (fixes || []).forEach(function (fx) { (fx.fixType === 'root-cause' ? root : temp).push(fx); });
    return { temp: temp, root: root };
  }
  function sharedFixSectionsHTML(fixes, findingID) {
    var s = sharedSplitFixes(fixes);
    var out = '';
    out += '<h4 style="margin:16px 0 8px;font-size:12px;text-transform:uppercase;letter-spacing:.5px;color:var(--high);">Temporary mitigation</h4>';
    out += s.temp.length ? s.temp.map(function (fx) { return sharedFixCardHTML(fx, findingID); }).join('')
      : '<div style="color:var(--muted);font-size:12.5px;">No temporary mitigation — address the root cause directly.</div>';
    out += '<h4 style="margin:18px 0 8px;font-size:12px;text-transform:uppercase;letter-spacing:.5px;color:var(--good);">Root cause fix <span style="font-weight:400;text-transform:none;color:var(--muted);">— the real solution</span></h4>';
    out += s.root.length ? s.root.map(function (fx) { return sharedFixCardHTML(fx, findingID); }).join('')
      : '<div style="color:var(--muted);font-size:12.5px;">No distinct root-cause fix identified — run an investigation for deeper analysis.</div>';
    return out;
  }
  function sharedWireCopyButtons(root) {
    root.querySelectorAll('.ex-copy').forEach(function (b) {
      b.addEventListener('click', function () { try { navigator.clipboard.writeText(b.getAttribute('data-copy')); b.textContent = 'copied'; setTimeout(function () { b.textContent = 'copy'; }, 1200); } catch (e) {} });
    });
  }

  // ── Shared API for the panel/chart/log/chat modules ──
  window.Exalm = {
    esc: esc, fmt: fmt, css: css, sevMeta: sevMeta, mdToHtml: mdToHtml, confColor: confColor,
    data: function () { return data; },
    state: state,
    namespaces: function () { return data.namespaces || []; },
    findings: function () { return data.findings || []; },
    finding: function (id) { return (data.findings || []).filter(function (f) { return f.id === id; })[0]; },
    refresh: refresh,
    applyPrimaryFix: fix,
    legacyNarrativeHTML: legacyNarrativeHTML,
    // shared rendering — single implementation used by panels.js and chat.js
    cardStyle: SHARED_CARD, lblStyle: SHARED_LBL,
    sevColor: sharedSevColor, confBadge: sharedConfBadge,
    evidenceHTML: sharedEvidenceHTML, fixCardHTML: sharedFixCardHTML,
    fixSectionsHTML: sharedFixSectionsHTML, wireCopyButtons: sharedWireCopyButtons
  };

  // ── Boot ──
  // Registry mode: the "dashboard" page becomes a dashboard selection. Map
  // the saved page (or default) onto a valid dashboard id.
  if (dashList()) {
    if (state.page === 'dashboard' || state.page === 'dash') {
      state.page = 'dash';
      if (!dashById(state.dash) || dashById(state.dash).standalone) state.dash = defaultDash();
    }
    if (!dashById('k8s') && (state.page === 'explorer' || state.page === 'ai' || state.page === 'alerts')) {
      state.page = 'dash'; state.dash = defaultDash();
    }
  }
  applyTheme();
  render();
  document.getElementById('app').addEventListener('click', onClick);
  document.getElementById('app').addEventListener('input', onInput);
  document.getElementById('app').addEventListener('change', onInput);
  if (data.autoRefresh) setInterval(refresh, 30000);
})();
