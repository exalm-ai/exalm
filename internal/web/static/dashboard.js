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

  var THEMES = {
    dark: {
      '--bg': '#070b14', '--panel': '#0e1626', '--panel2': '#131f33', '--border': '#1f2c44',
      '--sidebar': '#0a1120', '--track': '#17243a', '--code': '#070c15', '--codeFg': '#9fb6cf', '--scroll': '#243348',
      '--fg': '#e8eef6', '--body': '#c2cfde', '--muted': '#8294aa', '--faint': '#5b6c83',
      '--accent': '#22b8e6', '--accentGlow': 'rgba(34,184,230,.45)', '--accentSoft': 'rgba(34,184,230,.14)',
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
  var savedTheme = 'dark', savedPage = 'dashboard';
  try { var t0 = localStorage.getItem(THEME_KEY); if (t0 === 'light' || t0 === 'dark') savedTheme = t0; } catch (e) {}
  try { var p0 = localStorage.getItem(PAGE_KEY); if (PAGES.indexOf(p0) !== -1) savedPage = p0; } catch (e) {}

  var state = {
    theme: savedTheme, page: savedPage, query: '', filter: 'all', range: '24h',
    freqScope: 'cluster', selectedNs: 'all', nsMenuOpen: false,
    openGroups: { Pods: true, Resources: true }, openFinding: null,
    fixed: {}, fixing: {}
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
    s = s.replace(/`([^`]+)`/g, '<code style="font-family:\'IBM Plex Mono\',monospace;font-size:11.5px;background:var(--track);padding:1px 6px;border-radius:5px;color:var(--accent);">$1</code>');
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

    // Flattened, filtered rows in group order — for the Log Explorer table.
    var rows = [];
    groups.forEach(function (g) { g.items.forEach(function (f) { rows.push(f); }); });

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
      return '<div style="' + box + 'border-left:3px solid ' + m.c + ';"><div style="display:flex;justify-content:space-between;gap:10px;"><strong style="color:var(--fg)">' + esc(f.title) + '</strong><span style="font-family:\'IBM Plex Mono\',monospace;font-size:11px;color:var(--faint);white-space:nowrap;">' + esc(f.restarts !== '—' ? f.restarts + ' restarts' : f.nsKey) + '</span></div><div style="color:var(--muted);margin-top:4px;">' + esc(f.reason) + '</div></div>';
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
    }
    return '';
  }

  // ── Sidebar ──
  function sidebar() {
    var items = [['dashboard', 'Dashboard'], ['explorer', 'Log Explorer'], ['ai', 'AI Analysis'], ['alerts', 'Alerts'], ['settings', 'Settings']];
    var nav = items.map(function (it) {
      var active = state.page === it[0];
      return '<button data-act="nav" data-page="' + it[0] + '" style="display:flex;align-items:center;gap:12px;width:100%;padding:10px 14px;border:none;border-left:3px solid ' + (active ? 'var(--accent)' : 'transparent') + ';cursor:pointer;font-family:inherit;font-size:13.5px;font-weight:' + (active ? '600' : '500') + ';text-align:left;background:' + (active ? 'var(--accentSoft)' : 'transparent') + ';color:' + (active ? 'var(--accent)' : SIDEBAR_MUTED) + ';">' +
        '<span style="display:flex;width:18px;height:18px;flex:none;">' + icon(it[0]) + '</span><span>' + it[1] + '</span></button>';
    }).join('');
    return '<aside class="ex-sidebar" style="width:230px;flex:none;background:var(--sidebar);border-right:1px solid var(--border);display:flex;flex-direction:column;position:sticky;top:0;height:100vh;">' +
      '<div style="display:flex;align-items:center;gap:10px;padding:18px 16px 16px;">' +
      '<div style="width:30px;height:30px;border-radius:8px;background:linear-gradient(135deg,var(--accent),#7b5bff);display:flex;align-items:center;justify-content:center;box-shadow:0 0 16px var(--accentGlow);"><div style="width:11px;height:11px;border-radius:3px;background:#fff;"></div></div>' +
      '<div class="ex-brand-text"><div style="font-weight:700;font-size:15px;letter-spacing:-.2px;color:' + SIDEBAR_FG + ';">Exalm</div><div style="font-size:9.5px;letter-spacing:1px;text-transform:uppercase;color:' + SIDEBAR_MUTED + ';">K8s Analyzer</div></div></div>' +
      '<nav style="display:flex;flex-direction:column;gap:2px;margin-top:6px;">' + nav + '</nav>' +
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
      '<span style="font-family:\'IBM Plex Mono\',monospace;">' + esc(v.nsLabel) + '</span>' +
      '<span style="font-size:9px;color:var(--faint);transform:' + (state.nsMenuOpen ? 'rotate(180deg)' : 'none') + ';transition:transform .2s;">▾</span></button>';
    if (state.nsMenuOpen) {
      html += '<div style="position:absolute;top:40px;right:0;min-width:230px;background:var(--panel);border:1px solid var(--border);border-radius:10px;box-shadow:0 12px 34px rgba(0,0,0,.45);padding:5px;z-index:50;">';
      nsMenuRows.forEach(function (n) {
        var active = state.selectedNs === n.key;
        html += '<button data-act="ns-select" data-ns="' + esc(n.key) + '" style="display:flex;align-items:center;gap:9px;width:100%;padding:7px 9px;border-radius:7px;border:none;cursor:pointer;background:' + (active ? 'var(--panel2)' : 'transparent') + ';color:var(--fg);">' +
          '<span style="width:8px;height:8px;border-radius:2px;background:' + n.color + ';flex:none;"></span>' +
          '<span style="flex:1;text-align:left;font-family:\'IBM Plex Mono\',monospace;font-size:12.5px;">' + esc(n.label) + '</span>' +
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
      settings: ['Settings', 'Theme and environment']
    }[state.page] || ['Dashboard', ''];
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

  // ── Stat cards ──
  function statCards(v) {
    var cards = [
      ['Total findings', v.totalFindings, 'var(--accent)'],
      ['Errors / high', v.sevCounts.high, 'var(--high)'],
      ['Critical', v.sevCounts.crit, 'var(--crit)'],
      ['Warnings / med', v.sevCounts.med, 'var(--med)'],
      ['Namespaces', v.NS.length, 'var(--low)']
    ];
    return '<div class="ex-statcards" style="display:grid;grid-template-columns:repeat(5,1fr);gap:14px;margin-bottom:16px;">' +
      cards.map(function (c) {
        return '<div style="background:var(--panel);border:1px solid var(--border);border-radius:14px;padding:15px 16px;">' +
          '<div style="display:flex;justify-content:space-between;align-items:center;">' + cardLabel(c[0]) + '<span style="width:8px;height:8px;border-radius:2px;background:' + c[2] + ';"></span></div>' +
          '<div style="font-size:30px;font-weight:700;line-height:1;margin-top:12px;font-variant-numeric:tabular-nums;">' + fmt(c[1]) + '</div></div>';
      }).join('') + '</div>';
  }

  // ── Severity donut + legend ──
  function severityDonut(v) {
    var legend = [['Critical', 'crit', v.sevCounts.crit], ['High', 'high', v.sevCounts.high], ['Medium', 'med', v.sevCounts.med], ['Low', 'low', v.sevCounts.low]];
    return card(cardLabel('Severity distribution') +
      '<div style="display:flex;align-items:center;gap:18px;margin-top:14px;flex-wrap:wrap;justify-content:center;">' +
      '<svg width="150" height="150" viewBox="0 0 80 80" style="flex:none;"><g transform="rotate(-90 40 40)"><circle cx="40" cy="40" r="34" fill="none" stroke="var(--track)" stroke-width="9"></circle>' +
      v.ringSegs.map(function (r) { return '<circle cx="40" cy="40" r="34" fill="none" stroke="' + r.color + '" stroke-width="9" stroke-dasharray="' + r.dash + '" stroke-dashoffset="' + r.offset + '"></circle>'; }).join('') +
      '</g><text x="40" y="38" text-anchor="middle" font-size="16" font-weight="700" fill="var(--fg)">' + v.totalFindings + '</text><text x="40" y="50" text-anchor="middle" font-size="6.5" fill="var(--faint)" letter-spacing="1">FINDINGS</text></svg>' +
      '<div style="display:flex;flex-direction:column;gap:8px;font-size:12.5px;min-width:130px;">' +
      legend.map(function (x) { return '<div style="display:flex;align-items:center;gap:8px;"><span style="width:9px;height:9px;border-radius:2px;background:var(--' + x[1] + ');"></span><span style="color:var(--muted);flex:1;">' + x[0] + '</span><b>' + x[2] + '</b></div>'; }).join('') +
      '</div></div>');
  }

  // ── Logs by namespace (horizontal bars) ──
  function nsBars(v) {
    var max = Math.max.apply(null, v.NS.map(function (n) { return n.findings; }).concat([1]));
    var rows = v.NS.slice().sort(function (a, b) { return b.findings - a.findings; }).slice(0, 9).map(function (n) {
      var active = state.selectedNs === n.key;
      return '<button data-act="ns-select" data-ns="' + esc(n.key) + '" style="display:flex;align-items:center;gap:10px;width:100%;border:none;background:transparent;cursor:pointer;padding:3px 0;">' +
        '<span style="width:120px;text-align:right;font-family:\'IBM Plex Mono\',monospace;font-size:11px;color:' + (active ? 'var(--accent)' : 'var(--muted)') + ';white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">' + esc(n.key) + '</span>' +
        '<span style="flex:1;height:14px;background:var(--track);border-radius:4px;overflow:hidden;"><span style="display:block;height:100%;width:' + Math.max(4, (n.findings / max) * 100) + '%;background:' + n.color + ';border-radius:4px;transition:width .3s;"></span></span>' +
        '<span style="width:26px;text-align:left;font-size:11px;font-weight:600;color:var(--fg);">' + n.findings + '</span></button>';
    }).join('');
    return card(cardLabel('Findings by namespace') + '<div style="display:flex;flex-direction:column;gap:6px;margin-top:14px;">' + (rows || '<div style="color:var(--faint);font-size:12px;">No namespaces.</div>') + '</div>');
  }

  // ── Error frequency time-series (Cluster/Namespace toggle) ──
  function errorFreq(v) {
    var toggle = ['cluster', 'namespace'].map(function (k) {
      var a = state.freqScope === k;
      return '<button data-act="freqscope" data-v="' + k + '" style="padding:4px 11px;border-radius:7px;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.4px;cursor:pointer;border:1px solid ' + (a ? 'var(--accent)' : 'var(--border)') + ';background:' + (a ? 'var(--accentSoft)' : 'transparent') + ';color:' + (a ? 'var(--accent)' : 'var(--muted)') + ';">' + k + '</button>';
    }).join('');
    var legend = [['crit', 'critical'], ['high', 'high'], ['med', 'medium'], ['low', 'low']].map(function (x) { return '<span style="display:flex;align-items:center;gap:5px;font-size:10.5px;color:var(--muted);"><span style="width:8px;height:8px;border-radius:2px;background:var(--' + x[0] + ');"></span>' + x[1] + '</span>'; }).join('');
    var bars = v.tsBars.map(function (b) {
      return '<div class="ex-chart-bar" data-act="drilldown" data-kind="time" data-label="' + esc(b.title) + '" title="' + esc(b.title) + '" style="flex:1;display:flex;flex-direction:column;justify-content:flex-end;min-width:0;cursor:pointer;">' +
        b.segs.map(function (sg) { return '<div style="width:100%;height:' + sg.h + 'px;background:' + sg.bg + ';border-radius:' + (sg.first ? '3px 3px 0 0' : '0') + ';"></div>'; }).join('') + '</div>';
    }).join('');
    return card('<div style="display:flex;align-items:center;justify-content:space-between;gap:10px;flex-wrap:wrap;margin-bottom:8px;">' +
      '<div>' + cardLabel('Error frequency · last 24h') + '<div style="font-size:11px;color:var(--muted);margin-top:2px;">Findings trend ' + (state.freqScope === 'namespace' && !v.allMode ? 'by namespace · ' + esc(v.nsLabel) : 'by cluster') + '</div></div>' +
      '<div style="display:flex;gap:6px;">' + toggle + '</div></div>' +
      '<div style="display:flex;gap:14px;margin-bottom:8px;">' + legend + '</div>' +
      '<div style="display:flex;align-items:flex-end;gap:3px;height:150px;">' + bars + '</div>' +
      '<div style="display:flex;justify-content:space-between;margin-top:7px;font-family:\'IBM Plex Mono\',monospace;font-size:10px;color:var(--faint);"><span>00:00</span><span>06:00</span><span>12:00</span><span>18:00</span><span>now</span></div>');
  }

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
    var head = '<tr><th style="' + th + '">Severity</th><th style="' + th + '">Namespace / Pod</th><th style="' + th + 'width:42%;">Message</th><th style="' + th + '">Category</th><th style="' + th + 'text-align:right;">Action</th></tr>';
    var rows = v.rows.map(function (f) {
      var m = sevMeta(f.sev), isFixed = !!state.fixed[f.id], isFixing = !!state.fixing[f.id];
      var td = 'padding:11px 14px;border-bottom:1px solid var(--border);vertical-align:top;';
      var status = isFixed ? '<span style="font-size:9.5px;font-weight:700;color:var(--good);background:var(--track);padding:2px 8px;border-radius:20px;">FIXED ✓</span>' : '';
      return '<tr data-act="remediate" data-id="' + esc(f.id) + '" style="cursor:pointer;" class="ex-row">' +
        '<td style="' + td + '"><span style="font-size:9px;font-weight:700;letter-spacing:.5px;padding:2px 7px;border-radius:5px;color:' + m.c + ';background:' + m.soft + ';border:1px solid ' + m.line + ';white-space:nowrap;">' + m.label + '</span></td>' +
        '<td style="' + td + 'font-family:\'IBM Plex Mono\',monospace;font-size:11px;color:var(--muted);white-space:nowrap;">' + esc(f.ns) + '</td>' +
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

  // ── Page: AI Analysis — two-pane investigation workspace ──
  // Left: the cumulative investigation tree (tree.js). Right: the chat.
  function pageAI(v) {
    var header = '<div style="display:flex;align-items:center;gap:12px;margin-bottom:14px;">' +
      '<span style="width:34px;height:34px;border-radius:9px;background:linear-gradient(135deg,#7b5bff,var(--accent));display:flex;align-items:center;justify-content:center;color:#fff;">' + icon('ai') + '</span>' +
      '<div style="flex:1;"><div style="font-size:14px;font-weight:700;">Investigation assistant</div><div style="font-size:12px;color:var(--muted);">Ask follow-ups — Exalm plans the investigation, gathers evidence across the cluster, and remembers it all, scoped to ' + esc(v.nsLabel) + '</div></div>' +
      '<button data-act="reanalyze" style="display:flex;align-items:center;gap:8px;height:36px;padding:0 16px;border-radius:9px;border:none;background:var(--accent);color:#04222b;font-size:12.5px;font-weight:700;cursor:pointer;">✦ Re-analyze ' + v.totalFindings + ' findings</button></div>';
    return card(header +
      '<div class="ex-ai-grid" style="display:grid;grid-template-columns:minmax(280px,34%) 1fr;gap:16px;">' +
      '<div id="ai-tree-root" style="min-width:0;border-right:1px solid var(--border);padding-right:14px;max-height:62vh;overflow-y:auto;"></div>' +
      '<div id="ai-chat-root" style="min-width:0;"></div>' +
      '</div>', '18px 20px');
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
        '<div style="font-family:\'IBM Plex Mono\',monospace;font-size:11px;color:var(--faint);margin-top:4px;">' + esc(f.ns) + '</div></div>';
    }).join('');
    return head + cards;
  }

  // ── Page: Settings (read-only) ──
  function pageSettings(v) {
    function row(label, val) { return '<div style="display:flex;justify-content:space-between;padding:11px 0;border-bottom:1px solid var(--border);"><span style="color:var(--muted);font-size:12.5px;">' + esc(label) + '</span><span style="font-weight:600;font-size:12.5px;">' + val + '</span></div>'; }
    return '<div style="max-width:560px;">' +
      card(cardLabel('Appearance') +
        '<div style="display:flex;justify-content:space-between;align-items:center;padding:11px 0;border-bottom:1px solid var(--border);"><span style="color:var(--muted);font-size:12.5px;">Theme</span>' +
        '<button data-act="theme" style="display:flex;align-items:center;gap:7px;height:32px;padding:0 13px;border-radius:8px;border:1px solid var(--border);background:var(--panel2);color:var(--fg);font-size:12.5px;font-weight:500;cursor:pointer;">' + (state.theme === 'dark' ? '☀ Light' : '☾ Dark') + '</button></div>' +
        row('Auto-refresh', data.autoRefresh ? '<span style="color:var(--good)">every 30s</span>' : 'static snapshot'), '18px 20px') +
      '<div style="height:14px;"></div>' +
      card(cardLabel('Environment') +
        row('LLM provider', esc(data.provider || 'llm')) +
        row('Namespaces', v.NS.length) +
        row('Pods (cluster)', fmt(data.pods || 0)) +
        row('Findings', v.totalFindings), '18px 20px') +
      '<div style="margin-top:12px;font-size:11.5px;color:var(--faint);">Settings are read-only here — configure Exalm via CLI flags / environment variables.</div>' +
      '</div>';
  }

  // ── Render shell + page dispatch ──
  function render() {
    var v = computeVals();
    var shell = '<div style="display:flex;min-height:100vh;background:var(--bg);color:var(--fg);font-family:\'IBM Plex Sans\',system-ui,sans-serif;font-size:14px;">' +
      sidebar() +
      '<div style="flex:1;min-width:0;display:flex;flex-direction:column;">' +
      topbar(v) +
      '<main id="page" style="flex:1;padding:18px 22px;min-width:0;">';
    switch (state.page) {
      case 'explorer': shell += pageExplorer(v); break;
      case 'ai': shell += pageAI(v); break;
      case 'alerts': shell += pageAlerts(v); break;
      case 'settings': shell += pageSettings(v); break;
      default: shell += pageDashboard(v);
    }
    shell += '</main>' +
      '<footer style="display:flex;align-items:center;gap:8px;padding:10px 22px;border-top:1px solid var(--border);color:var(--faint);font-size:11.5px;"><span>exalm.com</span><span style="flex:1;"></span>' +
      (data.autoRefresh ? '<span style="display:inline-block;width:11px;height:11px;border:1.6px solid var(--faint);border-top-color:transparent;border-radius:50%;animation:ex-spin 1s linear infinite;"></span><span>auto-refreshes every 30s</span>' : '<span>static snapshot — re-run analyze to update</span>') +
      '</footer></div></div>';

    var app = document.getElementById('app');
    var active = document.activeElement;
    var refocus = active && active.id === 'finding-search';
    var caret = refocus ? active.selectionStart : 0;
    app.innerHTML = shell;
    if (refocus) {
      var inp = document.getElementById('finding-search');
      if (inp) { inp.focus(); try { inp.setSelectionRange(caret, caret); } catch (e) {} }
    }
    if (window.ExalmCharts && window.ExalmCharts.attach) window.ExalmCharts.attach();
    if (window.ExalmChat && window.ExalmChat.attach) window.ExalmChat.attach();
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
      case 'ns-toggle': state.nsMenuOpen = !state.nsMenuOpen; render(); break;
      case 'ns-select': state.selectedNs = el.getAttribute('data-ns'); state.nsMenuOpen = false; render(); break;
      case 'theme': state.theme = state.theme === 'dark' ? 'light' : 'dark'; try { localStorage.setItem(THEME_KEY, state.theme); } catch (x) {} applyTheme(); render(); break;
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
    }
  }
  function onInput(e) {
    if (e.target && e.target.id === 'finding-search') { state.query = e.target.value; render(); }
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
      var anchor = e.anchor ? '<div style="margin-top:5px;display:flex;gap:6px;align-items:center;"><code style="font-family:\'IBM Plex Mono\',monospace;font-size:11px;background:var(--track);padding:2px 7px;border-radius:5px;color:var(--accent);flex:1;overflow:auto;">' + esc(e.anchor) + '</code><button class="ex-copy" data-copy="' + esc(e.anchor) + '" style="border:1px solid var(--border);background:var(--panel);color:var(--muted);border-radius:6px;cursor:pointer;font-size:10px;padding:3px 8px;">copy</button></div>' : '';
      return '<div style="' + SHARED_CARD + 'margin-bottom:8px;"><div style="display:flex;gap:8px;align-items:center;"><span>' + (icon[e.kind] || '•') + '</span><span style="' + SHARED_LBL + '">' + esc(e.kind) + ' · ' + esc(e.source) + '</span></div>' +
        (e.excerpt ? '<pre style="margin:6px 0 0;white-space:pre-wrap;font-family:\'IBM Plex Mono\',monospace;font-size:11px;color:var(--codeFg);line-height:1.45;">' + esc(e.excerpt) + '</pre>' : '') +
        anchor + '</div>';
    }).join('');
  }
  function sharedFixCardHTML(fx, findingID) {
    var preview = [['Risk', fx.risk], ['Downtime', fx.downtime], ['Rollback', fx.rollback], ['Expected', fx.expectedOutcome]]
      .filter(function (p) { return p[1]; })
      .map(function (p) { return '<div><div style="' + SHARED_LBL + '">' + p[0] + '</div><div style="font-size:12px;margin-top:1px;">' + esc(p[1]) + '</div></div>'; })
      .join('');
    var cmd = fx.kubectlCmd ? '<div style="margin-top:8px;display:flex;gap:6px;align-items:center;"><code style="font-family:\'IBM Plex Mono\',monospace;font-size:11px;background:var(--track);padding:3px 8px;border-radius:5px;color:var(--accent);flex:1;overflow:auto;">' + esc(fx.kubectlCmd) + '</code><button class="ex-copy" data-copy="' + esc(fx.kubectlCmd) + '" style="border:1px solid var(--border);background:var(--panel);color:var(--muted);border-radius:6px;cursor:pointer;font-size:10px;padding:3px 8px;">copy</button></div>' : '';
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
  applyTheme();
  render();
  document.getElementById('app').addEventListener('click', onClick);
  document.getElementById('app').addEventListener('input', onInput);
  if (data.autoRefresh) setInterval(refresh, 30000);
})();
