'use strict';
// Exalm dashboard — vanilla-JS port of the redesign prototype, wired to the
// real backend (/api/dashboard). All derived values mirror the reference's
// renderVals(); the namespace selector and filters operate client-side for
// instant response. Live updates re-fetch /api/dashboard and re-render in
// place, preserving client-side state (theme, selection, fix progress).

(function () {
  var THEME_KEY = 'exalm.theme';
  var GROUP_ORDER = ['Other', 'Pods', 'Resources', 'Security', 'Services', 'Workloads'];

  var THEMES = {
    dark: {
      '--bg': '#0b0e14', '--panel': '#11161f', '--panel2': '#161c27', '--border': '#222b3a',
      '--track': '#1e2737', '--code': '#0a0d13', '--codeFg': '#9fb0c3', '--scroll': '#2a3343',
      '--fg': '#e6edf3', '--body': '#c4cfdc', '--muted': '#8b97a7', '--faint': '#5b6675',
      '--accent': '#4c8dff', '--accentGlow': 'rgba(76,141,255,.45)',
      '--crit': '#ff5d5d', '--high': '#ff9f45', '--med': '#f5c542', '--low': '#5b9bff', '--good': '#3ddc97',
      '--critSoft': 'rgba(255,93,93,.14)', '--critLine': 'rgba(255,93,93,.3)',
      '--highSoft': 'rgba(255,159,69,.14)', '--highLine': 'rgba(255,159,69,.28)',
      '--medSoft': 'rgba(245,197,66,.14)', '--medLine': 'rgba(245,197,66,.28)',
      '--lowSoft': 'rgba(91,155,255,.14)', '--lowLine': 'rgba(91,155,255,.28)'
    },
    light: {
      '--bg': '#f1f4f9', '--panel': '#ffffff', '--panel2': '#f6f8fc', '--border': '#e2e8f0',
      '--track': '#eef2f7', '--code': '#0e1320', '--codeFg': '#aebccf', '--scroll': '#cbd5e1',
      '--fg': '#13203a', '--body': '#3c4a63', '--muted': '#64748b', '--faint': '#94a3b8',
      '--accent': '#2563eb', '--accentGlow': 'rgba(37,99,235,.28)',
      '--crit': '#dc2626', '--high': '#ea7317', '--med': '#c2870a', '--low': '#2563eb', '--good': '#0f9d6b',
      '--critSoft': 'rgba(220,38,38,.09)', '--critLine': 'rgba(220,38,38,.2)',
      '--highSoft': 'rgba(234,115,23,.1)', '--highLine': 'rgba(234,115,23,.22)',
      '--medSoft': 'rgba(194,135,10,.11)', '--medLine': 'rgba(194,135,10,.24)',
      '--lowSoft': 'rgba(37,99,235,.09)', '--lowLine': 'rgba(37,99,235,.2)'
    }
  };

  var data = window.__DASH__ || { namespaces: [], findings: [], raw: '', provider: 'llm', autoRefresh: false };
  var savedTheme = 'dark';
  try { var t0 = localStorage.getItem(THEME_KEY); if (t0 === 'light' || t0 === 'dark') savedTheme = t0; } catch (e) {}

  var state = {
    theme: savedTheme, query: '', filter: 'all', range: '24h', llmTab: 'all',
    selectedNs: 'all', nsMenuOpen: false,
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

    var scale = allMode ? 1 : Math.max(0.35, podCount / 92);
    var series = buildSeries(scale);
    var maxTot = Math.max.apply(null, series.map(function (b) { return b.crit + b.high + b.med + b.low; }).concat([1]));
    var H = 116, segColor = { crit: 'var(--crit)', high: 'var(--high)', med: 'var(--med)', low: 'var(--low)' };
    var tsBars = series.map(function (b) {
      var total = b.crit + b.high + b.med + b.low;
      var segs = [['crit', b.crit], ['high', b.high], ['med', b.med], ['low', b.low]].filter(function (x) { return x[1] > 0; })
        .map(function (x, i) { return { h: Math.max(1, (x[1] / maxTot) * H), bg: segColor[x[0]], first: i === 0 }; });
      return { title: b.hour + ':00 · ' + total + ' findings', segs: segs };
    });

    var scopeFindings = (data.findings || []).filter(function (f) { return allMode || f.nsKey === s.selectedNs; });
    var catCounts = {}; GROUP_ORDER.forEach(function (g) { catCounts[g] = 0; });
    scopeFindings.forEach(function (f) { if (catCounts[f.group] != null) catCounts[f.group]++; });
    var catMax = Math.max.apply(null, GROUP_ORDER.map(function (g) { return catCounts[g]; }).concat([1]));
    var catColor = function (g) { return ({ Other: 'var(--low)', Pods: 'var(--high)', Resources: 'var(--med)', Security: 'var(--high)', Services: 'var(--low)', Workloads: 'var(--med)' }[g]) || 'var(--low)'; };
    var catShort = { Other: 'Other', Pods: 'Pods', Resources: 'Resrc', Security: 'Secur', Services: 'Svcs', Workloads: 'Wkld' };
    var catBars = GROUP_ORDER.map(function (g) { return { label: catShort[g] + ' ' + catCounts[g], h: Math.max(4, (catCounts[g] / catMax) * 54), bg: catColor(g) }; });

    var distTotal = Math.max(1, agg.crit + agg.high + agg.med + agg.low);
    var distSegs = [['crit', agg.crit, 'var(--crit)'], ['high', agg.high, 'var(--high)'], ['med', agg.med, 'var(--med)'], ['low', agg.low, 'var(--low)']]
      .filter(function (x) { return x[1] > 0; }).map(function (x) { var pct = (x[1] / distTotal) * 100; return { pct: pct, bg: x[2], label: pct > 11 ? (x[0] + ' ' + x[1]) : '' }; });

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
      totalFindings: agg.findings, podCount: podCount, unhealthy: unhealthy, errorRate: errorRate, bigNumber: bigNumber,
      donutSegs: donutSegs, donutCenter: allMode ? donutTotal : nsObj.findings,
      ringSegs: ringSegs, healthScore: healthScore, healthColor: healthColor,
      healthDash: ((healthScore / 100) * C).toFixed(1) + ' ' + C,
      sloColor: agg.crit > 0 ? 'var(--high)' : 'var(--good)', sloLabel: agg.crit > 0 ? 'SLO at risk' : 'SLO all green',
      tsBars: tsBars, catBars: catBars, distSegs: distSegs,
      groups: groups, shownTotal: shownTotal, fixableCount: fixableCount, tabCounts: tabCounts
    };
  }

  // ── LLM panel (derived from real Report.Raw + findings) ──
  function llmHTML(v) {
    var box = 'padding:12px 14px;border-radius:10px;background:var(--panel2);border:1px solid var(--border);';
    if (state.llmTab === 'all') return mdToHtml(data.raw);
    if (state.llmTab === 'verdict') {
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
    if (state.llmTab === 'incidents') {
      var inc = (data.findings || []).filter(function (f) { return f.sev === 'critical' || f.sev === 'high'; }).slice(0, 8);
      if (!inc.length) return '<div style="color:var(--muted)">No critical or high incidents in scope.</div>';
      return '<div style="display:flex;flex-direction:column;gap:11px;">' + inc.map(function (f) {
        var m = sevMeta(f.sev);
        return '<div style="' + box + 'border-left:3px solid ' + m.c + ';"><div style="display:flex;justify-content:space-between;gap:10px;"><strong style="color:var(--fg)">' + esc(f.title) + '</strong><span style="font-family:\'IBM Plex Mono\',monospace;font-size:11px;color:var(--faint);white-space:nowrap;">' + esc(f.restarts !== '—' ? f.restarts + ' restarts' : f.nsKey) + '</span></div><div style="color:var(--muted);margin-top:4px;">' + esc(f.reason) + '</div></div>';
      }).join('') + '</div>';
    }
    if (state.llmTab === 'rbac') {
      var sec = (data.findings || []).filter(function (f) { return f.group === 'Security' || /rbac|forbidden|privileg|secret/i.test(f.title); });
      if (!sec.length) return '<div style="color:var(--muted)">No RBAC or security findings detected in scope.</div>';
      return '<div style="display:flex;flex-direction:column;gap:9px;">' + sec.map(function (f) {
        return '<div style="display:flex;gap:10px;' + box + '"><span style="color:var(--high)">⚿</span><div><strong style="color:var(--fg)">' + esc(f.title) + '</strong><div style="color:var(--muted)">' + esc(f.root) + '</div></div></div>';
      }).join('') + '</div>';
    }
    // prevention
    var seen = {}, tips = [];
    (data.findings || []).forEach(function (f) { if (f.suggestion && !seen[f.suggestion]) { seen[f.suggestion] = true; tips.push(f.suggestion); } });
    tips = tips.slice(0, 8);
    if (!tips.length) return '<div style="color:var(--muted)">No remediation suggestions available.</div>';
    return '<div style="display:flex;flex-direction:column;gap:9px;">' + tips.map(function (s) {
      return '<div style="display:flex;gap:10px;' + box + '"><span style="color:var(--good)">✓</span><div style="color:var(--body)">' + esc(s) + '</div></div>';
    }).join('') + '</div>';
  }

  // ── Render ──
  function render() {
    var v = computeVals(), s = state;
    var capWidth = window.innerWidth || 1400;

    var nsMenuRows = [{ key: 'all', color: '#8b97a7', label: 'all namespaces', count: v.NS.reduce(function (a, n) { return a + n.findings; }, 0) }]
      .concat(v.NS.map(function (n) { return { key: n.key, color: n.color, label: n.key, count: n.findings }; }));

    function pill(color, soft, line, label, val) {
      return '<div style="display:flex;align-items:center;gap:6px;padding:3px 11px 3px 9px;border-radius:30px;background:' + soft + ';border:1px solid ' + line + ';">' +
        '<span style="width:7px;height:7px;border-radius:50%;background:' + color + ';"></span>' +
        '<span style="font-size:12px;color:var(--muted);">' + label + '</span>' +
        '<span style="font-size:12px;font-weight:700;color:' + color + ';">' + val + '</span></div>';
    }

    var html = '<div style="' + css({ minHeight: '100vh', background: 'var(--bg)', color: 'var(--fg)', fontFamily: "'IBM Plex Sans',system-ui,sans-serif", fontSize: '14px', transition: 'background .25s,color .25s' }) + '">';

    // HEADER
    html += '<header style="display:flex;align-items:center;gap:16px;padding:0 20px;height:54px;border-bottom:1px solid var(--border);background:var(--panel);position:sticky;top:0;z-index:30;">' +
      '<div style="display:flex;align-items:center;gap:9px;"><div style="width:22px;height:22px;border-radius:6px;background:linear-gradient(135deg,var(--accent),#7b5bff);display:flex;align-items:center;justify-content:center;box-shadow:0 0 14px var(--accentGlow);"><div style="width:8px;height:8px;border-radius:2px;background:#fff;"></div></div><span style="font-weight:700;font-size:16px;letter-spacing:-.3px;">exalm</span></div>' +
      '<div style="display:flex;align-items:center;gap:8px;color:var(--muted);font-size:13px;"><span style="width:6px;height:6px;border-radius:50%;background:var(--good);animation:ex-pulse 2s ease infinite;"></span><span style="font-weight:500;color:var(--fg);">Kubernetes analysis</span></div>';
    // ns selector
    html += '<div style="position:relative;"><button data-act="ns-toggle" style="display:flex;align-items:center;gap:9px;height:32px;padding:0 11px;border-radius:8px;border:1px solid var(--border);background:var(--panel2);color:var(--fg);font-size:12.5px;font-weight:500;cursor:pointer;">' +
      '<span style="width:8px;height:8px;border-radius:2px;background:' + v.nsDot + ';"></span>' +
      '<span style="font-size:10px;color:var(--faint);text-transform:uppercase;letter-spacing:.5px;">namespace</span>' +
      '<span style="font-family:\'IBM Plex Mono\',monospace;">' + esc(v.allMode ? 'all namespaces' : v.nsObj.key) + '</span>' +
      '<span style="font-size:9px;color:var(--faint);transform:' + (s.nsMenuOpen ? 'rotate(180deg)' : 'none') + ';transition:transform .2s;">▾</span></button>';
    if (s.nsMenuOpen) {
      html += '<div style="position:absolute;top:38px;left:0;min-width:230px;background:var(--panel);border:1px solid var(--border);border-radius:10px;box-shadow:0 12px 34px rgba(0,0,0,.45);padding:5px;z-index:50;">';
      nsMenuRows.forEach(function (n) {
        var active = s.selectedNs === n.key;
        html += '<button data-act="ns-select" data-ns="' + esc(n.key) + '" style="display:flex;align-items:center;gap:9px;width:100%;padding:7px 9px;border-radius:7px;border:none;cursor:pointer;background:' + (active ? 'var(--panel2)' : 'transparent') + ';color:var(--fg);">' +
          '<span style="width:8px;height:8px;border-radius:2px;background:' + n.color + ';flex:none;"></span>' +
          '<span style="flex:1;text-align:left;font-family:\'IBM Plex Mono\',monospace;font-size:12.5px;">' + esc(n.label) + '</span>' +
          '<span style="font-size:11px;color:var(--muted);">' + n.count + '</span>' + (active ? '<span style="color:var(--accent);font-size:12px;">✓</span>' : '') + '</button>';
      });
      html += '</div>';
    }
    html += '</div>';
    html += '<div style="flex:1;"></div>';
    html += '<span style="font-family:\'IBM Plex Mono\',monospace;font-size:12px;color:var(--muted);" id="ex-clock">' + esc(clockText()) + '</span>';
    html += '<button data-act="logs" title="Open the log viewer" style="display:flex;align-items:center;gap:7px;height:32px;padding:0 12px;border-radius:8px;border:1px solid var(--border);background:var(--panel2);color:var(--fg);font-size:12.5px;font-weight:500;cursor:pointer;"><span style="font-size:13px;">▤</span><span>Logs</span></button>';
    html += '<button data-act="theme" style="display:flex;align-items:center;gap:7px;height:32px;padding:0 12px;border-radius:8px;border:1px solid var(--border);background:var(--panel2);color:var(--fg);font-size:12.5px;font-weight:500;cursor:pointer;"><span style="font-size:13px;">' + (s.theme === 'dark' ? '☀' : '☾') + '</span><span>' + (s.theme === 'dark' ? 'Light' : 'Dark') + '</span></button>';
    if (data.canFix) {
      html += '<button data-act="fixall" style="display:flex;align-items:center;gap:8px;height:32px;padding:0 14px;border-radius:8px;border:none;background:linear-gradient(135deg,var(--accent),#6a7bff);color:#fff;font-size:12.5px;font-weight:600;cursor:pointer;box-shadow:0 2px 10px var(--accentGlow);"><span style="width:7px;height:7px;border-radius:2px;background:#fff;"></span>Fix all (' + v.fixableCount + ')</button>';
    }
    html += '</header>';

    // SUMMARY STRIP
    html += '<div style="display:flex;align-items:center;gap:8px;padding:11px 20px;border-bottom:1px solid var(--border);background:var(--bg);flex-wrap:wrap;">' +
      pill('var(--crit)', 'var(--critSoft)', 'var(--critLine)', 'critical', v.sevCounts.crit) +
      pill('var(--high)', 'var(--highSoft)', 'var(--highLine)', 'high', v.sevCounts.high) +
      pill('var(--med)', 'var(--medSoft)', 'var(--medLine)', 'medium', v.sevCounts.med) +
      pill('var(--low)', 'var(--lowSoft)', 'var(--lowLine)', 'low', v.sevCounts.low) +
      '<span style="width:1px;height:18px;background:var(--border);margin:0 4px;"></span>' +
      '<span style="font-size:12.5px;color:var(--muted);">Scope <strong style="color:var(--fg)">' + esc(v.allMode ? 'all namespaces' : v.nsObj.key) + '</strong> · <strong style="color:var(--fg)">' + fmt(v.podCount) + ' pods</strong> · <span style="color:var(--high)">' + v.unhealthy + ' unhealthy</span> · via ' + esc(data.provider || 'llm') + '</span></div>';

    // ACTIVITY ROW
    html += '<div class="ex-activity" style="padding:16px 20px 0;display:grid;grid-template-columns:232px 1fr 312px;gap:14px;">';
    // big metric
    html += '<div style="background:var(--panel);border:1px solid var(--border);border-radius:14px;padding:16px;display:flex;flex-direction:column;justify-content:space-between;">' +
      '<div style="font-size:10.5px;letter-spacing:.7px;text-transform:uppercase;color:var(--faint);font-weight:600;">Log lines analysed · 24h</div>' +
      '<div><div style="font-size:38px;font-weight:700;letter-spacing:-1px;line-height:1;font-variant-numeric:tabular-nums;">' + v.bigNumber + '</div>' +
      '<div style="display:flex;align-items:center;gap:7px;margin-top:9px;"><span style="font-size:11px;font-weight:600;color:var(--good);background:var(--lowSoft);padding:2px 8px;border-radius:20px;">▲ 4.2%</span><span style="font-size:11px;color:var(--muted);">vs prior 24h</span></div></div>' +
      '<div style="display:flex;gap:14px;margin-top:14px;padding-top:13px;border-top:1px solid var(--border);">' +
      '<div><div style="font-size:16px;font-weight:700;">' + v.errorRate + '</div><div style="font-size:10px;color:var(--muted);">error rate</div></div>' +
      '<div><div style="font-size:16px;font-weight:700;">' + fmt(v.podCount) + '</div><div style="font-size:10px;color:var(--muted);">pods</div></div>' +
      '<div><div style="font-size:16px;font-weight:700;color:var(--high);">' + v.unhealthy + '</div><div style="font-size:10px;color:var(--muted);">unhealthy</div></div></div></div>';
    // time series
    html += '<div style="background:var(--panel);border:1px solid var(--border);border-radius:14px;padding:14px 16px;">' +
      '<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:6px;"><div style="font-size:10.5px;letter-spacing:.7px;text-transform:uppercase;color:var(--faint);font-weight:600;">Findings over time</div>' +
      '<div style="display:flex;gap:13px;">' + [['crit', 'critical'], ['high', 'high'], ['med', 'medium'], ['low', 'low']].map(function (x) { return '<span style="display:flex;align-items:center;gap:5px;font-size:10.5px;color:var(--muted);"><span style="width:8px;height:8px;border-radius:2px;background:var(--' + x[0] + ');"></span>' + x[1] + '</span>'; }).join('') + '</div></div>' +
      '<div style="display:flex;align-items:flex-end;gap:3px;height:118px;">' +
      v.tsBars.map(function (b) {
        return '<div class="ex-chart-bar" data-act="drilldown" data-kind="time" data-label="' + esc(b.title) + '" title="' + esc(b.title) + '" style="flex:1;display:flex;flex-direction:column;justify-content:flex-end;min-width:0;cursor:pointer;">' +
          b.segs.map(function (sg) { return '<div style="width:100%;height:' + sg.h + 'px;background:' + sg.bg + ';border-radius:' + (sg.first ? '3px 3px 0 0' : '0') + ';"></div>'; }).join('') + '</div>';
      }).join('') + '</div>' +
      '<div style="display:flex;justify-content:space-between;margin-top:7px;font-family:\'IBM Plex Mono\',monospace;font-size:10px;color:var(--faint);"><span>00:00</span><span>06:00</span><span>12:00</span><span>18:00</span><span>now</span></div></div>';
    // ns donut
    html += '<div style="background:var(--panel);border:1px solid var(--border);border-radius:14px;padding:14px 16px;">' +
      '<div style="font-size:10.5px;letter-spacing:.7px;text-transform:uppercase;color:var(--faint);font-weight:600;margin-bottom:4px;">Findings by namespace</div>' +
      '<div style="display:flex;align-items:center;gap:14px;"><svg width="92" height="92" viewBox="0 0 80 80" style="flex:none;"><g transform="rotate(-90 40 40)"><circle cx="40" cy="40" r="34" fill="none" stroke="var(--track)" stroke-width="10"></circle>' +
      v.donutSegs.map(function (d) { return '<circle data-act="ns-select" data-ns="' + esc(d.key) + '" cx="40" cy="40" r="34" fill="none" stroke="' + d.color + '" stroke-width="10" stroke-dasharray="' + d.dash + '" stroke-dashoffset="' + d.offset + '" opacity="' + d.opacity + '" style="cursor:pointer;transition:opacity .2s;"></circle>'; }).join('') +
      '</g><text x="40" y="38" text-anchor="middle" font-size="17" font-weight="700" fill="var(--fg)">' + v.donutCenter + '</text><text x="40" y="50" text-anchor="middle" font-size="7" fill="var(--faint)" letter-spacing="1">FINDINGS</text></svg>' +
      '<div style="flex:1;display:flex;flex-direction:column;gap:3px;min-width:0;">' +
      v.NS.map(function (n) {
        var active = s.selectedNs === n.key;
        return '<button data-act="ns-select" data-ns="' + esc(n.key) + '" style="display:flex;align-items:center;gap:7px;width:100%;padding:3px 6px;border-radius:6px;border:1px solid ' + (active ? 'var(--accent)' : 'transparent') + ';background:' + (active ? 'var(--lowSoft)' : 'transparent') + ';cursor:pointer;color:var(--fg);">' +
          '<span style="width:8px;height:8px;border-radius:2px;background:' + n.color + ';flex:none;"></span>' +
          '<span style="flex:1;text-align:left;font-family:\'IBM Plex Mono\',monospace;font-size:11px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">' + esc(n.key) + '</span>' +
          '<span style="font-size:11px;font-weight:600;">' + n.findings + '</span></button>';
      }).join('') + '</div></div></div>';
    html += '</div>';

    // STATS ROW
    html += '<div class="ex-stats" style="padding:14px 20px 0;display:grid;grid-template-columns:200px 200px 1fr;gap:14px;">';
    // cluster health
    html += '<div style="background:var(--panel);border:1px solid var(--border);border-radius:14px;padding:15px;"><div style="font-size:10.5px;letter-spacing:.7px;text-transform:uppercase;color:var(--faint);font-weight:600;">Cluster health</div>' +
      '<div style="display:flex;align-items:center;gap:13px;margin-top:10px;"><svg width="76" height="76" viewBox="0 0 80 80"><g transform="rotate(-90 40 40)"><circle cx="40" cy="40" r="34" fill="none" stroke="var(--track)" stroke-width="9"></circle><circle cx="40" cy="40" r="34" fill="none" stroke="' + v.healthColor + '" stroke-width="9" stroke-linecap="round" stroke-dasharray="' + v.healthDash + '"></circle></g><text x="40" y="38" text-anchor="middle" font-size="20" font-weight="700" fill="var(--fg)">' + v.healthScore + '</text><text x="40" y="51" text-anchor="middle" font-size="8" fill="var(--faint)" letter-spacing="1">HEALTH</text></svg>' +
      '<div style="display:flex;flex-direction:column;gap:8px;"><div><div style="font-size:18px;font-weight:700;line-height:1;">' + v.totalFindings + '</div><div style="font-size:10.5px;color:var(--muted);">findings</div></div>' +
      '<div style="display:flex;align-items:center;gap:5px;"><span style="width:6px;height:6px;border-radius:50%;background:' + v.sloColor + ';"></span><span style="font-size:11px;color:var(--muted);">' + esc(v.sloLabel) + '</span></div></div></div></div>';
    // severity ring
    html += '<div style="background:var(--panel);border:1px solid var(--border);border-radius:14px;padding:15px;"><div style="font-size:10.5px;letter-spacing:.7px;text-transform:uppercase;color:var(--faint);font-weight:600;">Severity</div>' +
      '<div style="display:flex;align-items:center;gap:13px;margin-top:10px;"><svg width="76" height="76" viewBox="0 0 80 80"><g transform="rotate(-90 40 40)"><circle cx="40" cy="40" r="34" fill="none" stroke="var(--track)" stroke-width="9"></circle>' +
      v.ringSegs.map(function (r) { return '<circle cx="40" cy="40" r="34" fill="none" stroke="' + r.color + '" stroke-width="9" stroke-dasharray="' + r.dash + '" stroke-dashoffset="' + r.offset + '"></circle>'; }).join('') +
      '</g><text x="40" y="38" text-anchor="middle" font-size="20" font-weight="700" fill="var(--fg)">' + v.totalFindings + '</text><text x="40" y="51" text-anchor="middle" font-size="8" fill="var(--faint)" letter-spacing="1">FINDINGS</text></svg>' +
      '<div style="display:flex;flex-direction:column;gap:5px;font-size:11px;">' +
      [['Critical', 'crit', v.sevCounts.crit], ['High', 'high', v.sevCounts.high], ['Med', 'med', v.sevCounts.med], ['Low', 'low', v.sevCounts.low]].map(function (x) {
        return '<div style="display:flex;align-items:center;gap:6px;"><span style="width:7px;height:7px;border-radius:2px;background:var(--' + x[1] + ');"></span><span style="color:var(--muted);">' + x[0] + '</span><b style="margin-left:auto;">' + x[2] + '</b></div>';
      }).join('') + '</div></div></div>';
    // by category + dist
    html += '<div style="background:var(--panel);border:1px solid var(--border);border-radius:14px;padding:15px;display:flex;flex-direction:column;">' +
      '<div style="display:flex;justify-content:space-between;align-items:center;"><div style="font-size:10.5px;letter-spacing:.7px;text-transform:uppercase;color:var(--faint);font-weight:600;">By category</div><div style="font-size:11px;color:var(--muted);">across ' + esc(v.allMode ? 'all namespaces' : v.nsObj.key) + '</div></div>' +
      '<div style="flex:1;display:flex;align-items:flex-end;gap:14px;height:64px;margin-top:10px;padding:0 4px;">' +
      v.catBars.map(function (c) { return '<div style="flex:1;display:flex;flex-direction:column;align-items:center;gap:5px;"><div style="width:100%;max-width:44px;height:' + c.h + 'px;background:' + c.bg + ';border-radius:4px 4px 0 0;transition:height .3s;"></div><span style="font-size:9.5px;color:var(--faint);">' + esc(c.label) + '</span></div>'; }).join('') + '</div>' +
      '<div style="margin-top:12px;"><div style="font-size:10px;letter-spacing:.7px;text-transform:uppercase;color:var(--faint);font-weight:600;margin-bottom:6px;">Severity distribution</div>' +
      '<div style="display:flex;height:14px;border-radius:7px;overflow:hidden;background:var(--track);">' +
      v.distSegs.map(function (d) { return '<div style="width:' + d.pct + '%;background:' + d.bg + ';display:flex;align-items:center;justify-content:center;transition:width .3s;"><span style="font-size:9px;font-weight:600;color:rgba(0,0,0,.6);">' + esc(d.label) + '</span></div>'; }).join('') + '</div></div></div>';
    html += '</div>';

    // MAIN GRID
    html += '<div class="ex-main" style="padding:14px 20px 20px;display:grid;grid-template-columns:1fr 1fr;gap:14px;align-items:start;">';
    // findings
    html += '<section style="background:var(--panel);border:1px solid var(--border);border-radius:14px;overflow:hidden;display:flex;flex-direction:column;">' +
      '<div style="padding:13px 15px;border-bottom:1px solid var(--border);">' +
      '<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:11px;"><div style="display:flex;align-items:baseline;gap:8px;"><span style="font-size:11px;letter-spacing:.7px;text-transform:uppercase;font-weight:700;color:var(--fg);">Findings</span><span style="font-size:12px;color:var(--muted);">' + v.shownTotal + ' shown · ' + esc(v.allMode ? 'all namespaces' : v.nsObj.key) + '</span></div>' +
      '<div style="display:flex;gap:5px;">' + ['1h', '24h', '7d', 'All'].map(function (r) { var a = s.range === r; return '<button data-act="range" data-r="' + r + '" style="padding:4px 10px;border-radius:7px;font-size:11.5px;font-weight:500;cursor:pointer;border:1px solid ' + (a ? 'var(--accent)' : 'var(--border)') + ';background:' + (a ? 'var(--lowSoft)' : 'transparent') + ';color:' + (a ? 'var(--accent)' : 'var(--muted)') + ';">' + r + '</button>'; }).join('') + '</div></div>' +
      '<div style="position:relative;margin-bottom:10px;"><span style="position:absolute;left:11px;top:50%;transform:translateY(-50%);color:var(--faint);font-size:13px;">⌕</span>' +
      '<input id="finding-search" value="' + esc(s.query) + '" placeholder="Search findings, namespaces, reasons…" autocomplete="off" style="width:100%;height:34px;padding:0 12px 0 30px;border-radius:9px;border:1px solid var(--border);background:var(--panel2);color:var(--fg);font-family:inherit;font-size:13px;outline:none;"></div>' +
      '<div style="display:flex;gap:6px;flex-wrap:wrap;">' + [['all', 'All'], ['critical', 'Critical'], ['high', 'High'], ['med', 'Med'], ['low', 'Low']].map(function (x) {
        var a = s.filter === x[0];
        return '<button data-act="filter" data-f="' + x[0] + '" style="display:flex;align-items:center;gap:6px;padding:5px 11px;border-radius:8px;font-size:12px;font-weight:500;cursor:pointer;border:1px solid ' + (a ? 'var(--accent)' : 'var(--border)') + ';background:' + (a ? 'var(--accent)' : 'transparent') + ';color:' + (a ? '#fff' : 'var(--muted)') + ';">' + x[1] + '<span style="font-size:10px;font-weight:700;padding:0 6px;border-radius:10px;background:' + (a ? 'rgba(255,255,255,.22)' : 'var(--track)') + ';color:' + (a ? '#fff' : 'var(--muted)') + ';">' + v.tabCounts[x[0]] + '</span></button>';
      }).join('') + '</div></div>';
    html += '<div style="max-height:520px;overflow-y:auto;">';
    if (!v.groups.length) {
      html += '<div style="padding:50px 20px;text-align:center;color:var(--faint);font-size:13px;">No findings match your filters.</div>';
    }
    v.groups.forEach(function (g) {
      html += '<div style="border-bottom:1px solid var(--border);"><button data-act="group-toggle" data-group="' + esc(g.name) + '" style="width:100%;display:flex;align-items:center;gap:9px;padding:10px 15px;background:var(--panel2);border:none;cursor:pointer;text-align:left;">' +
        '<span style="font-size:11px;color:var(--muted);display:inline-block;transform:' + (g.open ? 'none' : 'rotate(-90deg)') + ';transition:transform .2s;flex:none;">▾</span>' +
        '<span style="font-size:12.5px;font-weight:600;color:var(--fg);">' + esc(g.name) + '</span>' +
        '<span style="font-size:11px;color:var(--muted);background:var(--track);padding:1px 8px;border-radius:20px;">' + g.shown + '</span><span style="flex:1;"></span></button>';
      if (g.open) {
        g.items.forEach(function (f) {
          var m = sevMeta(f.sev), open = s.openFinding === f.id;
          var isFixed = !!s.fixed[f.id], isFixing = !!s.fixing[f.id];
          html += '<div style="background:' + (open ? 'var(--panel2)' : 'transparent') + ';transition:background .15s;">' +
            '<div data-act="finding-toggle" data-id="' + esc(f.id) + '" style="display:flex;align-items:center;gap:11px;padding:11px 15px;cursor:pointer;">' +
            '<span style="width:3px;align-self:stretch;border-radius:3px;background:' + m.c + ';flex:none;"></span>' +
            '<span style="font-size:9px;font-weight:700;letter-spacing:.5px;padding:2px 7px;border-radius:5px;color:' + m.c + ';background:' + m.soft + ';border:1px solid ' + m.line + ';flex:none;">' + m.label + '</span>' +
            '<div style="flex:1;min-width:0;"><div style="font-size:13px;font-weight:500;color:var(--fg);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">' + esc(f.title) + '</div>' +
            '<div style="font-family:\'IBM Plex Mono\',monospace;font-size:10.5px;color:var(--faint);margin-top:2px;">' + esc(f.ns) + '</div></div>' +
            (f.fix ? fixBtn(f, isFixed, isFixing, false) : '') +
            '<span style="font-size:14px;color:var(--faint);flex:none;transform:' + (open ? 'rotate(180deg)' : 'none') + ';transition:transform .2s;">⌄</span></div>';
          if (open) {
            var cell = 'background:var(--panel2);border:1px solid var(--border);border-radius:8px;padding:8px 10px;';
            var lbl = 'font-size:9.5px;text-transform:uppercase;letter-spacing:.5px;color:var(--faint);';
            html += '<div style="padding:2px 15px 15px 30px;">' +
              '<div style="display:grid;grid-template-columns:repeat(3,1fr);gap:9px;margin-bottom:11px;">' +
              '<div style="' + cell + '"><div style="' + lbl + '">Reason</div><div style="font-size:12px;font-weight:500;margin-top:2px;">' + esc(f.reason) + '</div></div>' +
              '<div style="' + cell + '"><div style="' + lbl + '">Age</div><div style="font-size:12px;font-weight:500;margin-top:2px;">' + esc(f.age) + '</div></div>' +
              '<div style="' + cell + '"><div style="' + lbl + '">Restarts</div><div style="font-size:12px;font-weight:500;margin-top:2px;">' + esc(f.restarts) + '</div></div></div>' +
              '<div style="display:flex;gap:8px;padding:9px 11px;border-radius:8px;background:' + m.soft + ';border:1px solid ' + m.line + ';margin-bottom:10px;"><span style="color:' + m.c + ';font-size:13px;">●</span><div><div style="' + lbl + '">Root cause</div><div style="font-size:12.5px;margin-top:2px;">' + esc(f.root) + '</div></div></div>';
            if (f.log) {
              html += '<div style="' + lbl + 'margin-bottom:5px;">Log</div><pre style="margin:0 0 11px;padding:10px 12px;border-radius:8px;background:var(--code);border:1px solid var(--border);font-family:\'IBM Plex Mono\',monospace;font-size:11px;color:var(--codeFg);white-space:pre-wrap;line-height:1.5;overflow:auto;">' + esc(f.log) + '</pre>';
            }
            var confBadge = f.confidence ? '<span title="root-cause confidence" style="font-size:9px;font-weight:700;letter-spacing:.4px;text-transform:uppercase;padding:2px 7px;border-radius:5px;color:' + confColor(f.confidence) + ';background:var(--track);">' + esc(f.confidence) + ' confidence</span>' : '';
            html += '<div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;">' +
              (f.fix ? fixBtn(f, isFixed, isFixing, true) : '') +
              '<button data-act="investigate" data-id="' + esc(f.id) + '" style="font-family:inherit;font-size:12px;font-weight:600;border-radius:7px;cursor:pointer;padding:6px 14px;border:1px solid var(--accent);background:transparent;color:var(--accent);">✦ Investigate</button>' +
              confBadge +
              '<span style="font-size:11.5px;color:var(--muted);flex:1;min-width:120px;">' + esc(f.suggestion) + '</span></div></div>';
          }
          html += '</div>';
        });
      }
      html += '</div>';
    });
    html += '</div></section>';

    // LLM
    html += '<section style="background:var(--panel);border:1px solid var(--border);border-radius:14px;overflow:hidden;position:sticky;top:70px;">' +
      '<div style="padding:13px 15px;border-bottom:1px solid var(--border);"><div style="display:flex;align-items:center;gap:8px;margin-bottom:11px;"><span style="width:18px;height:18px;border-radius:5px;background:linear-gradient(135deg,#7b5bff,var(--accent));display:flex;align-items:center;justify-content:center;font-size:10px;">✦</span><span style="font-size:11px;letter-spacing:.7px;text-transform:uppercase;font-weight:700;">LLM analysis</span><span style="font-size:11px;color:var(--good);display:flex;align-items:center;gap:5px;"><span style="width:6px;height:6px;border-radius:50%;background:var(--good);animation:ex-pulse 2s ease infinite;"></span>live</span></div>' +
      '<div style="display:flex;gap:5px;flex-wrap:wrap;">' + [['all', 'All'], ['verdict', 'Verdict'], ['incidents', 'Incidents'], ['rbac', 'RBAC'], ['prevention', 'Prevention']].map(function (x) {
        var a = s.llmTab === x[0];
        return '<button data-act="llm" data-tab="' + x[0] + '" style="padding:4px 10px;border-radius:7px;font-size:11.5px;font-weight:500;cursor:pointer;border:1px solid ' + (a ? 'var(--accent)' : 'var(--border)') + ';background:' + (a ? 'var(--lowSoft)' : 'transparent') + ';color:' + (a ? 'var(--accent)' : 'var(--muted)') + ';">' + x[1] + '</button>';
      }).join('') + '</div></div>' +
      '<div style="max-height:620px;overflow-y:auto;padding:16px 17px;font-size:13px;line-height:1.65;color:var(--body);">' + llmHTML(v) + '</div></section>';
    html += '</div>';

    // FOOTER
    html += '<footer style="display:flex;align-items:center;gap:8px;padding:9px 20px;border-top:1px solid var(--border);color:var(--faint);font-size:11.5px;"><span>exalm.com</span><span style="flex:1;"></span>' +
      (data.autoRefresh ? '<span style="display:inline-block;width:11px;height:11px;border:1.6px solid var(--faint);border-top-color:transparent;border-radius:50%;animation:ex-spin 1s linear infinite;"></span><span>auto-refreshes every 30s</span>' : '<span>static snapshot — re-run analyze to update</span>') +
      '</footer>';

    html += '</div>';

    // capWidth guard (avoid unused var lint in minifiers); used for future responsive tweaks
    void capWidth;

    var app = document.getElementById('app');
    // Preserve search focus + caret across re-render.
    var active = document.activeElement;
    var refocus = active && active.id === 'finding-search';
    var caret = refocus ? active.selectionStart : 0;
    app.innerHTML = html;
    if (refocus) {
      var inp = document.getElementById('finding-search');
      if (inp) { inp.focus(); try { inp.setSelectionRange(caret, caret); } catch (e) {} }
    }
    // Let the charts module wire hover tooltips + drill-down on the fresh DOM.
    if (window.ExalmCharts && window.ExalmCharts.attach) window.ExalmCharts.attach();
  }

  function fixBtn(f, isFixed, isFixing, large) {
    var base = 'font-family:inherit;font-weight:600;border-radius:7px;cursor:pointer;flex:none;border:1px solid var(--border);transition:all .15s;';
    var label, extra;
    if (isFixed) { extra = 'background:var(--good);color:#06281b;border:none;'; label = 'Fixed ✓'; }
    else if (isFixing) { extra = 'background:var(--track);color:var(--muted);'; label = large ? 'Applying fix…' : 'Fixing…'; }
    else { extra = 'background:var(--accent);color:#fff;border:none;'; label = large ? 'Apply fix' : 'Fix'; }
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

  function clockText() {
    // Current UTC time, formatted like the design: "Tue, 23 Jun 2026 · 15:44 GMT".
    var d = new Date();
    var days = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
    var mons = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
    function p2(n) { return (n < 10 ? '0' : '') + n; }
    return days[d.getUTCDay()] + ', ' + d.getUTCDate() + ' ' + mons[d.getUTCMonth()] + ' ' + d.getUTCFullYear() +
      ' · ' + p2(d.getUTCHours()) + ':' + p2(d.getUTCMinutes()) + ' GMT';
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
      case 'ns-toggle': state.nsMenuOpen = !state.nsMenuOpen; render(); break;
      case 'ns-select': state.selectedNs = el.getAttribute('data-ns'); state.nsMenuOpen = false; render(); break;
      case 'theme': state.theme = state.theme === 'dark' ? 'light' : 'dark'; try { localStorage.setItem(THEME_KEY, state.theme); } catch (x) {} applyTheme(); render(); break;
      case 'fixall': fixAll(); break;
      case 'group-toggle': { var g = el.getAttribute('data-group'); state.openGroups[g] = !state.openGroups[g]; render(); break; }
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
      case 'logs':
        if (window.ExalmLogs) window.ExalmLogs.open();
        break;
      case 'drilldown':
        if (window.ExalmPanels) window.ExalmPanels.openDrilldown({ kind: el.getAttribute('data-kind'), label: el.getAttribute('data-label') });
        break;
      case 'filter': state.filter = el.getAttribute('data-f'); render(); break;
      case 'range': state.range = el.getAttribute('data-r'); render(); break;
      case 'llm': state.llmTab = el.getAttribute('data-tab'); render(); break;
    }
  }
  function onInput(e) {
    if (e.target && e.target.id === 'finding-search') { state.query = e.target.value; render(); }
  }

  // ── Shared API for the panel/chart/log modules ──
  // Exposed so remediation.js / investigate.js (panels.js), charts.js, and
  // logviewer.js can reuse helpers, read current data, and drive fix/refresh
  // without duplicating logic.
  window.Exalm = {
    esc: esc, fmt: fmt, css: css, sevMeta: sevMeta, mdToHtml: mdToHtml, confColor: confColor,
    data: function () { return data; },
    state: state,
    namespaces: function () { return data.namespaces || []; },
    findings: function () { return data.findings || []; },
    finding: function (id) { return (data.findings || []).filter(function (f) { return f.id === id; })[0]; },
    refresh: refresh,
    // applyPrimaryFix runs the existing fix flow (Fixing… → Fixed ✓ → refresh);
    // the remediation panel calls this on confirm.
    applyPrimaryFix: fix
  };

  // ── Boot ──
  applyTheme();
  render();
  document.getElementById('app').addEventListener('click', onClick);
  document.getElementById('app').addEventListener('input', onInput);
  if (data.autoRefresh) setInterval(refresh, 30000);
})();
