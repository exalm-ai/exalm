'use strict';
// widgets.js — THE shared chart/widget library for every Exalm dashboard.
// Loads before dashboard.js, so anything that needs the window.Exalm API
// (esc/fmt/state/…) must read it at CALL time, never at module-load time.
// Consumers: dashboard.js (k8s page), analyzer.js (per-analyzer pages).

(function () {
  function exalm() { return window.Exalm || {}; }
  function esc(s) {
    var E = exalm();
    if (E.esc) return E.esc(s);
    return String(s == null ? '' : s);
  }

  var SEV_COLORS = {
    emerg: 'var(--crit)', alert: 'var(--crit)', crit: 'var(--crit)', critical: 'var(--crit)', fatal: 'var(--crit)',
    err: 'var(--high)', error: 'var(--high)', '5xx': 'var(--crit)',
    warn: 'var(--med)', warning: 'var(--med)', '4xx': 'var(--high)',
    notice: 'var(--low)', info: 'var(--good)', information: 'var(--good)', '2xx': 'var(--good)', '3xx': 'var(--low)',
    debug: 'var(--faint)'
  };
  function sevColor(s) { return SEV_COLORS[String(s || '').toLowerCase()] || 'var(--low)'; }

  // pick tolerates minor JSON-tag spelling differences between Go structs.
  function pick(obj) {
    if (!obj) return null;
    for (var i = 1; i < arguments.length; i++) {
      var v = obj[arguments[i]];
      if (v !== undefined && v !== null) return v;
    }
    return null;
  }

  var card = 'background:var(--panel);border:1px solid var(--border);border-radius:14px;padding:14px 16px;';
  var lbl = 'font-size:10.5px;letter-spacing:.7px;text-transform:uppercase;color:var(--faint);font-weight:600;margin-bottom:9px;';

  function panel(title, inner) {
    return '<div style="' + card + '"><div style="' + lbl + '">' + esc(title) + '</div>' + inner + '</div>';
  }

  // ── chart primitives (inline, CSS-var themed, drill-enabled) ──

  // timeline: vertical bars per bucket; click drills into that minute.
  function timelineChart(buckets, drillBase) {
    if (!buckets || !buckets.length) return '<div style="color:var(--faint);font-size:12px;">No timestamped events.</div>';
    var max = 1;
    buckets.forEach(function (b) { if (b.count > max) max = b.count; });
    var bars = buckets.map(function (b) {
      var h = Math.max(3, Math.round((b.count / max) * 64));
      var drill = drillBase + '&contains=&bucket=' + encodeURIComponent(b.t) + (b.sev ? '&severity=' + encodeURIComponent(b.sev) : '');
      return '<div class="ex-an-drill" data-drill="' + esc(drill) + '" title="' + esc(b.t + ' · ' + b.count + (b.sev ? ' ' + b.sev : '')) + '"' +
        ' style="flex:1;min-width:3px;max-width:22px;height:' + h + 'px;background:' + sevColor(b.sev) + ';border-radius:2px 2px 0 0;cursor:pointer;opacity:.85;"></div>';
    }).join('');
    var first = buckets[0].t, last = buckets[buckets.length - 1].t;
    return '<div style="display:flex;align-items:flex-end;gap:2px;height:68px;">' + bars + '</div>' +
      '<div style="display:flex;justify-content:space-between;font-family:\'IBM Plex Mono\',monospace;font-size:10px;color:var(--faint);margin-top:4px;"><span>' + esc(first) + '</span><span>' + esc(last) + '</span></div>';
  }

  // barList: horizontal top-N; click drills into that name.
  function barList(items, dim, colorFor) {
    if (!items || !items.length) return '<div style="color:var(--faint);font-size:12px;">Nothing recorded.</div>';
    var max = 1;
    items.forEach(function (it) { if (it.count > max) max = it.count; });
    return items.map(function (it) {
      var w = Math.max(2, Math.round((it.count / max) * 100));
      var color = colorFor ? colorFor(it.name) : 'var(--accent)';
      return '<div class="ex-an-drill" data-drill="' + esc(dim + '=' + encodeURIComponent(it.name)) + '" title="' + esc(it.name) + '" style="display:flex;align-items:center;gap:9px;padding:3px 0;cursor:pointer;">' +
        '<span style="flex:0 0 34%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:11.5px;color:var(--body);" title="' + esc(it.name) + '">' + esc(it.name) + '</span>' +
        '<span style="flex:1;height:8px;background:var(--track);border-radius:4px;overflow:hidden;"><span style="display:block;width:' + w + '%;height:100%;background:' + color + ';"></span></span>' +
        '<b style="flex:0 0 40px;text-align:right;font-size:11.5px;color:var(--fg);">' + it.count + '</b></div>';
    }).join('');
  }

  // counters: severity-colored stat chips; click drills on the filter.
  function counters(list) {
    return '<div style="display:flex;gap:10px;flex-wrap:wrap;">' + list.map(function (c) {
      return '<div class="ex-an-drill" data-drill="' + esc(c.drill || '') + '" style="' + (c.drill ? 'cursor:pointer;' : '') + 'flex:1;min-width:110px;background:var(--panel2);border:1px solid var(--border);border-radius:10px;padding:9px 12px;">' +
        '<div style="font-size:20px;font-weight:700;color:' + (c.value > 0 ? (c.color || 'var(--fg)') : 'var(--faint)') + ';">' + c.value + '</div>' +
        '<div style="font-size:10.5px;color:var(--muted);">' + esc(c.label) + '</div></div>';
    }).join('') + '</div>';
  }

  // ── k8s-page widgets (moved from dashboard.js) ──
  // These read window.Exalm at call time (widgets.js loads before dashboard.js).

  function kCard(inner, pad) { return '<div style="background:var(--panel);border:1px solid var(--border);border-radius:14px;padding:' + (pad || '16px') + ';">' + inner + '</div>'; }
  function kCardLabel(t) { return '<div style="font-size:10.5px;letter-spacing:.7px;text-transform:uppercase;color:var(--faint);font-weight:600;">' + esc(t) + '</div>'; }

  // ── Stat cards ──
  function statCards(v) {
    var E = exalm();
    var fmt = E.fmt || function (n) { return String(n); };
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
          '<div style="display:flex;justify-content:space-between;align-items:center;">' + kCardLabel(c[0]) + '<span style="width:8px;height:8px;border-radius:2px;background:' + c[2] + ';"></span></div>' +
          '<div style="font-size:30px;font-weight:700;line-height:1;margin-top:12px;font-variant-numeric:tabular-nums;">' + fmt(c[1]) + '</div></div>';
      }).join('') + '</div>';
  }

  // ── Severity donut + legend ──
  function severityDonut(v) {
    var legend = [['Critical', 'crit', v.sevCounts.crit], ['High', 'high', v.sevCounts.high], ['Medium', 'med', v.sevCounts.med], ['Low', 'low', v.sevCounts.low]];
    return kCard(kCardLabel('Severity distribution') +
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
    var E = exalm();
    var state = E.state || {};
    var max = Math.max.apply(null, v.NS.map(function (n) { return n.findings; }).concat([1]));
    var rows = v.NS.slice().sort(function (a, b) { return b.findings - a.findings; }).slice(0, 9).map(function (n) {
      var active = state.selectedNs === n.key;
      return '<button data-act="ns-select" data-ns="' + esc(n.key) + '" style="display:flex;align-items:center;gap:10px;width:100%;border:none;background:transparent;cursor:pointer;padding:3px 0;">' +
        '<span style="width:120px;text-align:right;font-family:\'IBM Plex Mono\',monospace;font-size:11px;color:' + (active ? 'var(--accent)' : 'var(--muted)') + ';white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">' + esc(n.key) + '</span>' +
        '<span style="flex:1;height:14px;background:var(--track);border-radius:4px;overflow:hidden;"><span style="display:block;height:100%;width:' + Math.max(4, (n.findings / max) * 100) + '%;background:' + n.color + ';border-radius:4px;transition:width .3s;"></span></span>' +
        '<span style="width:26px;text-align:left;font-size:11px;font-weight:600;color:var(--fg);">' + n.findings + '</span></button>';
    }).join('');
    return kCard(kCardLabel('Findings by namespace') + '<div style="display:flex;flex-direction:column;gap:6px;margin-top:14px;">' + (rows || '<div style="color:var(--faint);font-size:12px;">No namespaces.</div>') + '</div>');
  }

  // ── Error frequency time-series (Cluster/Namespace toggle) ──
  function errorFreq(v) {
    var E = exalm();
    var state = E.state || {};
    var toggle = ['cluster', 'namespace'].map(function (k) {
      var a = state.freqScope === k;
      return '<button data-act="freqscope" data-v="' + k + '" style="padding:4px 11px;border-radius:7px;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.4px;cursor:pointer;border:1px solid ' + (a ? 'var(--accent)' : 'var(--border)') + ';background:' + (a ? 'var(--accentSoft)' : 'transparent') + ';color:' + (a ? 'var(--accent)' : 'var(--muted)') + ';">' + k + '</button>';
    }).join('');
    var legend = [['crit', 'critical'], ['high', 'high'], ['med', 'medium'], ['low', 'low']].map(function (x) { return '<span style="display:flex;align-items:center;gap:5px;font-size:10.5px;color:var(--muted);"><span style="width:8px;height:8px;border-radius:2px;background:var(--' + x[0] + ');"></span>' + x[1] + '</span>'; }).join('');
    var bars = v.tsBars.map(function (b) {
      return '<div class="ex-chart-bar" data-act="drilldown" data-kind="time" data-label="' + esc(b.title) + '" title="' + esc(b.title) + '" style="flex:1;display:flex;flex-direction:column;justify-content:flex-end;min-width:0;cursor:pointer;">' +
        b.segs.map(function (sg) { return '<div style="width:100%;height:' + sg.h + 'px;background:' + sg.bg + ';border-radius:' + (sg.first ? '3px 3px 0 0' : '0') + ';"></div>'; }).join('') + '</div>';
    }).join('');
    return kCard('<div style="display:flex;align-items:center;justify-content:space-between;gap:10px;flex-wrap:wrap;margin-bottom:8px;">' +
      '<div>' + kCardLabel('Error frequency · last 24h') + '<div style="font-size:11px;color:var(--muted);margin-top:2px;">Findings trend ' + (state.freqScope === 'namespace' && !v.allMode ? 'by namespace · ' + esc(v.nsLabel) : 'by cluster') + '</div></div>' +
      '<div style="display:flex;gap:6px;">' + toggle + '</div></div>' +
      '<div style="display:flex;gap:14px;margin-bottom:8px;">' + legend + '</div>' +
      '<div style="display:flex;align-items:flex-end;gap:3px;height:150px;">' + bars + '</div>' +
      '<div style="display:flex;justify-content:space-between;margin-top:7px;font-family:\'IBM Plex Mono\',monospace;font-size:10px;color:var(--faint);"><span>00:00</span><span>06:00</span><span>12:00</span><span>18:00</span><span>now</span></div>');
  }

  // ── Hover tooltips for .ex-chart-bar elements (moved from charts.js) ──

  var tip = null;

  function ensureTip() {
    if (tip) return tip;
    tip = document.createElement('div');
    tip.id = 'ex-chart-tip';
    tip.style.cssText =
      'position:fixed;z-index:90;pointer-events:none;display:none;max-width:280px;' +
      'background:var(--panel,#11161f);color:var(--fg,#e6edf3);border:1px solid var(--border,#222b3a);' +
      'border-radius:9px;box-shadow:0 10px 28px rgba(0,0,0,.45);padding:8px 11px;font-size:11.5px;line-height:1.5;' +
      "font-family:'IBM Plex Sans',system-ui,sans-serif;";
    document.body.appendChild(tip);
    return tip;
  }

  function show(html, x, y) {
    var t = ensureTip();
    t.innerHTML = html;
    t.style.display = 'block';
    // Keep within the viewport.
    var w = t.offsetWidth, vw = window.innerWidth;
    var left = x + 14; if (left + w > vw - 8) left = x - w - 14;
    t.style.left = Math.max(8, left) + 'px';
    t.style.top = (y + 14) + 'px';
  }
  function hide() { if (tip) tip.style.display = 'none'; }

  // Parse "12:00 · 7 findings" into a richer tooltip.
  function barTip(label) {
    var faint = 'color:var(--faint);';
    var parts = String(label || '').split('·');
    var when = (parts[0] || '').trim();
    var count = (parts[1] || '').trim();
    return '<div style="font-weight:600;margin-bottom:2px;">' + when + '</div>' +
      '<div>' + count + '</div>' +
      '<div style="' + faint + 'margin-top:4px;">Click to drill down — metrics, logs, changes & findings for this window.</div>';
  }

  function attachTooltips() {
    var bars = document.querySelectorAll('.ex-chart-bar');
    bars.forEach(function (bar) {
      if (bar._exTipWired) return;
      bar._exTipWired = true;
      // Suppress the native title tooltip in favour of our styled one.
      var label = bar.getAttribute('data-label') || bar.getAttribute('title') || '';
      bar.removeAttribute('title');
      bar.addEventListener('mousemove', function (e) { show(barTip(label), e.clientX, e.clientY); });
      bar.addEventListener('mouseleave', hide);
    });
  }

  // ── Drill menu: click a .ex-an-drill element → floating action menu ──
  // opts = { onLogs(query), onInvestigate(query, label) }. The Investigate
  // item is only rendered when the server supports AI features.

  function closeDrillMenu() {
    var m = document.getElementById('ex-widget-menu');
    if (m) m.remove();
  }

  function openDrillMenu(x, y, query, label, opts) {
    closeDrillMenu();
    var menu = document.createElement('div');
    menu.id = 'ex-widget-menu';
    menu.style.cssText =
      'position:fixed;z-index:95;min-width:190px;background:var(--panel,#11161f);color:var(--fg,#e6edf3);' +
      'border:1px solid var(--border,#222b3a);border-radius:10px;box-shadow:0 12px 34px rgba(0,0,0,.45);' +
      "padding:4px;font-family:'IBM Plex Sans',system-ui,sans-serif;font-size:12.5px;";
    var itemStyle = 'display:block;width:100%;text-align:left;border:none;background:transparent;color:var(--fg);cursor:pointer;font-family:inherit;font-size:12.5px;padding:8px 11px;border-radius:7px;';
    var supportsAI = !(window.__DASH__ && window.__DASH__.supportsAI === false);

    var logsBtn = document.createElement('button');
    logsBtn.style.cssText = itemStyle;
    logsBtn.textContent = '▤ Show related logs';
    logsBtn.addEventListener('click', function () { closeDrillMenu(); if (opts.onLogs) opts.onLogs(query); });
    menu.appendChild(logsBtn);

    if (supportsAI) {
      var invBtn = document.createElement('button');
      invBtn.style.cssText = itemStyle + 'color:var(--accent);';
      invBtn.textContent = '✦ Investigate';
      invBtn.addEventListener('click', function () { closeDrillMenu(); if (opts.onInvestigate) opts.onInvestigate(query, label); });
      menu.appendChild(invBtn);
    }

    document.body.appendChild(menu);
    // Position at the click, kept inside the viewport.
    var mw = menu.offsetWidth, mh = menu.offsetHeight;
    var left = x, top = y + 4;
    if (left + mw > window.innerWidth - 8) left = window.innerWidth - mw - 8;
    if (top + mh > window.innerHeight - 8) top = y - mh - 4;
    menu.style.left = Math.max(8, left) + 'px';
    menu.style.top = Math.max(8, top) + 'px';
  }

  // Close the menu on any click outside it.
  document.addEventListener('click', function (e) {
    var m = document.getElementById('ex-widget-menu');
    if (m && !m.contains(e.target)) closeDrillMenu();
  }, true);

  // attachDrillMenu wires .ex-an-drill clicks inside rootEl to the floating
  // menu. Idempotent per root element.
  function attachDrillMenu(rootEl, opts) {
    if (!rootEl || rootEl._exDrillMenuWired) return;
    rootEl._exDrillMenuWired = true;
    opts = opts || {};
    rootEl.addEventListener('click', function (e) {
      var drill = e.target.closest ? e.target.closest('.ex-an-drill') : null;
      if (!drill) return;
      var query = drill.getAttribute('data-drill') || '';
      var label = drill.getAttribute('title') || (drill.textContent || '').trim();
      openDrillMenu(e.clientX, e.clientY, query, label, opts);
    });
  }

  window.ExalmWidgets = {
    sevColor: sevColor, pick: pick, panel: panel, card: card, lbl: lbl,
    timelineChart: timelineChart, barList: barList, counters: counters,
    statCards: statCards, severityDonut: severityDonut, nsBars: nsBars, errorFreq: errorFreq,
    attachTooltips: attachTooltips, attachDrillMenu: attachDrillMenu
  };
  // The dashboard's first paint may happen before this module loads on legacy
  // pages; wire any already-rendered chart bars now.
  attachTooltips();
})();
