'use strict';
// analyzer.js — the per-analyzer dashboards (syslog / httplog / eventlog /
// iis / logs). Active only when the payload carries __DASH__.analyzer; the
// k8s dashboard is untouched. Panels render from the analyzer-typed stats
// payload, and EVERY chart element carries data-drill filters — clicking it
// queries /api/analyzer/logs and opens the matching corpus lines, each with
// the ✦ Analyze line action.

(function () {
  var E = window.Exalm || {};
  var esc = E.esc || function (s) { return String(s == null ? '' : s); };

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
      return '<div class="ex-an-drill" data-drill="' + esc(dim + '=' + encodeURIComponent(it.name)) + '" style="display:flex;align-items:center;gap:9px;padding:3px 0;cursor:pointer;">' +
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

  var grid2 = 'display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:14px;';

  // ── per-analyzer page builders ──

  function pageSyslog(st) {
    return '<div style="' + grid2 + '">' +
      panel('Severity timeline', timelineChart(pick(st, 'severityTimeline', 'errorTimeline') || [], '')) +
      panel('Signals', counters([
        { label: 'Auth failures', value: pick(st, 'authFailures') || 0, color: 'var(--high)', drill: 'contains=' + encodeURIComponent('authentication failure') },
        { label: 'OOM events', value: pick(st, 'oomEvents', 'ooms') || 0, color: 'var(--crit)', drill: 'contains=' + encodeURIComponent('out of memory') },
        { label: 'Disk errors', value: pick(st, 'diskErrors') || 0, color: 'var(--med)', drill: 'contains=' + encodeURIComponent('no space left') }
      ])) +
      panel('Top failing units', barList(pick(st, 'topUnits') || [], 'unit', function () { return 'var(--high)'; })) +
      panel('Top hosts', barList(pick(st, 'topHosts') || [], 'scope')) +
      '</div>';
  }

  function pageHTTP(st) {
    return '<div style="' + grid2 + '">' +
      panel('Requests over time', timelineChart(pick(st, 'requestTimeline') || [], '')) +
      panel('5xx bursts', timelineChart(pick(st, 'bursts5xx', 'bursts5XX') || [], 'severity=5xx')) +
      panel('Status codes', barList(pick(st, 'codeHistogram') || [], 'code', function (n) { return sevColor(n.charAt(0) + 'xx'); })) +
      panel('Latency & volume', counters([
        { label: 'Slow requests (>5s)', value: pick(st, 'slowRequests') || 0, color: 'var(--med)' },
        { label: 'Top URI count', value: (pick(st, 'topURIs', 'topUris') || []).length }
      ])) +
      panel('Top URLs', barList(pick(st, 'topURIs', 'topUris') || [], 'unit')) +
      panel('Top clients', barList(pick(st, 'topClients') || [], 'contains')) +
      '</div>';
  }

  function pageEventlog(st) {
    return '<div style="' + grid2 + '">' +
      panel('Event level timeline', timelineChart(pick(st, 'levelTimeline') || [], '')) +
      panel('Signals', counters([
        { label: 'Service events', value: pick(st, 'serviceEvents') || 0, color: 'var(--high)', drill: 'unit=' + encodeURIComponent('Service Control Manager') },
        { label: 'Reboots', value: pick(st, 'reboots') || 0, color: 'var(--med)', drill: 'code=6008' },
        { label: 'Auth failures (4625)', value: pick(st, 'authFailures') || 0, color: 'var(--crit)', drill: 'code=4625' }
      ])) +
      panel('Top event IDs', barList(pick(st, 'topEventIDs', 'topEventIds') || [], 'code', function () { return 'var(--accent)'; })) +
      panel('Top providers', barList(pick(st, 'topProviders') || [], 'unit')) +
      '</div>';
  }

  function pageIIS(st) {
    return '<div style="' + grid2 + '">' +
      panel('Requests over time', timelineChart(pick(st, 'requestTimeline') || [], '')) +
      panel('Status codes', barList(pick(st, 'codeHistogram') || [], 'code', function (n) { return sevColor(n.charAt(0) + 'xx'); })) +
      panel('Slow requests', counters([{ label: 'Requests >5s', value: pick(st, 'slowRequests') || 0, color: 'var(--med)' }])) +
      panel('Top sites / pools', barList(pick(st, 'topSites', 'topPools') || [], 'scope')) +
      panel('Top URIs', barList(pick(st, 'topURIs', 'topUris') || [], 'unit')) +
      '</div>';
  }

  function pageLogs(st) {
    return '<div style="' + grid2 + '">' +
      panel('Errors over time', timelineChart(pick(st, 'errorTimeline') || [], 'severity=error')) +
      panel('Severity mix', barList(pick(st, 'severityCounts') || [], 'severity', function (n) { return sevColor(n); })) +
      '</div>';
  }

  var PAGES = { syslog: pageSyslog, httplog: pageHTTP, eventlog: pageEventlog, iis: pageIIS, logs: pageLogs };

  // ── drilldown: chart click → /api/analyzer/logs → corpus lines ──

  function drillPanelHTML() {
    return '<div id="ex-an-drillpanel" style="display:none;' + card + 'margin-top:2px;">' +
      '<div style="display:flex;align-items:center;gap:8px;margin-bottom:8px;">' +
      '<span style="' + lbl + 'margin-bottom:0;">Matching log lines</span>' +
      '<span id="ex-an-drillinfo" style="font-size:11px;color:var(--muted);"></span><span style="flex:1;"></span>' +
      '<button id="ex-an-drillclose" style="border:1px solid var(--border);background:var(--panel2);color:var(--muted);border-radius:6px;cursor:pointer;font-size:10.5px;padding:2px 9px;">✕ close</button></div>' +
      '<div id="ex-an-drillout" style="max-height:38vh;overflow:auto;font-family:\'IBM Plex Mono\',monospace;font-size:11px;line-height:1.5;background:var(--code);color:var(--codeFg);border-radius:8px;padding:8px 10px;"></div></div>';
  }

  function runDrill(query) {
    var panelEl = document.getElementById('ex-an-drillpanel');
    var out = document.getElementById('ex-an-drillout');
    var info = document.getElementById('ex-an-drillinfo');
    if (!panelEl || !out) return;
    panelEl.style.display = 'block';
    out.innerHTML = '<span style="color:var(--faint)">Loading…</span>';
    // "bucket=HH:MM" is a UI-side minute filter; translate via contains on
    // the timestamp text as a best-effort (corpus timestamps vary).
    var q = query.replace(/(^|&)bucket=([^&]*)/, function (_m, p, v) {
      return p + 'contains=' + v;
    });
    fetch('/api/analyzer/logs?' + q + '&limit=200').then(function (r) {
      if (!r.ok) throw new Error('HTTP ' + r.status);
      return r.json();
    }).then(function (d) {
      info.textContent = d.total + ' match(es)' + (d.truncated ? ' · corpus truncated by ' + d.truncated : '');
      if (!d.events || !d.events.length) {
        out.innerHTML = '<span style="color:var(--faint)">No matching lines.</span>';
        return;
      }
      out.innerHTML = d.events.map(function (e, i) {
        return '<div class="ex-an-row" data-idx="' + i + '" style="display:flex;gap:8px;align-items:baseline;padding:1px 2px;border-radius:4px;">' +
          '<span style="flex:1;white-space:pre-wrap;color:' + sevColor(e.severity) + ';">' + esc(e.raw) + '</span>' +
          '<button class="ex-an-analyze" data-idx="' + i + '" title="AI analysis of this line" style="border:1px solid var(--accent);background:transparent;color:var(--accent);border-radius:6px;cursor:pointer;font-size:9.5px;padding:1px 7px;flex:none;">✦</button></div>';
      }).join('');
      out._events = d.events;
    }).catch(function (err) {
      out.innerHTML = '<span style="color:var(--crit)">Drilldown failed: ' + esc(err.message) + '</span>';
    });
  }

  function analyzeRow(ev, allEvents) {
    var ctx = allEvents.map(function (e) { return e.raw; }).join('\n');
    var out = document.getElementById('ex-an-drillout');
    var d = window.__DASH__ || {};
    fetch('/api/logs/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Exalm-Request': 'true' },
      body: JSON.stringify({
        namespace: ev.scope || '', pod: ev.unit || '', severity: ev.severity || '',
        source: d.analyzer || '', message: ev.raw, context: ctx.slice(0, 20000)
      })
    }).then(function (r) {
      if (!r.ok) throw new Error(r.status === 503 ? 'AI analysis unavailable (no LLM configured)' : 'HTTP ' + r.status);
      return r.json();
    }).then(function (resp) {
      var html = (E.mdToHtml ? E.mdToHtml(resp.analysis) : esc(resp.analysis));
      out.insertAdjacentHTML('afterend',
        '<div class="ex-an-analysis" style="margin-top:10px;background:var(--panel2);border:1px solid var(--accent);border-radius:10px;padding:11px 14px;font-size:12.5px;line-height:1.6;color:var(--body);">' +
        '<div style="display:flex;"><span style="' + lbl + '">✦ AI analysis of the selected line</span><span style="flex:1"></span>' +
        '<button onclick="this.closest(\'.ex-an-analysis\').remove()" style="border:1px solid var(--border);background:var(--panel);color:var(--muted);border-radius:6px;cursor:pointer;font-size:10px;padding:1px 8px;">✕</button></div>' +
        html + '</div>');
    }).catch(function (err) {
      out.insertAdjacentHTML('afterend', '<div class="ex-an-analysis" style="margin-top:8px;color:var(--crit);font-size:12px;">⚠ ' + esc(err.message) + '</div>');
    });
  }

  // render builds the whole analyzer dashboard page body.
  function render(data) {
    var builder = PAGES[data.analyzer];
    if (!builder) return '<div style="color:var(--faint);">No dashboard for analyzer ' + esc(data.analyzer) + '.</div>';
    var truncNote = '';
    return builder(data.stats || {}) + drillPanelHTML() + truncNote;
  }

  // attach wires drill + analyze clicks; idempotent per repaint.
  function attach() {
    var root = document.getElementById('analyzer-dash-root');
    if (!root || root._exWired) return;
    root._exWired = true;
    root.addEventListener('click', function (e) {
      var closeBtn = e.target.closest('#ex-an-drillclose');
      if (closeBtn) { document.getElementById('ex-an-drillpanel').style.display = 'none'; return; }
      var analyze = e.target.closest('.ex-an-analyze');
      if (analyze) {
        var out = document.getElementById('ex-an-drillout');
        var events = out._events || [];
        var ev = events[+analyze.getAttribute('data-idx')];
        if (ev) analyzeRow(ev, events);
        return;
      }
      var drill = e.target.closest('.ex-an-drill');
      if (drill) {
        var q = drill.getAttribute('data-drill') || '';
        runDrill(q);
      }
    });
  }

  window.AnalyzerDash = { render: render, attach: attach };

  // dashboard.js's first paint happens before this module loads — fill the
  // analyzer panels now if the container is already on the page.
  (function () {
    var root = document.getElementById('analyzer-dash-root');
    var d = window.__DASH__ || {};
    if (root && d.analyzer) {
      root.innerHTML = render(d);
      attach();
    }
  })();
})();
