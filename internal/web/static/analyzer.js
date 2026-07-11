'use strict';
// analyzer.js — the per-analyzer dashboards (syslog / httplog / eventlog /
// iis / logs). Active only when the payload carries __DASH__.analyzer; the
// k8s dashboard is untouched. Panels render from the analyzer-typed stats
// payload via the shared ExalmWidgets chart library, and EVERY chart element
// carries data-drill filters — clicking it opens a small menu to either show
// the matching corpus lines or hand the query to the AI investigation chat.

(function () {
  var E = window.Exalm || {};
  var esc = E.esc || function (s) { return String(s == null ? '' : s); };
  var W = window.ExalmWidgets;

  var sevColor = W.sevColor, pick = W.pick, panel = W.panel;
  var card = W.card, lbl = W.lbl;
  var timelineChart = W.timelineChart, barList = W.barList, counters = W.counters;

  // apiBase resolves the analyzer API root: registry mode routes through the
  // per-dashboard prefix; legacy single-analyzer mode keeps /api/analyzer.
  function apiBase() {
    return (window.__DASH__ && window.__DASH__.dashboards && window.__DASH__.dashboards.length)
      ? '/api/dashboards/' + encodeURIComponent(window.__DASH__.analyzer)
      : '/api/analyzer';
  }

  var grid2 = 'display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:14px;';

  // section wraps a page area in a consistently styled collapsible block.
  function section(title, inner) {
    return '<details open style="margin-bottom:14px;">' +
      '<summary style="cursor:pointer;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.6px;color:var(--muted);margin-bottom:10px;">' + esc(title) + '</summary>' +
      inner + '</details>';
  }

  // ── per-analyzer page builders ──

  function pageSyslog(st) {
    return section('Overview',
      panel('Signals', counters([
        { label: 'Auth failures', value: pick(st, 'authFailures') || 0, color: 'var(--high)', drill: 'contains=' + encodeURIComponent('authentication failure') },
        { label: 'OOM events', value: pick(st, 'oomEvents', 'ooms') || 0, color: 'var(--crit)', drill: 'contains=' + encodeURIComponent('out of memory') },
        { label: 'Disk errors', value: pick(st, 'diskErrors') || 0, color: 'var(--med)', drill: 'contains=' + encodeURIComponent('no space left') }
      ]))) +
      section('Charts', '<div style="' + grid2 + '">' +
        panel('Severity timeline', timelineChart(pick(st, 'severityTimeline', 'errorTimeline') || [], '')) +
        panel('Top failing units', barList(pick(st, 'topUnits') || [], 'unit', function () { return 'var(--high)'; })) +
        panel('Top hosts', barList(pick(st, 'topHosts') || [], 'scope')) +
        '</div>');
  }

  function pageHTTP(st) {
    return section('Overview',
      panel('Latency & volume', counters([
        { label: 'Slow requests (>5s)', value: pick(st, 'slowRequests') || 0, color: 'var(--med)' },
        { label: 'Top URI count', value: (pick(st, 'topURIs', 'topUris') || []).length }
      ]))) +
      section('Charts', '<div style="' + grid2 + '">' +
        panel('Requests over time', timelineChart(pick(st, 'requestTimeline') || [], '')) +
        panel('5xx bursts', timelineChart(pick(st, 'bursts5xx', 'bursts5XX') || [], 'severity=5xx')) +
        panel('Status codes', barList(pick(st, 'codeHistogram') || [], 'code', function (n) { return sevColor(n.charAt(0) + 'xx'); })) +
        panel('Top URLs', barList(pick(st, 'topURIs', 'topUris') || [], 'unit')) +
        panel('Top clients', barList(pick(st, 'topClients') || [], 'contains')) +
        '</div>');
  }

  function pageEventlog(st) {
    return section('Overview',
      panel('Signals', counters([
        { label: 'Service events', value: pick(st, 'serviceEvents') || 0, color: 'var(--high)', drill: 'unit=' + encodeURIComponent('Service Control Manager') },
        { label: 'Reboots', value: pick(st, 'reboots') || 0, color: 'var(--med)', drill: 'code=6008' },
        { label: 'Auth failures (4625)', value: pick(st, 'authFailures') || 0, color: 'var(--crit)', drill: 'code=4625' }
      ]))) +
      section('Charts', '<div style="' + grid2 + '">' +
        panel('Event level timeline', timelineChart(pick(st, 'levelTimeline') || [], '')) +
        panel('Top event IDs', barList(pick(st, 'topEventIDs', 'topEventIds') || [], 'code', function () { return 'var(--accent)'; })) +
        panel('Top providers', barList(pick(st, 'topProviders') || [], 'unit')) +
        '</div>');
  }

  function pageIIS(st) {
    return section('Overview',
      panel('Slow requests', counters([{ label: 'Requests >5s', value: pick(st, 'slowRequests') || 0, color: 'var(--med)' }]))) +
      section('Charts', '<div style="' + grid2 + '">' +
        panel('Requests over time', timelineChart(pick(st, 'requestTimeline') || [], '')) +
        panel('Status codes', barList(pick(st, 'codeHistogram') || [], 'code', function (n) { return sevColor(n.charAt(0) + 'xx'); })) +
        panel('Top sites / pools', barList(pick(st, 'topSites', 'topPools') || [], 'scope')) +
        panel('Top URIs', barList(pick(st, 'topURIs', 'topUris') || [], 'unit')) +
        '</div>');
  }

  function pageLogs(st) {
    return section('Charts', '<div style="' + grid2 + '">' +
      panel('Errors over time', timelineChart(pick(st, 'errorTimeline') || [], 'severity=error')) +
      panel('Severity mix', barList(pick(st, 'severityCounts') || [], 'severity', function (n) { return sevColor(n); })) +
      '</div>');
  }

  var PAGES = { syslog: pageSyslog, httplog: pageHTTP, eventlog: pageEventlog, iis: pageIIS, logs: pageLogs };

  // ── drilldown: chart click → analyzer logs API → corpus lines ──

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
    fetch(apiBase() + '/logs?' + q + '&limit=200').then(function (r) {
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

  // attach wires the drill menu + analyze clicks; idempotent per repaint.
  function attach() {
    var root = document.getElementById('analyzer-dash-root');
    if (!root || root._exWired) return;
    root._exWired = true;
    W.attachDrillMenu(root, {
      onLogs: runDrill,
      onInvestigate: function (query, label) {
        if (window.ExalmChat && window.ExalmChat.ask) {
          window.ExalmChat.ask('Investigate ' + label + ' (' + query + ')');
        } else {
          runDrill(query);
        }
      }
    });
    root.addEventListener('click', function (e) {
      var closeBtn = e.target.closest('#ex-an-drillclose');
      if (closeBtn) { document.getElementById('ex-an-drillpanel').style.display = 'none'; return; }
      var analyze = e.target.closest('.ex-an-analyze');
      if (analyze) {
        var out = document.getElementById('ex-an-drillout');
        var events = out._events || [];
        var ev = events[+analyze.getAttribute('data-idx')];
        if (ev) analyzeRow(ev, events);
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
