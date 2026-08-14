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

  // currentAnalyzer tracks the analyzer whose page was last rendered — the
  // payload's own analyzer in legacy mode, or whichever live hub dashboard
  // render() was called with.
  var currentAnalyzer = (window.__DASH__ && window.__DASH__.analyzer) || '';

  // apiBase resolves the analyzer API root: registry mode routes through the
  // per-dashboard prefix; legacy single-analyzer mode keeps /api/analyzer.
  function apiBase() {
    return (window.__DASH__ && window.__DASH__.dashboards && window.__DASH__.dashboards.length)
      ? '/api/dashboards/' + encodeURIComponent(currentAnalyzer)
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
        panel('Top user agents', barList(pick(st, 'topUserAgents') || [], 'contains')) +
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

  function pageCloudTrail(st) {
    return section('Overview',
      panel('Signals', counters([
        { label: 'Root account usage', value: pick(st, 'rootUsage') || 0, color: 'var(--crit)', drill: 'contains=' + encodeURIComponent('"type":"Root"') },
        { label: 'Access denied', value: pick(st, 'accessDenied') || 0, color: 'var(--high)', drill: 'code=AccessDenied' },
        { label: 'Console login failures', value: pick(st, 'consoleLoginFailures') || 0, color: 'var(--med)', drill: 'unit=ConsoleLogin' },
        { label: 'Resource deletions', value: pick(st, 'resourceDeletions') || 0, color: 'var(--med)', drill: 'contains=Delete' }
      ]))) +
      section('Charts', '<div style="' + grid2 + '">' +
        panel('Events over time', timelineChart(pick(st, 'eventTimeline') || [], '')) +
        panel('Top event names', barList(pick(st, 'topEventNames') || [], 'unit')) +
        panel('Top principals', barList(pick(st, 'topPrincipals') || [], 'contains')) +
        panel('Top source IPs', barList(pick(st, 'topSourceIps', 'topSourceIPs') || [], 'contains')) +
        '</div>');
  }

  var PAGES = { syslog: pageSyslog, httplog: pageHTTP, eventlog: pageEventlog, iis: pageIIS, logs: pageLogs, cloudtrail: pageCloudTrail };

  // ── drilldown: chart click → shared logs explorer over the corpus API ──

  function drillPanelHTML() {
    return '<div id="ex-an-drillpanel" style="display:none;' + card + 'margin-top:2px;">' +
      '<div style="display:flex;align-items:center;gap:8px;margin-bottom:8px;">' +
      '<span style="' + lbl + 'margin-bottom:0;">Matching log lines</span><span style="flex:1;"></span>' +
      '<button id="ex-an-drillclose" style="border:1px solid var(--border);background:var(--panel2);color:var(--muted);border-radius:6px;cursor:pointer;font-size:10.5px;padding:2px 9px;">✕ close</button></div>' +
      '<div id="ex-an-drillmount"></div></div>';
  }

  // parseDrillQuery turns a chart element's data-drill query string into the
  // explorer's filter object.
  //
  // from/to are an exact time range and are passed straight through to the
  // corpus query. "bucket=HH:MM" is the legacy form emitted by charts whose
  // stats payload has no bucket instant: it can only be matched as text against
  // the timestamp, which is why buckets now carry `at`.
  function parseDrillQuery(query) {
    var filters = {};
    String(query || '').split('&').forEach(function (pair) {
      if (!pair) return;
      var eq = pair.indexOf('=');
      var k = eq === -1 ? pair : pair.slice(0, eq);
      var v = eq === -1 ? '' : decodeURIComponent(pair.slice(eq + 1).replace(/\+/g, ' '));
      if (k === 'bucket') { k = 'contains'; }
      if (k === 'severity' || k === 'unit' || k === 'scope' || k === 'code' ||
        k === 'contains' || k === 'from' || k === 'to') filters[k] = v;
    });
    return filters;
  }

  function qs(filters) {
    var parts = [];
    ['severity', 'unit', 'scope', 'code', 'contains', 'from', 'to'].forEach(function (k) {
      if (filters[k]) parts.push(k + '=' + encodeURIComponent(filters[k]));
    });
    return parts.join('&');
  }

  // corpusExplorerConfig builds the shared-explorer config for one analyzer
  // dashboard — the drilldown panel and the investigation workspace's Logs
  // pane both use it, so there is exactly one corpus wiring. The API base
  // derives from the analyzerId ARGUMENT, not the module's currentAnalyzer:
  // the workspace mounts before this module's render() has run (hub stats
  // load asynchronously), when currentAnalyzer is still empty or stale.
  function corpusExplorerConfig(analyzerId, initialFilters) {
    var base = (window.__DASH__ && window.__DASH__.dashboards && window.__DASH__.dashboards.length)
      ? '/api/dashboards/' + encodeURIComponent(analyzerId)
      : '/api/analyzer';
    return {
      mode: 'corpus',
      initialFilters: initialFilters || {},
      capabilities: { search: true, severity: true, source: true, time: true, export: true, context: true },
      downloadName: analyzerId + '-logs',
      // Route line analysis through the dashboard-scoped endpoint: the hub
      // wires AnalyzeLine per ingested session, while the legacy global
      // /api/logs/analyze is only bound in single-analyzer mode.
      analyzeURL: base + '/logs/analyze',
      fetchLogs: function (f) {
        return fetch(base + '/logs?' + qs(f) + '&limit=200').then(function (r) {
          if (!r.ok) throw new Error('HTTP ' + r.status);
          return r.json();
        });
      },
      fetchContext: function (ev, n) {
        var anchor = ev.idx != null ? ev.idx : encodeURIComponent(ev.at || '');
        return fetch(base + '/logs?around=' + anchor + '&context=' + n).then(function (r) {
          if (!r.ok) throw new Error('HTTP ' + r.status);
          return r.json();
        });
      },
      analyzeMeta: function (ev) {
        return { namespace: ev.scope || '', pod: ev.unit || '', severity: ev.severity || '', source: analyzerId };
      },
      onInvestigate: function (ev) {
        if (window.ExalmChat && window.ExalmChat.ask) {
          window.ExalmChat.ask('Investigate this ' + (ev.severity || 'log') + ' line from ' + (ev.unit || ev.scope || analyzerId) + ': ' + ev.raw);
        }
      },
      onJumpToResource: function (ev) {
        var res = ev.unit || ev.scope;
        if (res && window.ExalmChat && window.ExalmChat.ask) {
          window.ExalmChat.ask('What is the status of ' + res + '?');
        }
      }
    };
  }

  function runDrill(query) {
    var panelEl = document.getElementById('ex-an-drillpanel');
    var mount = document.getElementById('ex-an-drillmount');
    if (!panelEl || !mount || !window.ExalmLogExplorer) return;
    panelEl.style.display = 'block';
    window.ExalmLogExplorer.create(mount, corpusExplorerConfig(currentAnalyzer, parseDrillQuery(query)));
  }

  // render builds the whole analyzer dashboard page body.
  function render(data) {
    var builder = PAGES[data.analyzer];
    if (!builder) return '<div style="color:var(--faint);">No dashboard for analyzer ' + esc(data.analyzer) + '.</div>';
    currentAnalyzer = data.analyzer;
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
      if (closeBtn) { document.getElementById('ex-an-drillpanel').style.display = 'none'; }
    });
  }

  window.AnalyzerDash = { render: render, attach: attach, corpusExplorerConfig: corpusExplorerConfig };

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
