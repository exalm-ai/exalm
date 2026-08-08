'use strict';
// logviewer.js — the k8s pod-log drawer: namespace/pod/container selection,
// current vs previous logs, and a live-tail poll against /api/logs (the
// already-connected cluster client). Filtering, severity colorize, export,
// line selection, ✦ analysis, and context all live in the shared
// ExalmLogExplorer view (logexplorer.js) — this file owns only the k8s
// target-selection shell and the fetch loop, and pushes lines into the
// explorer via setEvents.

(function () {
  var E = window.Exalm || {};
  var esc = E.esc || function (s) { return String(s == null ? '' : s); };

  var root = document.getElementById('ex-logviewer');
  if (!root) { root = document.createElement('div'); root.id = 'ex-logviewer'; document.body.appendChild(root); }

  var liveTimer = null;
  var explorer = null; // ExalmLogExplorer handle for the open drawer

  function close() {
    if (liveTimer) { clearInterval(liveTimer); liveTimer = null; }
    if (explorer) { explorer.destroy(); explorer = null; }
    root.innerHTML = ''; root.style.display = 'none';
  }
  document.addEventListener('keydown', function (e) { if (e.key === 'Escape') close(); });

  // Pod suggestions from the current findings (namespace/name paths).
  function podOptions() {
    var seen = {}, opts = [];
    (E.findings ? E.findings() : []).forEach(function (f) {
      var ns = f.nsKey || '', path = f.ns || '';
      var name = path.indexOf('/') !== -1 ? path.split('/')[1] : path;
      var key = ns + '|' + name;
      if (name && !seen[key]) { seen[key] = true; opts.push({ ns: ns, pod: name }); }
    });
    return opts;
  }

  function ctrl(styleExtra) {
    return 'height:30px;border-radius:8px;border:1px solid var(--border);background:var(--panel2);color:var(--fg);font-family:inherit;font-size:12.5px;padding:0 9px;outline:none;' + (styleExtra || '');
  }

  function shell() {
    var opts = podOptions();
    var podList = opts.map(function (o) { return '<option value="' + esc(o.pod) + '" data-ns="' + esc(o.ns) + '">' + esc(o.ns + '/' + o.pod) + '</option>'; }).join('');
    root.style.display = 'block';
    root.innerHTML =
      '<div class="ex-lv-backdrop" style="position:fixed;inset:0;background:rgba(0,0,0,.5);z-index:85;"></div>' +
      '<div style="position:fixed;z-index:86;top:0;right:0;height:100vh;width:min(900px,96vw);background:var(--panel);border-left:1px solid var(--border);display:flex;flex-direction:column;color:var(--fg);font-family:var(--font-sans),system-ui,sans-serif;box-shadow:-16px 0 40px rgba(0,0,0,.4);">' +
      '<div style="display:flex;align-items:center;gap:10px;padding:13px 16px;border-bottom:1px solid var(--border);">' +
      '<span style="font-size:14px;font-weight:700;">▤ Log viewer</span><span style="flex:1;"></span>' +
      '<button class="ex-lv-close" style="border:1px solid var(--border);background:var(--panel2);color:var(--fg);border-radius:8px;cursor:pointer;font-size:13px;padding:4px 10px;">✕</button></div>' +
      // target selection row (k8s-specific, stays here)
      '<div style="display:flex;gap:8px;flex-wrap:wrap;padding:11px 16px 0;">' +
      '<select id="ex-lv-pod" style="' + ctrl('min-width:220px;') + '"><option value="">— pick a pod —</option>' + podList + '</select>' +
      '<input id="ex-lv-ns" placeholder="namespace" style="' + ctrl('width:130px;') + '">' +
      '<input id="ex-lv-container" placeholder="container (optional)" style="' + ctrl('width:170px;') + '">' +
      '<label style="display:flex;align-items:center;gap:5px;font-size:12px;color:var(--muted);"><input type="checkbox" id="ex-lv-prev"> previous</label>' +
      '<input id="ex-lv-tail" type="number" value="500" min="1" max="5000" title="tail lines" style="' + ctrl('width:80px;') + '">' +
      '<button id="ex-lv-fetch" style="height:30px;border:none;background:var(--accent);color:#fff;border-radius:8px;cursor:pointer;font-size:12.5px;font-weight:600;padding:0 14px;">Fetch</button>' +
      '<label style="display:flex;align-items:center;gap:5px;font-size:12px;color:var(--muted);"><input type="checkbox" id="ex-lv-live"> live tail</label></div>' +
      // shared explorer (filters, lines, export, analyze, context)
      '<div id="ex-lv-explorer" style="flex:1;display:flex;flex-direction:column;min-height:0;padding:9px 16px;overflow-y:auto;"></div>' +
      '<div id="ex-lv-status" style="padding:7px 16px;border-top:1px solid var(--border);font-size:11px;color:var(--faint);">Pick a pod and click Fetch. Click a log line, then ✦ Analyze for an AI root-cause breakdown.</div></div>';

    root.querySelector('.ex-lv-backdrop').addEventListener('click', close);
    root.querySelector('.ex-lv-close').addEventListener('click', close);

    var podSel = root.querySelector('#ex-lv-pod');
    podSel.addEventListener('change', function () {
      var opt = podSel.options[podSel.selectedIndex];
      if (opt) root.querySelector('#ex-lv-ns').value = opt.getAttribute('data-ns') || '';
    });
    // Prefill with the first suggested pod.
    if (opts.length) { podSel.value = opts[0].pod; root.querySelector('#ex-lv-ns').value = opts[0].ns; }

    explorer = window.ExalmLogExplorer.create(root.querySelector('#ex-lv-explorer'), {
      mode: 'raw',
      // Raw k8s tail lines carry no parsed timestamps or units — hide the
      // corpus-only filters; context is client-side (clear filters + scroll).
      capabilities: { search: true, severity: true, export: true, context: true, time: false, source: false },
      severityOptions: ['error', 'warn', 'info'],
      downloadName: 'pod-logs',
      analyzeMeta: function () {
        return { namespace: val('#ex-lv-ns'), pod: val('#ex-lv-pod'), container: val('#ex-lv-container') };
      },
      onInvestigate: function (ev) {
        var pod = val('#ex-lv-pod'), ns = val('#ex-lv-ns');
        close();
        if (window.ExalmChat && window.ExalmChat.ask) {
          window.ExalmChat.ask('Investigate this log line from pod ' + (ns ? ns + '/' : '') + pod + ': ' + ev.raw);
        }
      }
    });

    root.querySelector('#ex-lv-fetch').addEventListener('click', doFetch);
    root.querySelector('#ex-lv-live').addEventListener('change', function (e) {
      if (e.target.checked) { liveTimer = setInterval(doFetch, 4000); } else if (liveTimer) { clearInterval(liveTimer); liveTimer = null; }
    });
  }

  function val(id) { var el = root.querySelector(id); return el ? el.value : ''; }
  function checked(id) { var el = root.querySelector(id); return el && el.checked; }

  function doFetch() {
    var pod = val('#ex-lv-pod') || '';
    var ns = val('#ex-lv-ns'), container = val('#ex-lv-container');
    if (!pod) { setStatus('Pick a pod first.'); return; }
    var tail = parseInt(val('#ex-lv-tail'), 10) || 500;
    var url = '/api/logs?pod=' + encodeURIComponent(pod) + '&ns=' + encodeURIComponent(ns) +
      '&container=' + encodeURIComponent(container) + '&previous=' + (checked('#ex-lv-prev') ? 'true' : 'false') + '&tail=' + tail;
    setStatus('Fetching…');
    fetch(url).then(function (r) {
      if (r.status === 503) return { error: 'Log access is unavailable in this mode (no cluster connection).' };
      return r.json();
    }).then(function (d) {
      if (d.error) { setStatus(d.error); if (explorer) explorer.setEvents([]); return; }
      var raw = d.lines || '';
      var lines = raw ? raw.split('\n') : [];
      setStatus(lines.length + ' lines · ' + esc(ns || '') + '/' + esc(pod) + (d.previous ? ' (previous)' : ''));
      if (explorer) {
        explorer.setEvents(lines.map(function (l) { return { raw: l }; }));
      }
    }).catch(function (err) { setStatus('Error: ' + err.message); });
  }

  function setStatus(s) { var el = root.querySelector('#ex-lv-status'); if (el) el.textContent = s; }

  window.ExalmLogs = { open: shell, close: close };
})();
