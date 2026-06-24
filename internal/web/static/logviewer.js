'use strict';
// logviewer.js — a dedicated log exploration drawer: namespace/pod/container
// selection, current vs previous logs, client-side search/regex/severity
// filtering, copy/download, and a live-tail poll. Fetches /api/logs (which uses
// the already-connected cluster client). Renders into its own #ex-logviewer
// container so it doesn't collide with the panels overlay.

(function () {
  var E = window.Exalm || {};
  var esc = E.esc || function (s) { return String(s == null ? '' : s); };

  var root = document.getElementById('ex-logviewer');
  if (!root) { root = document.createElement('div'); root.id = 'ex-logviewer'; document.body.appendChild(root); }

  var raw = '';           // last fetched raw log text
  var liveTimer = null;

  function close() {
    if (liveTimer) { clearInterval(liveTimer); liveTimer = null; }
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
      '<div style="position:fixed;z-index:86;top:0;right:0;height:100vh;width:min(900px,96vw);background:var(--panel);border-left:1px solid var(--border);display:flex;flex-direction:column;color:var(--fg);font-family:\'IBM Plex Sans\',system-ui,sans-serif;box-shadow:-16px 0 40px rgba(0,0,0,.4);">' +
      '<div style="display:flex;align-items:center;gap:10px;padding:13px 16px;border-bottom:1px solid var(--border);">' +
      '<span style="font-size:14px;font-weight:700;">▤ Log viewer</span><span style="flex:1;"></span>' +
      '<button class="ex-lv-close" style="border:1px solid var(--border);background:var(--panel2);color:var(--fg);border-radius:8px;cursor:pointer;font-size:13px;padding:4px 10px;">✕</button></div>' +
      // controls row 1: target
      '<div style="display:flex;gap:8px;flex-wrap:wrap;padding:11px 16px 0;">' +
      '<select id="ex-lv-pod" style="' + ctrl('min-width:220px;') + '"><option value="">— pick a pod —</option>' + podList + '</select>' +
      '<input id="ex-lv-ns" placeholder="namespace" style="' + ctrl('width:130px;') + '">' +
      '<input id="ex-lv-container" placeholder="container (optional)" style="' + ctrl('width:170px;') + '">' +
      '<label style="display:flex;align-items:center;gap:5px;font-size:12px;color:var(--muted);"><input type="checkbox" id="ex-lv-prev"> previous</label>' +
      '<input id="ex-lv-tail" type="number" value="500" min="1" max="5000" title="tail lines" style="' + ctrl('width:80px;') + '">' +
      '<button id="ex-lv-fetch" style="height:30px;border:none;background:var(--accent);color:#fff;border-radius:8px;cursor:pointer;font-size:12.5px;font-weight:600;padding:0 14px;">Fetch</button>' +
      '<label style="display:flex;align-items:center;gap:5px;font-size:12px;color:var(--muted);"><input type="checkbox" id="ex-lv-live"> live tail</label></div>' +
      // controls row 2: filters
      '<div style="display:flex;gap:8px;flex-wrap:wrap;padding:9px 16px;">' +
      '<input id="ex-lv-search" placeholder="filter (substring)…" style="' + ctrl('flex:1;min-width:160px;') + '">' +
      '<label style="display:flex;align-items:center;gap:5px;font-size:12px;color:var(--muted);"><input type="checkbox" id="ex-lv-regex"> regex</label>' +
      '<select id="ex-lv-sev" style="' + ctrl('') + '"><option value="">all levels</option><option value="error">error</option><option value="warn">warn</option><option value="info">info</option></select>' +
      '<button id="ex-lv-copy" style="' + ctrl('cursor:pointer;') + '">copy</button>' +
      '<button id="ex-lv-download" style="' + ctrl('cursor:pointer;') + '">download</button></div>' +
      // log area
      '<pre id="ex-lv-out" style="flex:1;overflow:auto;margin:0;padding:12px 16px;background:var(--code);color:var(--codeFg);font-family:\'IBM Plex Mono\',monospace;font-size:11.5px;line-height:1.5;white-space:pre-wrap;border-top:1px solid var(--border);"></pre>' +
      '<div id="ex-lv-status" style="padding:7px 16px;border-top:1px solid var(--border);font-size:11px;color:var(--faint);">Pick a pod and click Fetch.</div></div>';

    root.querySelector('.ex-lv-backdrop').addEventListener('click', close);
    root.querySelector('.ex-lv-close').addEventListener('click', close);

    var podSel = root.querySelector('#ex-lv-pod');
    podSel.addEventListener('change', function () {
      var opt = podSel.options[podSel.selectedIndex];
      if (opt) root.querySelector('#ex-lv-ns').value = opt.getAttribute('data-ns') || '';
    });
    // Prefill with the first suggested pod.
    if (opts.length) { podSel.value = opts[0].pod; root.querySelector('#ex-lv-ns').value = opts[0].ns; }

    root.querySelector('#ex-lv-fetch').addEventListener('click', doFetch);
    root.querySelector('#ex-lv-search').addEventListener('input', renderOut);
    root.querySelector('#ex-lv-regex').addEventListener('change', renderOut);
    root.querySelector('#ex-lv-sev').addEventListener('change', renderOut);
    root.querySelector('#ex-lv-copy').addEventListener('click', function () { try { navigator.clipboard.writeText(filtered()); } catch (e) {} });
    root.querySelector('#ex-lv-download').addEventListener('click', downloadLogs);
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
      if (d.error) { raw = ''; setStatus(d.error); renderOut(); return; }
      raw = d.lines || '';
      setStatus((raw ? raw.split('\n').length : 0) + ' lines · ' + esc(ns || '') + '/' + esc(pod) + (d.previous ? ' (previous)' : ''));
      renderOut();
    }).catch(function (err) { setStatus('Error: ' + err.message); });
  }

  function lineMatches(line) {
    var q = val('#ex-lv-search'), sev = val('#ex-lv-sev');
    if (sev) {
      var lc = line.toLowerCase();
      var ok = sev === 'error' ? /(error|panic|fatal|fail)/.test(lc) : sev === 'warn' ? /(warn)/.test(lc) : /(info)/.test(lc);
      if (!ok) return false;
    }
    if (!q) return true;
    if (checked('#ex-lv-regex')) { try { return new RegExp(q, 'i').test(line); } catch (e) { return true; } }
    return line.toLowerCase().indexOf(q.toLowerCase()) !== -1;
  }

  function filtered() {
    return raw.split('\n').filter(lineMatches).join('\n');
  }

  // Lightweight severity syntax highlighting.
  function colorize(line) {
    var safe = esc(line);
    if (/(error|panic|fatal|\bfail)/i.test(line)) return '<span style="color:var(--crit);">' + safe + '</span>';
    if (/warn/i.test(line)) return '<span style="color:var(--high);">' + safe + '</span>';
    if (/(info|started|ready|listening)/i.test(line)) return '<span style="color:var(--good);">' + safe + '</span>';
    return safe;
  }

  function renderOut() {
    var out = root.querySelector('#ex-lv-out');
    if (!out) return;
    if (!raw) { out.innerHTML = '<span style="color:var(--faint)">No log lines.</span>'; return; }
    var lines = raw.split('\n').filter(lineMatches);
    out.innerHTML = lines.map(colorize).join('\n');
  }

  function setStatus(s) { var el = root.querySelector('#ex-lv-status'); if (el) el.textContent = s; }

  function downloadLogs() {
    var blob = new Blob([filtered()], { type: 'text/plain' });
    var a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = (val('#ex-lv-pod') || 'logs') + '.log';
    a.click();
    setTimeout(function () { URL.revokeObjectURL(a.href); }, 1000);
  }

  window.ExalmLogs = { open: shell, close: close };
})();
