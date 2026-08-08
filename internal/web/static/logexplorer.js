'use strict';
// logexplorer.js — the shared log exploration view (window.ExalmLogExplorer).
// One implementation of filtering, severity colorize, line selection, export,
// one-shot ✦ analysis, surrounding context, and conversational hand-off,
// consumed by BOTH the k8s log drawer (logviewer.js, mode "raw") and the
// analyzer chart drilldowns (analyzer.js, mode "corpus").
//
// The module is a pure view: it knows no URLs. Call sites supply fetch
// callbacks, so corpus filtering runs server-side (the /logs query API)
// while raw k8s tail text filters client-side. All DOM lives under the
// mount element — no global ids, so several explorers can coexist.

(function () {
  var E = window.Exalm || {};
  var esc = E.esc || function (s) { return String(s == null ? '' : s); };

  // guessSeverity classifies a raw, unparsed log line — the k8s tail has no
  // structured severity. Corpus events carry their parsed severity instead.
  function guessSeverity(line) {
    if (/(error|panic|fatal|\bfail)/i.test(line)) return 'error';
    if (/warn/i.test(line)) return 'warn';
    if (/(info|started|ready|listening)/i.test(line)) return 'info';
    return '';
  }

  // lineColor maps a severity to a theme color: parsed corpus severities go
  // through the widget library's sevColor; guessed classes use the same
  // palette logviewer's colorize() used.
  function lineColor(severity) {
    var s = String(severity || '').toLowerCase();
    if (s === 'error' || s === 'err' || s === 'crit' || s === 'critical' || s === 'emerg' || s === 'alert' || s === 'fatal') return 'var(--crit)';
    if (s === 'warn' || s === 'warning') return 'var(--high)';
    if (s === 'info' || s === 'information' || s === 'notice') return 'var(--good)';
    if (window.ExalmWidgets && window.ExalmWidgets.sevColor && s) return window.ExalmWidgets.sevColor(s);
    return 'var(--codeFg)';
  }

  function ctrl(extra) {
    return 'height:30px;border-radius:8px;border:1px solid var(--border);background:var(--panel2);color:var(--fg);font-family:inherit;font-size:12.5px;padding:0 9px;outline:none;' + (extra || '');
  }
  function actBtn(extra) {
    return 'border:1px solid var(--border);background:var(--panel2);color:var(--fg);border-radius:6px;cursor:pointer;font-size:10.5px;padding:2px 9px;' + (extra || '');
  }

  // create renders the explorer into mountEl and returns its handle.
  // config:
  //   mode: 'corpus' (server-side filters via fetchLogs) | 'raw' (client-side)
  //   fetchLogs(filters) -> Promise<{events,total,truncated}>   (corpus)
  //   fetchContext(ev, n) -> Promise<{events}> | null           (corpus)
  //   initialFilters: {severity,unit,scope,code,contains,from,to}
  //   severityOptions: ['err','warn',…] | null (null => free-text input)
  //   capabilities: {search,severity,source,time,export,context} (all bool)
  //   analyzeMeta(ev) -> extra fields for POST /api/logs/analyze
  //   onInvestigate(ev, filters) | null — conversational hand-off
  //   onJumpToResource(ev) | null — focus the related resource
  function create(mountEl, config) {
    var cfg = config || {};
    var caps = cfg.capabilities || {};
    var corpus = cfg.mode === 'corpus';
    var events = [];        // normalized {at,severity,scope,unit,code,message,raw,idx}
    var selectedRaw = null; // selection survives re-renders/live tail by line identity
    var inContext = false;  // context view active (corpus mode)
    var filters = {};
    var init = cfg.initialFilters || {};
    ['severity', 'unit', 'scope', 'code', 'contains', 'from', 'to'].forEach(function (k) {
      if (init[k]) filters[k] = init[k];
    });

    function q(sel) { return mountEl.querySelector(sel); }

    function sevControl() {
      if (!caps.severity) return '';
      if (cfg.severityOptions && cfg.severityOptions.length) {
        return '<select class="ex-le-sev" style="' + ctrl('') + '"><option value="">all levels</option>' +
          cfg.severityOptions.map(function (s) {
            return '<option' + (filters.severity === s ? ' selected' : '') + '>' + esc(s) + '</option>';
          }).join('') + '</select>';
      }
      return '<input class="ex-le-sev" placeholder="severity" value="' + esc(filters.severity || '') + '" style="' + ctrl('width:90px;') + '">';
    }

    function barHTML() {
      var h = '<div class="ex-le-bar" style="display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:8px;">';
      if (caps.search !== false) {
        h += '<input class="ex-le-search" placeholder="' + (corpus ? 'contains…' : 'filter (substring)…') + '" value="' + esc(filters.contains || '') + '" style="' + ctrl('flex:1;min-width:150px;') + '">';
        if (!corpus) h += '<label style="display:flex;align-items:center;gap:5px;font-size:12px;color:var(--muted);"><input type="checkbox" class="ex-le-regex"> regex</label>';
      }
      h += sevControl();
      if (caps.source) {
        h += '<input class="ex-le-unit" placeholder="unit / route" value="' + esc(filters.unit || '') + '" style="' + ctrl('width:120px;') + '">' +
          '<input class="ex-le-scope" placeholder="host / site" value="' + esc(filters.scope || '') + '" style="' + ctrl('width:110px;') + '">';
      }
      if (caps.time) {
        h += '<input class="ex-le-from" type="datetime-local" title="from" style="' + ctrl('') + '">' +
          '<input class="ex-le-to" type="datetime-local" title="to" style="' + ctrl('') + '">';
      }
      if (corpus) h += '<button class="ex-le-apply" style="height:30px;border:none;background:var(--accent);color:#04222b;border-radius:8px;cursor:pointer;font-size:12.5px;font-weight:600;padding:0 13px;">Apply</button>';
      if (caps.export !== false) {
        h += '<button class="ex-le-copy" style="' + ctrl('cursor:pointer;') + '">copy</button>' +
          '<button class="ex-le-download" style="' + ctrl('cursor:pointer;') + '">download</button>';
      }
      return h + '</div>';
    }

    function actionsHTML() {
      var h = '<div class="ex-le-actions" style="display:flex;gap:6px;align-items:center;margin:8px 0 0;">' +
        '<span class="ex-le-info" style="font-size:11px;color:var(--faint);flex:1;">Click a line to select it.</span>' +
        '<button class="ex-le-analyze" disabled style="' + actBtn('border-color:var(--accent);color:var(--accent);opacity:.5;') + '">✦ Analyze</button>';
      if (caps.context !== false && (corpus ? !!cfg.fetchContext : true)) {
        h += '<button class="ex-le-context" disabled style="' + actBtn('opacity:.5;') + '">⇱ Context</button>';
      }
      if (cfg.onInvestigate) h += '<button class="ex-le-invest" disabled style="' + actBtn('opacity:.5;') + '">➤ Investigate</button>';
      if (cfg.onJumpToResource) h += '<button class="ex-le-jump" disabled style="' + actBtn('opacity:.5;') + '">↷ Resource</button>';
      return h + '</div>';
    }

    function shellHTML() {
      return barHTML() +
        '<div class="ex-le-out" style="max-height:42vh;overflow:auto;font-family:var(--font-mono),monospace;font-size:11px;line-height:1.5;background:var(--code);color:var(--codeFg);border-radius:8px;padding:8px 10px;white-space:pre-wrap;"></div>' +
        actionsHTML() +
        '<div class="ex-le-analysis" style="display:none;margin-top:10px;max-height:38vh;overflow-y:auto;background:var(--panel2);border:1px solid var(--accent);border-radius:10px;padding:11px 14px;font-size:12.5px;line-height:1.6;color:var(--body);"></div>';
    }

    // ── client-side filtering (raw mode; corpus filters run server-side) ──
    function lineMatches(ev) {
      if (corpus) return true;
      if (filters.severity && guessSeverity(ev.raw) !== filters.severity) return false;
      var needle = filters.contains;
      if (!needle) return true;
      var regexEl = q('.ex-le-regex');
      if (regexEl && regexEl.checked) {
        try { return new RegExp(needle, 'i').test(ev.raw); } catch (e) { return true; }
      }
      return ev.raw.toLowerCase().indexOf(needle.toLowerCase()) !== -1;
    }

    function visible() { return events.filter(lineMatches); }

    function getFilteredText() {
      return visible().map(function (ev) { return ev.raw; }).join('\n');
    }

    function selectedEvent() {
      var vis = visible();
      for (var i = 0; i < vis.length; i++) if (vis[i].raw === selectedRaw) return vis[i];
      return null;
    }

    function renderList(list, anchorIdx) {
      var out = q('.ex-le-out');
      if (!out) return;
      if (!list.length) {
        out.innerHTML = '<span style="color:var(--faint)">No matching lines.</span>';
        syncActions();
        return;
      }
      out.innerHTML = list.map(function (ev, i) {
        var sel = ev.raw === selectedRaw ? 'background:var(--accentSoft);outline:1px solid var(--accent);' : '';
        var anchor = anchorIdx != null && ev.idx === anchorIdx ? 'border-left:3px solid var(--accent);padding-left:4px;' : '';
        var ts = ev.at ? '<span style="color:var(--faint);flex:none;">' + esc(ev.at.replace('T', ' ').replace('Z', '')) + '</span> ' : '';
        return '<div class="ex-le-line" data-i="' + i + '" style="cursor:pointer;border-radius:4px;padding:0 4px;display:flex;gap:8px;' + sel + anchor + '">' +
          ts + '<span style="flex:1;white-space:pre-wrap;color:' + lineColor(ev.severity || guessSeverity(ev.raw)) + ';">' + esc(ev.raw) + '</span></div>';
      }).join('');
      out._list = list;
      syncActions();
    }

    function render() { renderList(visible(), null); }

    function syncActions() {
      var ev = selectedEvent();
      var info = q('.ex-le-info');
      if (info && !inContext) info.textContent = ev ? '1 line selected' : visible().length + ' line(s). Click one to select it.';
      ['.ex-le-analyze', '.ex-le-context', '.ex-le-invest', '.ex-le-jump'].forEach(function (sel) {
        var b = q(sel);
        if (!b) return;
        b.disabled = !ev;
        b.style.opacity = ev ? '1' : '.5';
      });
    }

    function readFilters() {
      var read = function (sel) { var el = q(sel); return el ? el.value.trim() : ''; };
      filters.contains = read('.ex-le-search');
      filters.severity = read('.ex-le-sev');
      if (caps.source) { filters.unit = read('.ex-le-unit'); filters.scope = read('.ex-le-scope'); }
      if (caps.time) {
        var f = read('.ex-le-from'), t = read('.ex-le-to');
        filters.from = f ? new Date(f).toISOString() : '';
        filters.to = t ? new Date(t).toISOString() : '';
      }
      return filters;
    }

    function normalize(list) {
      return (list || []).map(function (e) {
        return { at: e.at || '', severity: e.severity || '', scope: e.scope || '', unit: e.unit || '', code: e.code || '', message: e.message || '', raw: e.raw || '', idx: (e.idx != null ? e.idx : null) };
      });
    }

    function refetch() {
      if (!corpus || !cfg.fetchLogs) { render(); return; }
      inContext = false;
      var out = q('.ex-le-out');
      if (out) out.innerHTML = '<span style="color:var(--faint)">Loading…</span>';
      cfg.fetchLogs(readFilters()).then(function (d) {
        events = normalize(d.events);
        var info = q('.ex-le-info');
        if (info) info.textContent = (d.total != null ? d.total + ' match(es)' : events.length + ' line(s)') + (d.truncated ? ' · corpus truncated by ' + d.truncated : '');
        render();
      }).catch(function (err) {
        if (out) out.innerHTML = '<span style="color:var(--crit)">Query failed: ' + esc(err.message) + '</span>';
      });
    }

    // showContext renders the surrounding-context view for the selection:
    // corpus mode asks the backend (around/context params); raw mode simply
    // clears the filters — every line is already client-side.
    function showContext() {
      var ev = selectedEvent();
      if (!ev) return;
      if (!corpus) {
        var searchEl = q('.ex-le-search'), sevEl = q('.ex-le-sev');
        if (searchEl) searchEl.value = '';
        if (sevEl) sevEl.value = '';
        filters.contains = ''; filters.severity = '';
        render();
        var lines = mountEl.querySelectorAll('.ex-le-line');
        for (var i = 0; i < lines.length; i++) {
          var list = q('.ex-le-out')._list || [];
          if (list[i] && list[i].raw === selectedRaw) { lines[i].scrollIntoView({ block: 'center' }); break; }
        }
        return;
      }
      if (!cfg.fetchContext) return;
      var out = q('.ex-le-out');
      out.innerHTML = '<span style="color:var(--faint)">Loading context…</span>';
      cfg.fetchContext(ev, 30).then(function (d) {
        inContext = true;
        var ctxEvents = normalize(d.events);
        var info = q('.ex-le-info');
        if (info) info.innerHTML = 'Context around the selected line — <a href="#" class="ex-le-back" style="color:var(--accent);">back to results</a>';
        renderList(ctxEvents, ev.idx);
        var back = q('.ex-le-back');
        if (back) back.addEventListener('click', function (e) { e.preventDefault(); refetch(); });
      }).catch(function (err) {
        out.innerHTML = '<span style="color:var(--crit)">Context failed: ' + esc(err.message) + '</span>';
      });
    }

    // analyzeLine posts the selected line + surrounding lines for a one-shot
    // AI breakdown — the single merged implementation of logviewer.doAnalyze
    // and analyzer.analyzeRow.
    function analyzeLine() {
      var ev = selectedEvent();
      if (!ev) return;
      var list = (q('.ex-le-out') && q('.ex-le-out')._list) || visible();
      var at = list.indexOf(ev);
      var from = Math.max(0, at - 20), to = Math.min(list.length, at + 21);
      var context = list.slice(from, to).map(function (e) { return e.raw; }).join('\n');
      var meta = cfg.analyzeMeta ? cfg.analyzeMeta(ev) : {};
      var body = {
        namespace: meta.namespace || '', pod: meta.pod || '', container: meta.container || '',
        severity: meta.severity || ev.severity || guessSeverity(ev.raw) || 'info',
        source: meta.source || '', message: ev.raw, context: context.slice(0, 20000)
      };
      var panel = q('.ex-le-analysis');
      panel.style.display = 'block';
      panel.innerHTML = '<span style="display:inline-block;width:12px;height:12px;border:2px solid var(--faint);border-top-color:transparent;border-radius:50%;animation:ex-spin 1s linear infinite;vertical-align:-2px;"></span> <span style="color:var(--muted);">Analyzing the selected line…</span>';
      fetch(cfg.analyzeURL || '/api/logs/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Exalm-Request': 'true' },
        body: JSON.stringify(body)
      }).then(function (r) {
        if (r.status === 503) throw new Error('AI analysis is unavailable in this mode (no LLM configured).');
        if (r.status === 429) throw new Error('Exalm is busy with other analyses — try again in a moment.');
        if (!r.ok) throw new Error('Analysis failed (HTTP ' + r.status + ').');
        return r.json();
      }).then(function (d) {
        var html = (E.mdToHtml ? E.mdToHtml(d.analysis) : esc(d.analysis));
        panel.innerHTML = '<div style="display:flex;align-items:center;gap:8px;margin-bottom:8px;"><span style="font-size:10px;text-transform:uppercase;letter-spacing:.6px;color:var(--accent);font-weight:700;">✦ AI analysis of the selected line</span><span style="flex:1;"></span><button class="ex-le-analysis-close" style="' + actBtn('') + '">✕ close</button></div>' + html;
        var closeBtn = panel.querySelector('.ex-le-analysis-close');
        if (closeBtn) closeBtn.addEventListener('click', function () { panel.style.display = 'none'; });
      }).catch(function (err) {
        panel.innerHTML = '<span style="color:var(--crit);">⚠ ' + esc(err.message) + '</span>';
      });
    }

    function download() {
      var blob = new Blob([getFilteredText()], { type: 'text/plain' });
      var a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = (cfg.downloadName || 'logs') + '.log';
      a.click();
      setTimeout(function () { URL.revokeObjectURL(a.href); }, 1000);
    }

    function wire() {
      mountEl.innerHTML = shellHTML();
      var onFilter = corpus ? function () {} : render;
      ['.ex-le-search', '.ex-le-sev', '.ex-le-unit', '.ex-le-scope'].forEach(function (sel) {
        var el = q(sel);
        if (!el) return;
        el.addEventListener('input', function () { readFilters(); onFilter(); });
        el.addEventListener('change', function () { readFilters(); onFilter(); });
      });
      var regexEl = q('.ex-le-regex');
      if (regexEl) regexEl.addEventListener('change', render);
      var apply = q('.ex-le-apply');
      if (apply) apply.addEventListener('click', refetch);
      var search = q('.ex-le-search');
      if (search && corpus) search.addEventListener('keydown', function (e) { if (e.key === 'Enter') refetch(); });
      var copy = q('.ex-le-copy');
      if (copy) copy.addEventListener('click', function () { try { navigator.clipboard.writeText(getFilteredText()); } catch (e) {} });
      var dl = q('.ex-le-download');
      if (dl) dl.addEventListener('click', download);
      var analyze = q('.ex-le-analyze');
      if (analyze) analyze.addEventListener('click', analyzeLine);
      var ctx = q('.ex-le-context');
      if (ctx) ctx.addEventListener('click', showContext);
      var invest = q('.ex-le-invest');
      if (invest) invest.addEventListener('click', function () {
        var ev = selectedEvent();
        if (ev && cfg.onInvestigate) cfg.onInvestigate(ev, readFilters());
      });
      var jump = q('.ex-le-jump');
      if (jump) jump.addEventListener('click', function () {
        var ev = selectedEvent();
        if (ev && cfg.onJumpToResource) cfg.onJumpToResource(ev);
      });
      q('.ex-le-out').addEventListener('click', function (e) {
        var line = e.target.closest ? e.target.closest('.ex-le-line') : null;
        if (!line) return;
        var list = q('.ex-le-out')._list || [];
        var ev = list[+line.getAttribute('data-i')];
        selectedRaw = ev ? (ev.raw === selectedRaw ? null : ev.raw) : null;
        renderList(list, null);
      });
    }

    wire();
    if (corpus && cfg.fetchLogs) refetch(); else render();

    return {
      // setEvents replaces the data (raw mode / live tail). Selection is
      // preserved by raw-line identity so a 4s poll doesn't lose it.
      setEvents: function (list) { events = normalize(list); if (!inContext) render(); },
      refetch: refetch,
      getFilteredText: getFilteredText,
      getFilters: function () { return readFilters(); },
      destroy: function () { mountEl.innerHTML = ''; }
    };
  }

  window.ExalmLogExplorer = { create: create, guessSeverity: guessSeverity, lineColor: lineColor };
})();
