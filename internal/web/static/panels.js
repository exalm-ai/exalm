'use strict';
// panels.js — explainable remediation panel, AI investigation panel, and chart
// drill-down. All three share one overlay rendered into #ex-overlay (a sibling
// of #app, so it survives the dashboard's re-renders). Reuses window.Exalm for
// helpers, current data, and the primary-fix flow.

(function () {
  var E = window.Exalm || {};
  var esc = E.esc || function (s) { return String(s == null ? '' : s); };

  var root = document.getElementById('ex-overlay');
  if (!root) { root = document.createElement('div'); root.id = 'ex-overlay'; document.body.appendChild(root); }

  function close() { root.innerHTML = ''; root.style.display = 'none'; }
  document.addEventListener('keydown', function (e) { if (e.key === 'Escape') close(); });

  // overlay renders a centered panel with a title and body HTML.
  function overlay(title, bodyHTML) {
    root.style.display = 'block';
    root.innerHTML =
      '<div class="ex-ov-backdrop" style="position:fixed;inset:0;background:rgba(0,0,0,.55);z-index:80;"></div>' +
      '<div role="dialog" aria-modal="true" style="position:fixed;z-index:81;top:50%;left:50%;transform:translate(-50%,-50%);' +
      'width:min(760px,94vw);max-height:88vh;overflow-y:auto;background:var(--panel);border:1px solid var(--border);' +
      'border-radius:14px;box-shadow:0 24px 60px rgba(0,0,0,.5);color:var(--fg);font-family:\'IBM Plex Sans\',system-ui,sans-serif;">' +
      '<div style="display:flex;align-items:center;gap:10px;padding:15px 18px;border-bottom:1px solid var(--border);position:sticky;top:0;background:var(--panel);z-index:1;">' +
      '<div style="flex:1;font-size:14px;font-weight:700;">' + title + '</div>' +
      '<button class="ex-ov-close" style="border:1px solid var(--border);background:var(--panel2);color:var(--fg);border-radius:8px;cursor:pointer;font-size:13px;padding:4px 10px;">✕</button></div>' +
      '<div style="padding:16px 18px;">' + bodyHTML + '</div></div>';
    root.querySelector('.ex-ov-backdrop').addEventListener('click', close);
    root.querySelector('.ex-ov-close').addEventListener('click', close);
  }

  // ── shared bits ──
  var card = 'background:var(--panel2);border:1px solid var(--border);border-radius:10px;padding:11px 13px;';
  var lbl = 'font-size:10px;text-transform:uppercase;letter-spacing:.6px;color:var(--faint);font-weight:600;';
  function sevColor(sev) { return (E.sevMeta ? E.sevMeta(sev).c : 'var(--muted)'); }
  function confBadge(c) {
    if (!c) return '';
    var col = E.confColor ? E.confColor(c) : 'var(--muted)';
    return '<span style="font-size:9px;font-weight:700;text-transform:uppercase;letter-spacing:.4px;padding:2px 8px;border-radius:20px;background:var(--track);color:' + col + ';">' + esc(c) + ' confidence</span>';
  }

  function evidenceHTML(items) {
    if (!items || !items.length) return '<div style="color:var(--muted);font-size:12.5px;">No evidence captured for this finding.</div>';
    var icon = { log: '📝', event: '⚡', metric: '📊', change: '↺' };
    return items.map(function (e) {
      var anchor = e.anchor ? '<div style="margin-top:5px;display:flex;gap:6px;align-items:center;"><code style="font-family:\'IBM Plex Mono\',monospace;font-size:11px;background:var(--track);padding:2px 7px;border-radius:5px;color:var(--accent);flex:1;overflow:auto;">' + esc(e.anchor) + '</code><button class="ex-copy" data-copy="' + esc(e.anchor) + '" style="border:1px solid var(--border);background:var(--panel);color:var(--muted);border-radius:6px;cursor:pointer;font-size:10px;padding:3px 8px;">copy</button></div>' : '';
      return '<div style="' + card + 'margin-bottom:8px;"><div style="display:flex;gap:8px;align-items:center;"><span>' + (icon[e.kind] || '•') + '</span><span style="' + lbl + '">' + esc(e.kind) + ' · ' + esc(e.source) + '</span></div>' +
        (e.excerpt ? '<pre style="margin:6px 0 0;white-space:pre-wrap;font-family:\'IBM Plex Mono\',monospace;font-size:11px;color:var(--codeFg);line-height:1.45;">' + esc(e.excerpt) + '</pre>' : '') +
        anchor + '</div>';
    }).join('');
  }

  // fixCardHTML renders one classified fix with its preview.
  function fixCardHTML(fx, findingID) {
    var preview = [['Risk', fx.risk], ['Downtime', fx.downtime], ['Rollback', fx.rollback], ['Expected', fx.expectedOutcome]]
      .filter(function (p) { return p[1]; })
      .map(function (p) { return '<div><div style="' + lbl + '">' + p[0] + '</div><div style="font-size:12px;margin-top:1px;">' + esc(p[1]) + '</div></div>'; })
      .join('');
    var cmd = fx.kubectlCmd ? '<div style="margin-top:8px;display:flex;gap:6px;align-items:center;"><code style="font-family:\'IBM Plex Mono\',monospace;font-size:11px;background:var(--track);padding:3px 8px;border-radius:5px;color:var(--accent);flex:1;overflow:auto;">' + esc(fx.kubectlCmd) + '</code><button class="ex-copy" data-copy="' + esc(fx.kubectlCmd) + '" style="border:1px solid var(--border);background:var(--panel);color:var(--muted);border-radius:6px;cursor:pointer;font-size:10px;padding:3px 8px;">copy</button></div>' : '';
    var action = fx.applicable
      ? '<button class="ex-apply" data-id="' + esc(findingID) + '" style="margin-top:10px;border:none;background:var(--accent);color:#fff;border-radius:8px;cursor:pointer;font-size:12px;font-weight:600;padding:7px 16px;">Apply this fix</button>'
      : '<div style="margin-top:8px;font-size:11.5px;color:var(--muted);">Review and apply manually — Exalm will not auto-execute this change.</div>';
    return '<div style="' + card + 'margin-bottom:10px;border-left:3px solid ' + (fx.fixType === 'root-cause' ? 'var(--good)' : 'var(--high)') + ';">' +
      '<div style="font-size:13px;font-weight:600;">' + esc(fx.description || fx.kind) + '</div>' +
      (preview ? '<div style="display:grid;grid-template-columns:repeat(2,1fr);gap:8px;margin-top:9px;">' + preview + '</div>' : '') +
      cmd + action + '</div>';
  }

  function splitFixes(fixes) {
    var temp = [], root = [];
    (fixes || []).forEach(function (fx) { (fx.fixType === 'root-cause' ? root : temp).push(fx); });
    return { temp: temp, root: root };
  }

  function fixSectionsHTML(fixes, findingID) {
    var s = splitFixes(fixes);
    var out = '';
    out += '<h4 style="margin:16px 0 8px;font-size:12px;text-transform:uppercase;letter-spacing:.5px;color:var(--high);">Temporary mitigation</h4>';
    out += s.temp.length ? s.temp.map(function (fx) { return fixCardHTML(fx, findingID); }).join('')
      : '<div style="color:var(--muted);font-size:12.5px;">No temporary mitigation — address the root cause directly.</div>';
    out += '<h4 style="margin:18px 0 8px;font-size:12px;text-transform:uppercase;letter-spacing:.5px;color:var(--good);">Root cause fix <span style="font-weight:400;text-transform:none;color:var(--muted);">— the real solution</span></h4>';
    out += s.root.length ? s.root.map(function (fx) { return fixCardHTML(fx, findingID); }).join('')
      : '<div style="color:var(--muted);font-size:12.5px;">No distinct root-cause fix identified — run an investigation for deeper analysis.</div>';
    return out;
  }

  function wireCommon() {
    root.querySelectorAll('.ex-copy').forEach(function (b) {
      b.addEventListener('click', function () { try { navigator.clipboard.writeText(b.getAttribute('data-copy')); b.textContent = 'copied'; setTimeout(function () { b.textContent = 'copy'; }, 1200); } catch (e) {} });
    });
    root.querySelectorAll('.ex-apply').forEach(function (b) {
      b.addEventListener('click', function () {
        var id = b.getAttribute('data-id');
        b.disabled = true; b.textContent = 'Applying…';
        if (E.applyPrimaryFix) E.applyPrimaryFix(id);
        setTimeout(close, 1300);
      });
    });
  }

  // ── Remediation panel (explain before execute) ──
  function openRemediation(id) {
    var f = E.finding ? E.finding(id) : null;
    if (!f) { overlay('Remediation', '<div style="color:var(--muted)">Finding not found.</div>'); return; }
    var head = '<span style="color:' + sevColor(f.sev) + ';">●</span> ' + esc(f.title) + ' &nbsp;' + confBadge(f.confidence);
    var body =
      '<div style="' + card + 'margin-bottom:14px;"><div style="' + lbl + '">Problem summary</div>' +
      '<div style="font-size:13px;margin-top:4px;">' + esc(f.reason || f.title) + '</div>' +
      '<div style="margin-top:6px;font-size:12px;color:var(--muted);">Impact: <b style="color:' + sevColor(f.sev) + ';">' + esc((f.sev || '').toUpperCase()) + '</b> · namespace <code style="font-family:\'IBM Plex Mono\',monospace;">' + esc(f.nsKey || f.ns) + '</code></div></div>' +
      '<h4 style="margin:0 0 8px;font-size:12px;text-transform:uppercase;letter-spacing:.5px;color:var(--fg);">Why this fix</h4>' +
      '<div style="' + card + 'margin-bottom:14px;font-size:12.5px;">' + esc(f.root || 'Root cause not yet determined — run an investigation.') + '</div>' +
      '<h4 style="margin:0 0 8px;font-size:12px;text-transform:uppercase;letter-spacing:.5px;color:var(--fg);">Evidence collected</h4>' +
      evidenceHTML(f.evidence) +
      fixSectionsHTML(f.fixes, id);
    overlay(head, body);
    wireCommon();
  }

  // ── Investigation panel (deep root-cause) ──
  function openInvestigation(id) {
    var f = E.finding ? E.finding(id) : null;
    var title = '✦ Investigating ' + esc(f ? f.title : id);
    overlay(title, '<div style="display:flex;align-items:center;gap:10px;color:var(--muted);font-size:13px;"><span style="display:inline-block;width:14px;height:14px;border:2px solid var(--faint);border-top-color:transparent;border-radius:50%;animation:ex-spin 1s linear infinite;"></span>Gathering evidence and synthesizing root cause…</div>');
    fetch('/api/findings/' + encodeURIComponent(id) + '/investigate', { method: 'POST', headers: { 'X-Exalm-Request': 'true' } })
      .then(function (r) {
        if (r.status === 503) return { _unavailable: true };
        return r.json();
      })
      .then(function (inv) {
        if (inv && inv._unavailable) {
          overlay(title, '<div style="color:var(--muted);font-size:13px;">Live investigation is unavailable in this mode (no cluster connection / LLM). The finding\'s evidence and classification are still shown in the remediation panel.</div>');
          return;
        }
        renderInvestigation(title, id, inv);
      })
      .catch(function (err) { overlay(title, '<div style="color:var(--crit);font-size:13px;">Investigation failed: ' + esc(err.message) + '</div>'); });
  }

  function renderInvestigation(title, id, inv) {
    var steps = (inv.steps || []).map(function (st) {
      var mark = st.status === 'done' ? '<span style="color:var(--good);">✓</span>' : st.status === 'unavailable' ? '<span style="color:var(--faint);">○</span>' : '<span style="color:var(--faint);">–</span>';
      return '<div style="display:flex;gap:8px;align-items:baseline;padding:3px 0;font-size:12.5px;">' + mark + '<span style="flex:1;">' + esc(st.label) + (st.detail ? ' <span style="color:var(--muted);">— ' + esc(st.detail) + '</span>' : '') + '</span></div>';
    }).join('');
    var body =
      '<div style="' + card + 'margin-bottom:14px;"><div style="display:flex;align-items:center;gap:8px;"><div style="' + lbl + '">Root cause analysis</div>' + confBadge(inv.confidence) + '</div>' +
      '<div style="font-size:13px;line-height:1.6;margin-top:6px;">' + (E.mdToHtml ? E.mdToHtml(inv.summary || inv.rootCause) : esc(inv.summary || inv.rootCause)) + '</div></div>' +
      '<h4 style="margin:0 0 6px;font-size:12px;text-transform:uppercase;letter-spacing:.5px;color:var(--fg);">Investigation steps</h4>' +
      '<div style="' + card + 'margin-bottom:14px;">' + (steps || '<span style="color:var(--muted)">No steps recorded.</span>') + '</div>' +
      '<h4 style="margin:0 0 8px;font-size:12px;text-transform:uppercase;letter-spacing:.5px;color:var(--fg);">Evidence</h4>' +
      evidenceHTML(inv.evidence) +
      fixSectionsHTML((inv.temporaryFixes || []).concat(inv.rootCauseFixes || []), id);
    overlay(title, body);
    wireCommon();
  }

  // ── Chart drill-down ──
  function openDrilldown(opts) {
    var label = (opts && opts.label) || 'selection';
    var scope = E.state ? E.state.selectedNs : 'all';
    overlay('Drill-down · ' + esc(label), '<div style="color:var(--muted);font-size:13px;">Loading metrics, changes, and findings…</div>');
    Promise.all([
      fetch('/api/metrics?window=24h&ns=' + encodeURIComponent(scope)).then(function (r) { return r.json(); }).catch(function () { return []; }),
      fetch('/api/changes?since=24h').then(function (r) { return r.json(); }).catch(function () { return []; })
    ]).then(function (res) {
      var series = res[0] || [], changes = res[1] || [];
      var findings = (E.findings ? E.findings() : []).filter(function (f) { return scope === 'all' || f.nsKey === scope; }).slice(0, 8);
      var s0 = series[0];
      var metricHTML = s0
        ? '<div style="' + card + 'margin-bottom:12px;"><div style="' + lbl + '">' + esc(s0.name) + (s0.modeled ? ' (modeled)' : '') + '</div>' +
          '<div style="font-size:12px;color:var(--muted);margin-top:3px;">threshold ' + (s0.threshold || 0) + (s0.unit ? ' ' + esc(s0.unit) : '') + ' · ' + (s0.points || []).length + ' samples · ' + ((s0.annotations || []).length) + ' change annotation(s)</div></div>'
        : '';
      var changeHTML = changes.length
        ? '<h4 style="margin:12px 0 6px;font-size:12px;text-transform:uppercase;letter-spacing:.5px;color:var(--fg);">Recent changes</h4>' +
          changes.slice(0, 6).map(function (c) { return '<div style="' + card + 'margin-bottom:6px;font-size:12.5px;">' + esc(c.action || '') + ' <b>' + esc(c.kind || '') + '</b> ' + esc(c.name || '') + ' <span style="color:var(--muted)">' + esc(c.namespace || '') + '</span></div>'; }).join('')
        : '';
      var findingHTML = findings.length
        ? '<h4 style="margin:12px 0 6px;font-size:12px;text-transform:uppercase;letter-spacing:.5px;color:var(--fg);">Findings in scope</h4>' +
          findings.map(function (f) { return '<div style="' + card + 'margin-bottom:6px;font-size:12.5px;"><span style="color:' + sevColor(f.sev) + ';">●</span> ' + esc(f.title) + '</div>'; }).join('')
        : '';
      overlay('Drill-down · ' + esc(label), metricHTML + findingHTML + changeHTML +
        '<button class="ex-open-logs" style="margin-top:12px;border:1px solid var(--border);background:var(--panel2);color:var(--fg);border-radius:8px;cursor:pointer;font-size:12px;padding:7px 14px;">▤ Open log viewer</button>');
      var lb = root.querySelector('.ex-open-logs');
      if (lb) lb.addEventListener('click', function () { close(); if (window.ExalmLogs) window.ExalmLogs.open(); });
    });
  }

  window.ExalmPanels = { openRemediation: openRemediation, openInvestigation: openInvestigation, openDrilldown: openDrilldown, close: close };
})();
