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
      'border-radius:14px;box-shadow:0 24px 60px rgba(0,0,0,.5);color:var(--fg);font-family:var(--font-sans),system-ui,sans-serif;">' +
      '<div style="display:flex;align-items:center;gap:10px;padding:15px 18px;border-bottom:1px solid var(--border);position:sticky;top:0;background:var(--panel);z-index:1;">' +
      '<div style="flex:1;font-size:14px;font-weight:700;">' + title + '</div>' +
      '<button class="ex-ov-close" style="border:1px solid var(--border);background:var(--panel2);color:var(--fg);border-radius:8px;cursor:pointer;font-size:13px;padding:4px 10px;">✕</button></div>' +
      '<div style="padding:16px 18px;">' + bodyHTML + '</div></div>';
    root.querySelector('.ex-ov-backdrop').addEventListener('click', close);
    root.querySelector('.ex-ov-close').addEventListener('click', close);
  }

  // ── shared bits ── (single implementation lives on window.Exalm, set by
  // dashboard.js; panels.js and chat.js both alias it so neither duplicates
  // the rendering logic.)
  var card = E.cardStyle || '';
  var lbl = E.lblStyle || '';
  function sevColor(sev) { return E.sevColor ? E.sevColor(sev) : 'var(--muted)'; }
  function confBadge(c) { return E.confBadge ? E.confBadge(c) : ''; }
  function evidenceHTML(items) { return E.evidenceHTML ? E.evidenceHTML(items) : ''; }
  function fixSectionsHTML(fixes, findingID) { return E.fixSectionsHTML ? E.fixSectionsHTML(fixes, findingID) : ''; }

  function wireCommon() {
    if (E.wireCopyButtons) E.wireCopyButtons(root);
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
      '<div style="margin-top:6px;font-size:12px;color:var(--muted);">Impact: <b style="color:' + sevColor(f.sev) + ';">' + esc((f.sev || '').toUpperCase()) + '</b> · namespace <code style="font-family:var(--font-mono),monospace;">' + esc(f.nsKey || f.ns) + '</code></div></div>' +
      '<h4 style="margin:0 0 8px;font-size:12px;text-transform:uppercase;letter-spacing:.5px;color:var(--fg);">Why this fix</h4>' +
      '<div style="' + card + 'margin-bottom:14px;font-size:12.5px;">' + esc(f.root || 'Root cause not yet determined — run an investigation.') + '</div>' +
      '<h4 style="margin:0 0 8px;font-size:12px;text-transform:uppercase;letter-spacing:.5px;color:var(--fg);">Evidence collected</h4>' +
      evidenceHTML(f.evidence) +
      fixSectionsHTML(f.fixes, id);
    overlay(head, body);
    wireCommon();
  }

  // ── Investigation → opens the conversational chat, scoped to this finding.
  // The old one-shot POST /api/findings/{id}/investigate endpoint still
  // exists server-side (additive, for non-UI callers); the UI now always
  // opens a follow-up-capable chat instead of a single static report.
  function openInvestigation(id) {
    if (window.ExalmChat && window.ExalmChat.openScoped) { window.ExalmChat.openScoped(id); return; }
    var f = E.finding ? E.finding(id) : null;
    overlay('✦ Investigate ' + esc(f ? f.title : id), '<div style="color:var(--crit);font-size:13px;">The investigation assistant failed to load. Reload the page and try again.</div>');
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

  window.ExalmPanels = { openRemediation: openRemediation, openInvestigation: openInvestigation, openDrilldown: openDrilldown, overlay: overlay, close: close };
})();
