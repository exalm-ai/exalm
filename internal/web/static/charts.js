'use strict';
// charts.js — adds hover tooltips to the dashboard charts. Click drill-down is
// handled by the dashboard's event delegation (data-act="drilldown" →
// ExalmPanels.openDrilldown). attach() is called by dashboard.js after every
// re-render, so it must be idempotent and cheap.

(function () {
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

  function attach() {
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

  window.ExalmCharts = { attach: attach };
  // The dashboard's first paint happens before this module loads, so wire the
  // already-rendered chart bars now; subsequent re-renders call attach() again.
  attach();
})();
