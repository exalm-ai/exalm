'use strict';
// tree.js — the cumulative investigation tree shown beside the chat on the
// AI Analysis page. Folds ALL assistant turns of a conversation into one
// hierarchy: Focus resource → inspected resources (grouped by graph edge,
// newest evidence wins) → Root cause (top hypothesis + score) with
// alternatives → Fixes (mitigation / root-cause / prevention). Nodes are
// nested <details>; expanded state survives repaints via a key set held by
// the caller (chat.js keeps it on the Session).

(function () {
  var E = window.Exalm || {};
  var esc = E.esc || function (s) { return String(s == null ? '' : s); };

  // buildModel folds the conversation's messages into a tree model.
  function buildModel(messages, focus) {
    var latestByKey = {};      // (edge \x1f source) -> evidence (newest wins)
    var order = [];            // insertion order of keys
    var lastAssistant = null;
    var latestTurnKeys = {};   // keys contributed by the newest assistant turn

    (messages || []).forEach(function (m) {
      if (m.role !== 'assistant') return;
      lastAssistant = m;
      var turnKeys = {};
      (m.evidence || []).forEach(function (ev) {
        var key = (ev.edge || 'other') + '\x1f' + (ev.source || '?');
        if (!latestByKey[key]) order.push(key);
        latestByKey[key] = ev;
        turnKeys[key] = true;
      });
      latestTurnKeys = turnKeys;
    });

    // Group by edge, preserving first-seen edge order.
    var groups = [], groupByEdge = {};
    order.forEach(function (key) {
      var ev = latestByKey[key];
      var edge = ev.edge || 'other';
      var g = groupByEdge[edge];
      if (!g) { g = { edge: edge, items: [] }; groupByEdge[edge] = g; groups.push(g); }
      g.items.push({ ev: ev, isNew: !!latestTurnKeys[key] });
    });

    return {
      focus: focus || (lastAssistant ? '' : ''),
      groups: groups,
      hypotheses: (lastAssistant && lastAssistant.hypotheses) || [],
      score: (lastAssistant && lastAssistant.score) || 0,
      scoreRationale: (lastAssistant && lastAssistant.scoreRationale) || '',
      fixes: (lastAssistant && lastAssistant.fixes) || [],
      prevention: (lastAssistant && lastAssistant.prevention) || [],
      empty: groups.length === 0 && !lastAssistant
    };
  }

  function edgeLabel(edge) {
    if (!edge || edge === 'other') return 'Other signals';
    return edge.replace(/→/g, ' → ');
  }

  function nodeSummary(text, extra) {
    return '<summary style="cursor:pointer;font-size:12px;color:var(--fg);padding:3px 0;list-style-position:inside;">' + text + (extra || '') + '</summary>';
  }

  function chip(text, color) {
    return '<span style="font-family:var(--font-mono),monospace;font-size:9.5px;font-weight:700;padding:1px 6px;border-radius:9px;background:var(--track);color:' + (color || 'var(--accent)') + ';margin-left:6px;">' + esc(text) + '</span>';
  }

  function evidenceNode(item, openKeys) {
    var ev = item.ev;
    var key = 'ev:' + (ev.edge || '') + ':' + (ev.source || '');
    var open = openKeys[key] ? ' open' : '';
    var flags = '';
    if (ev.label) flags += chip(ev.label);
    if (ev.fromCache) flags += chip('cached', 'var(--faint)');
    if (item.isNew) flags += chip('new', 'var(--good)');
    var body = '';
    if (ev.excerpt) body += '<pre style="margin:4px 0 4px 14px;white-space:pre-wrap;font-family:var(--font-mono),monospace;font-size:10.5px;color:var(--codeFg);line-height:1.45;">' + esc(ev.excerpt) + '</pre>';
    if (ev.anchor) body += '<div style="margin:0 0 4px 14px;display:flex;gap:6px;align-items:center;"><code style="font-family:var(--font-mono),monospace;font-size:10px;background:var(--track);padding:2px 6px;border-radius:5px;color:var(--accent);flex:1;overflow:auto;">' + esc(ev.anchor) + '</code><button class="ex-copy" data-copy="' + esc(ev.anchor) + '" style="border:1px solid var(--border);background:var(--panel);color:var(--muted);border-radius:6px;cursor:pointer;font-size:9.5px;padding:2px 7px;">copy</button></div>';
    return '<details class="ex-tree-node" data-tree-key="' + esc(key) + '" data-ev-label="' + esc(ev.label || '') + '"' + open + ' style="margin-left:12px;">' +
      nodeSummary('<span style="color:var(--muted);">' + esc(ev.kind || '•') + '</span> ' + esc(ev.source || ''), flags) +
      body + '</details>';
  }

  function scoreBar(score) {
    var col = score >= 75 ? 'var(--good)' : score >= 45 ? 'var(--med)' : 'var(--high)';
    return '<span style="display:inline-flex;align-items:center;gap:6px;margin-left:6px;">' +
      '<span style="display:inline-block;width:52px;height:5px;border-radius:3px;background:var(--track);overflow:hidden;vertical-align:middle;"><span style="display:block;width:' + Math.max(2, Math.min(100, score)) + '%;height:100%;background:' + col + ';"></span></span>' +
      '<b style="font-size:11px;color:' + col + ';">' + score + '%</b></span>';
  }

  // renderHTML paints the model into the given root element.
  function renderHTML(model, root, openKeys) {
    openKeys = openKeys || {};
    if (!root) return;
    if (model.empty) {
      root.innerHTML = '<div style="color:var(--faint);font-size:12px;padding:10px 4px;">The investigation tree builds up here as you ask questions — every inspected resource, the ranked root cause, and the fixes.</div>';
      return;
    }
    var html = '<div style="font-size:10.5px;text-transform:uppercase;letter-spacing:.6px;color:var(--faint);font-weight:600;margin-bottom:8px;">Investigation tree</div>';
    html += '<div style="font-size:12.5px;font-weight:700;color:var(--fg);margin-bottom:6px;">⬡ ' + esc(model.focus || 'cluster scope') + '</div>';

    model.groups.forEach(function (g) {
      var key = 'edge:' + g.edge;
      var open = openKeys[key] !== false ? ' open' : ''; // edges default open
      html += '<details class="ex-tree-node" data-tree-key="' + esc(key) + '"' + open + ' style="margin-left:4px;border-left:1px solid var(--border);padding-left:8px;margin-bottom:2px;">' +
        nodeSummary('<span style="color:var(--accent);">' + esc(edgeLabel(g.edge)) + '</span>', chip(String(g.items.length), 'var(--muted)'));
      g.items.forEach(function (item) { html += evidenceNode(item, openKeys); });
      html += '</details>';
    });

    if (model.hypotheses.length) {
      var top = model.hypotheses[0];
      var rcKey = 'rootcause';
      html += '<details class="ex-tree-node" data-tree-key="' + rcKey + '"' + (openKeys[rcKey] !== false ? ' open' : '') + ' style="margin-top:10px;border-left:2px solid var(--good);padding-left:8px;">' +
        nodeSummary('<b style="color:var(--good);">Root cause</b>' + (model.score ? scoreBar(model.score) : ''));
      html += '<div style="margin:4px 0 4px 14px;font-size:12px;color:var(--fg);">' + esc(top.title) +
        (top.evidenceFor && top.evidenceFor.length ? ' <span style="color:var(--faint);">(' + top.evidenceFor.map(function (l) { return esc(l); }).join(', ') + ')</span>' : '') + '</div>';
      if (model.scoreRationale) html += '<div style="margin:0 0 6px 14px;font-size:11px;color:var(--muted);">' + esc(model.scoreRationale) + '</div>';
      if (model.hypotheses.length > 1) {
        html += '<details class="ex-tree-node" data-tree-key="alts" style="margin-left:12px;">' + nodeSummary('<span style="color:var(--muted);">Alternatives</span>', chip(String(model.hypotheses.length - 1), 'var(--muted)'));
        model.hypotheses.slice(1).forEach(function (h) {
          html += '<div style="margin:3px 0 3px 14px;font-size:11.5px;color:var(--body);">' + esc(h.title) + ' <span style="color:var(--faint);">(score ' + h.score + ')</span>' +
            (h.rationale ? '<div style="font-size:10.5px;color:var(--faint);">' + esc(h.rationale) + '</div>' : '') + '</div>';
        });
        html += '</details>';
      }
      html += '</details>';
    }

    var allFixes = (model.fixes || []).concat(model.prevention || []);
    if (allFixes.length) {
      var fxKey = 'fixes';
      html += '<details class="ex-tree-node" data-tree-key="' + fxKey + '"' + (openKeys[fxKey] ? ' open' : '') + ' style="margin-top:6px;border-left:2px solid var(--accent);padding-left:8px;">' +
        nodeSummary('<b style="color:var(--accent);">Fixes</b>', chip(String(allFixes.length), 'var(--muted)'));
      allFixes.forEach(function (fx) {
        var tag = fx.fixType === 'root-cause' ? ['root cause', 'var(--good)'] : fx.fixType === 'prevention' ? ['prevention', 'var(--low)'] : ['temporary', 'var(--high)'];
        html += '<div style="margin:4px 0 4px 14px;font-size:11.5px;color:var(--body);">' + chip(tag[0], tag[1]) + ' ' + esc(fx.description || fx.kind) + '</div>';
      });
      html += '</details>';
    }

    root.innerHTML = html;
    if (E.wireCopyButtons) E.wireCopyButtons(root);

    // Record open/closed state back into openKeys as the user toggles.
    root.querySelectorAll('.ex-tree-node').forEach(function (d) {
      d.addEventListener('toggle', function () {
        openKeys[d.getAttribute('data-tree-key')] = d.open;
      });
    });
  }

  // flash scrolls the tree node carrying the evidence label into view and
  // highlights it briefly — the citation-chip click target.
  function flash(root, label) {
    if (!root || !label) return false;
    var node = root.querySelector('[data-ev-label="' + label + '"]');
    if (!node) return false;
    // Open ancestors so the node is visible.
    var p = node;
    while (p && p !== root) { if (p.tagName === 'DETAILS') p.open = true; p = p.parentElement; }
    node.open = true;
    node.scrollIntoView({ block: 'center', behavior: 'smooth' });
    node.style.transition = 'background .2s ease';
    node.style.background = 'var(--accentSoft)';
    setTimeout(function () { node.style.background = ''; }, 1400);
    return true;
  }

  window.ExalmTree = { buildModel: buildModel, renderHTML: renderHTML, flash: flash };
})();
