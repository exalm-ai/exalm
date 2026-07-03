'use strict';
// chat.js — the conversational investigation workspace. Two entry points:
//   attach()      paints the inline chat embedded in the AI Analysis page
//                 (#ai-chat-root), called by dashboard.js after every render.
//   openScoped(id) opens the same chat anchored to one finding, inside the
//                 shared #ex-overlay (window.ExalmPanels.overlay/close), used
//                 by the ✦ Investigate action everywhere in the app.
//
// Each chat is a Session: conversationId cached in localStorage, messages
// kept in memory, and POST /api/chat for every turn. Sessions paint their own
// DOM subtree directly (not through dashboard.js's full re-render) so typing
// and streaming responses don't fight the rest of the page.

(function () {
  var E = window.Exalm || {};
  var esc = E.esc || function (s) { return String(s == null ? '' : s); };

  var INLINE_STARTERS = [
    'What is the biggest risk right now?',
    'Show me all critical findings',
    'Is this related to a recent deployment?',
    'Generate an RCA for the top incident'
  ];

  function scopedStarters(f) {
    var name = f ? f.title : 'this';
    return [
      'Why is ' + name + ' happening?',
      'Show me the previous logs',
      'Is this related to the last deployment?',
      'Suggest a permanent fix'
    ];
  }

  // ── localStorage helpers (best-effort; chat still works without them) ──
  function loadCachedId(key) { try { return localStorage.getItem(key); } catch (e) { return null; } }
  function saveCachedId(key, id) { try { localStorage.setItem(key, id); } catch (e) {} }
  function clearCachedId(key) { try { localStorage.removeItem(key); } catch (e) {} }

  // ── Session: one conversation's state + network calls ──
  function Session(key, scope) {
    this.key = key;
    this.scope = scope || {};
    this.id = loadCachedId(key);
    this.messages = [];
    this.focus = '';
    this.loading = false;
    this.error = null;
    this.draft = '';
    this.hydrated = false;
    this.lastSuggestions = [];
    this.treeOpenKeys = {};
    this.onChange = null;
  }
  Session.prototype.notify = function () { if (this.onChange) this.onChange(); };
  Session.prototype.hydrate = function () {
    var self = this;
    if (!self.id || self.hydrated) return;
    self.hydrated = true;
    fetch('/api/chat/' + encodeURIComponent(self.id))
      .then(function (r) { if (!r.ok) throw new Error('not found'); return r.json(); })
      .then(function (conv) { self.id = conv.id; self.focus = conv.focus || ''; self.messages = conv.messages || []; self.notify(); })
      .catch(function () { self.id = null; clearCachedId(self.key); self.notify(); });
  };
  Session.prototype.send = function (text) {
    var self = this;
    self.messages = self.messages.concat([{ role: 'user', content: text }]);
    self.loading = true; self.error = null; self.notify();
    var ns = self.scope.getNamespace ? self.scope.getNamespace() : (self.scope.namespace || '');
    return fetch('/api/chat', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Exalm-Request': 'true' },
      body: JSON.stringify({ conversationId: self.id || '', findingId: self.scope.findingId || '', namespace: ns, message: text })
    }).then(function (r) {
      if (r.ok) return r.json();
      if (r.status === 429) throw new Error('Exalm is busy with other investigations — try again in a moment.');
      if (r.status === 503) throw new Error('Chat is unavailable in this mode (no LLM or cluster connection).');
      throw new Error('The investigation request failed (HTTP ' + r.status + ').');
    }).then(function (conv) {
      self.id = conv.id; self.focus = conv.focus || ''; self.messages = conv.messages || []; self.loading = false;
      saveCachedId(self.key, self.id);
      self.notify();
    }).catch(function (err) {
      self.loading = false; self.error = (err && err.message) || String(err);
      self.notify();
    });
  };

  // ── Rendering ──
  function expandable(title, inner, count) {
    if (!inner) return '';
    return '<details style="margin-top:9px;border-top:1px solid var(--border);padding-top:8px;">' +
      '<summary style="cursor:pointer;font-size:10.5px;font-weight:600;text-transform:uppercase;letter-spacing:.5px;color:var(--muted);">' + esc(title) + (count ? ' (' + count + ')' : '') + '</summary>' +
      '<div style="margin-top:8px;">' + inner + '</div></details>';
  }

  function stepsHTML(steps) {
    if (!steps || !steps.length) return '';
    return steps.map(function (st) {
      var mark = st.status === 'done' ? '<span style="color:var(--good);">✓</span>' : st.status === 'unavailable' ? '<span style="color:var(--faint);">○</span>' : '<span style="color:var(--faint);">–</span>';
      return '<div style="display:flex;gap:8px;align-items:baseline;padding:3px 0;font-size:12px;">' + mark + '<span style="flex:1;">' + esc(st.label) + (st.detail ? ' <span style="color:var(--muted);">— ' + esc(st.detail) + '</span>' : '') + '</span></div>';
    }).join('');
  }

  function fmtWhen(at) {
    if (!at) return '';
    try {
      var d = new Date(at);
      if (isNaN(d.getTime())) return String(at);
      return d.toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
    } catch (e) { return String(at); }
  }

  function timelineHTML(events) {
    if (!events || !events.length) return '';
    return '<div style="position:relative;padding-left:18px;">' +
      '<div style="position:absolute;left:4px;top:2px;bottom:2px;width:2px;background:var(--border);"></div>' +
      events.map(function (ev) {
        var col = E.sevColor ? E.sevColor(ev.severity || 'info') : 'var(--muted)';
        return '<div style="position:relative;margin-bottom:11px;">' +
          '<span style="position:absolute;left:-18px;top:3px;width:9px;height:9px;border-radius:50%;background:' + col + ';border:2px solid var(--panel2);"></span>' +
          '<div style="font-family:\'IBM Plex Mono\',monospace;font-size:11px;color:var(--faint);">' + esc(fmtWhen(ev.at)) + '</div>' +
          '<div style="font-size:12.5px;color:var(--fg);font-weight:600;">' + esc(ev.label) + '</div>' +
          (ev.detail ? '<div style="font-size:11.5px;color:var(--muted);margin-top:1px;">' + esc(ev.detail) + '</div>' : '') +
          '</div>';
      }).join('') + '</div>';
  }

  // scoreLine renders the numeric confidence bar + rationale; falls back to
  // the legacy tier badge for transcripts recorded before scoring shipped.
  function scoreLine(msg) {
    if (!msg.score) return (E.confBadge && msg.confidence) ? '<div style="margin-top:9px;">' + E.confBadge(msg.confidence) + '</div>' : '';
    var col = msg.score >= 75 ? 'var(--good)' : msg.score >= 45 ? 'var(--med)' : 'var(--high)';
    return '<div style="margin-top:9px;display:flex;align-items:center;gap:8px;flex-wrap:wrap;">' +
      '<span style="font-size:9px;font-weight:700;text-transform:uppercase;letter-spacing:.4px;color:var(--faint);">Confidence</span>' +
      '<span style="display:inline-block;width:90px;height:6px;border-radius:3px;background:var(--track);overflow:hidden;"><span style="display:block;width:' + Math.max(2, Math.min(100, msg.score)) + '%;height:100%;background:' + col + ';"></span></span>' +
      '<b style="font-size:11.5px;color:' + col + ';">' + msg.score + '%</b>' +
      (msg.scoreRationale ? '<span style="font-size:11px;color:var(--muted);">— ' + esc(msg.scoreRationale) + '</span>' : '') +
      '</div>';
  }

  function planHTML(plan) {
    if (!plan || !plan.length) return '';
    return plan.map(function (ps) {
      var mark = ps.status === 'done' ? '<span style="color:var(--good);">✓</span>'
        : ps.fromCache ? '<span style="color:var(--faint);" title="served from this conversation\'s evidence cache">↺</span>'
        : ps.status === 'unavailable' ? '<span style="color:var(--faint);">○</span>' : '<span style="color:var(--faint);">–</span>';
      return '<div style="display:flex;gap:8px;align-items:baseline;padding:3px 0;font-size:12px;">' + mark +
        '<span style="flex:1;"><code style="font-family:\'IBM Plex Mono\',monospace;font-size:10.5px;color:var(--accent);">' + esc(ps.collector) + '</code>' +
        (ps.edge ? ' <span style="color:var(--faint);font-size:10.5px;">' + esc(ps.edge) + '</span>' : '') +
        (ps.fromCache ? ' <span style="color:var(--faint);font-size:10px;">(cached)</span>' : '') +
        ' <span style="color:var(--muted);">— ' + esc(ps.reason) + '</span></span></div>';
    }).join('');
  }

  function hypothesesHTML(hyps) {
    if (!hyps || !hyps.length) return '';
    return hyps.map(function (h, i) {
      var col = h.score >= 75 ? 'var(--good)' : h.score >= 45 ? 'var(--med)' : 'var(--faint)';
      var cites = function (labels, colr) {
        return (labels || []).map(function (l) { return '<a class="ex-cite" data-ev="' + esc(l) + '" style="cursor:pointer;color:' + colr + ';font-family:\'IBM Plex Mono\',monospace;font-size:10px;">[' + esc(l) + ']</a>'; }).join(' ');
      };
      return '<div style="padding:5px 0;border-bottom:1px solid var(--border);font-size:12px;">' +
        '<div style="display:flex;gap:8px;align-items:center;"><b style="color:var(--fg);">' + (i + 1) + '. ' + esc(h.title) + '</b>' +
        '<span style="display:inline-block;width:44px;height:5px;border-radius:3px;background:var(--track);overflow:hidden;"><span style="display:block;width:' + Math.max(2, Math.min(100, h.score)) + '%;height:100%;background:' + col + ';"></span></span>' +
        '<span style="font-size:10.5px;color:' + col + ';">' + h.score + '</span></div>' +
        '<div style="color:var(--muted);font-size:11px;margin-top:2px;">' + esc(h.rationale || '') +
        (h.evidenceFor && h.evidenceFor.length ? ' · for: ' + cites(h.evidenceFor, 'var(--good)') : '') +
        (h.evidenceAgainst && h.evidenceAgainst.length ? ' · against: ' + cites(h.evidenceAgainst, 'var(--high)') : '') +
        '</div></div>';
    }).join('');
  }

  function metaRow(msg, session) {
    var out = scoreLine(msg);
    out += expandable('Investigation plan', planHTML(msg.plan), (msg.plan || []).length || null);
    out += expandable('Alternative hypotheses', hypothesesHTML(msg.hypotheses), (msg.hypotheses || []).length || null);
    out += expandable('Investigation steps', stepsHTML(msg.steps));
    out += expandable('Supporting evidence', (msg.evidence && msg.evidence.length && E.evidenceHTML) ? E.evidenceHTML(msg.evidence) : '', (msg.evidence || []).length || null);
    out += expandable('Investigation timeline', timelineHTML(msg.timeline));
    if (msg.fixes && msg.fixes.length && E.fixSectionsHTML) {
      out += expandable('Suggested fixes', E.fixSectionsHTML(msg.fixes, session.scope.findingId || ''), msg.fixes.length);
    }
    if (msg.prevention && msg.prevention.length && E.fixCardHTML) {
      out += expandable('Prevention', msg.prevention.map(function (fx) { return E.fixCardHTML(fx, ''); }).join(''), msg.prevention.length);
    }
    return out;
  }

  // citeify turns [E3] markers in the assistant's HTML into clickable chips
  // that flash the matching evidence node in the tree (or open the details).
  function citeify(html) {
    return html.replace(/\[(E\d+)\]/g, function (_m, label) {
      return '<a class="ex-cite" data-ev="' + label + '" style="cursor:pointer;color:var(--accent);font-family:\'IBM Plex Mono\',monospace;font-size:11px;background:var(--accentSoft);padding:0 4px;border-radius:5px;">' + label + '</a>';
    });
  }

  function bubble(msg, session) {
    if (msg.role === 'user') {
      return '<div style="display:flex;justify-content:flex-end;margin-bottom:12px;">' +
        '<div style="max-width:78%;background:var(--accent);color:#04222b;border-radius:14px;padding:10px 14px;font-size:13px;line-height:1.5;white-space:pre-wrap;">' + esc(msg.content) + '</div></div>';
    }
    var bodyHTML = citeify(E.mdToHtml ? E.mdToHtml(msg.content) : esc(msg.content));
    return '<div style="display:flex;justify-content:flex-start;margin-bottom:12px;">' +
      '<div style="max-width:88%;background:var(--panel2);border:1px solid var(--border);border-radius:14px;padding:11px 14px;font-size:13px;line-height:1.55;color:var(--fg);">' +
      bodyHTML + metaRow(msg, session) + '</div></div>';
  }

  function typingIndicator() {
    var dots = [0, 1, 2].map(function (i) {
      return '<span style="width:6px;height:6px;border-radius:50%;background:var(--faint);display:inline-block;animation:ex-pulse 1.1s ease-in-out ' + (i * 0.15) + 's infinite;"></span>';
    }).join('');
    return '<div style="display:flex;justify-content:flex-start;margin-bottom:12px;">' +
      '<div style="background:var(--panel2);border:1px solid var(--border);border-radius:14px;padding:11px 16px;display:flex;gap:5px;align-items:center;">' + dots + '</div></div>';
  }

  function lastAssistantMessage(msgs) {
    for (var i = msgs.length - 1; i >= 0; i--) { if (msgs[i].role === 'assistant') return msgs[i]; }
    return null;
  }

  function renderBody(session, opts) {
    var html = '';
    if (opts.seedHTML) {
      html += '<div style="display:flex;justify-content:flex-start;margin-bottom:14px;">' +
        '<div style="max-width:94%;background:var(--panel2);border:1px solid var(--border);border-radius:14px;padding:12px 14px;">' +
        '<div style="font-size:10px;text-transform:uppercase;letter-spacing:.6px;color:var(--faint);font-weight:600;margin-bottom:7px;">Cluster analysis</div>' +
        opts.seedHTML + '</div></div>';
    }
    if (!session.messages.length && !session.loading) {
      html += '<div style="color:var(--muted);font-size:12.5px;padding:2px 2px 12px;">Ask a question to start investigating — Exalm gathers evidence automatically and remembers the conversation.</div>';
    }
    html += session.messages.map(function (m) { return bubble(m, session); }).join('');
    if (session.loading) html += typingIndicator();
    if (session.error) html += '<div style="color:var(--crit);font-size:12px;margin:8px 2px;">⚠ ' + esc(session.error) + '</div>';
    return html;
  }

  function suggestionsHTML(list) {
    return '<div style="display:flex;flex-wrap:wrap;gap:6px;margin:4px 0 0;">' +
      list.map(function (s, i) { return '<button class="ex-chat-sugg" data-sugg-idx="' + i + '" style="border:1px solid var(--accent);background:var(--accentSoft);color:var(--accent);border-radius:20px;cursor:pointer;font-size:11.5px;padding:5px 12px;">' + esc(s) + '</button>'; }).join('') +
      '</div>';
  }

  function inputBarHTML(session) {
    var chips = (!session.loading && session.lastSuggestions && session.lastSuggestions.length) ? suggestionsHTML(session.lastSuggestions) : '';
    return chips +
      '<div style="display:flex;gap:8px;margin-top:10px;align-items:flex-end;">' +
      '<textarea class="ex-chat-input" rows="1" placeholder="Ask about this resource — e.g. &quot;show me the previous logs&quot;" style="flex:1;resize:none;min-height:38px;max-height:120px;border:1px solid var(--border);background:var(--panel2);color:var(--fg);border-radius:10px;padding:9px 12px;font-size:13px;font-family:inherit;">' + esc(session.draft) + '</textarea>' +
      '<button class="ex-chat-send" ' + (session.loading ? 'disabled' : '') + ' style="height:38px;padding:0 16px;border:none;border-radius:9px;background:var(--accent);color:#04222b;font-size:12.5px;font-weight:700;cursor:pointer;white-space:nowrap;' + (session.loading ? 'opacity:.6;cursor:not-allowed;' : '') + '">' + (session.loading ? '…' : 'Send') + '</button></div>';
  }

  // toolbarHTML renders the export/print actions once a conversation exists.
  function toolbarHTML(session) {
    if (!session.id || !session.messages.length) return '';
    var btn = 'border:1px solid var(--border);background:var(--panel2);color:var(--muted);border-radius:7px;cursor:pointer;font-size:10.5px;padding:3px 10px;text-decoration:none;display:inline-block;';
    return '<div class="ex-chat-toolbar" style="display:flex;gap:6px;justify-content:flex-end;margin-bottom:6px;">' +
      '<a href="/api/chat/' + encodeURIComponent(session.id) + '/export?format=md" style="' + btn + '">⬇ Markdown</a>' +
      '<a href="/api/chat/' + encodeURIComponent(session.id) + '/export?format=json" style="' + btn + '">⬇ JSON</a>' +
      '<button class="ex-chat-print" style="' + btn + '">🖨 Print / PDF</button></div>';
  }

  function renderChat(session, opts) {
    opts = opts || {};
    var lastAssistant = lastAssistantMessage(session.messages);
    session.lastSuggestions = (lastAssistant && lastAssistant.suggestions && lastAssistant.suggestions.length) ? lastAssistant.suggestions : (opts.starters || []);
    return toolbarHTML(session) +
      '<div class="ex-chat-scroll" style="max-height:' + (opts.maxHeight || '520px') + ';overflow-y:auto;padding:2px 2px 10px;">' + renderBody(session, opts) + '</div>' + inputBarHTML(session);
  }

  // ── Event wiring (delegated once per root; root.innerHTML is replaced on
  // every repaint, but the root element itself is stable, so the listener
  // survives) ──
  function wire(root, session) {
    if (root._exWired) return;
    root._exWired = true;
    root.addEventListener('click', function (e) {
      if (e.target.closest('.ex-chat-send')) { doSend(); return; }
      if (e.target.closest('.ex-chat-print')) { window.print(); return; }
      var cite = e.target.closest('.ex-cite');
      if (cite) {
        var label = cite.getAttribute('data-ev');
        // Prefer flashing the tree node (inline page); otherwise open the
        // matching evidence <details> in this chat (scoped overlay).
        var tree = document.getElementById('ai-tree-root');
        if (window.ExalmTree && tree && window.ExalmTree.flash(tree, label)) return;
        var det = root.querySelector('details');
        var target = null;
        root.querySelectorAll('details').forEach(function (d) {
          if (!target && d.textContent.indexOf(label) !== -1) target = d;
        });
        if (target) { target.open = true; target.scrollIntoView({ block: 'center', behavior: 'smooth' }); }
        void det;
        return;
      }
      var sugg = e.target.closest('.ex-chat-sugg');
      if (sugg) {
        var text = (session.lastSuggestions || [])[+sugg.getAttribute('data-sugg-idx')];
        if (text) doSend(text);
      }
    });
    root.addEventListener('input', function (e) {
      if (!e.target.classList || !e.target.classList.contains('ex-chat-input')) return;
      session.draft = e.target.value;
      e.target.style.height = 'auto';
      e.target.style.height = Math.min(120, e.target.scrollHeight) + 'px';
    });
    root.addEventListener('keydown', function (e) {
      if (!e.target.classList || !e.target.classList.contains('ex-chat-input')) return;
      if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); doSend(); }
    });
    function doSend(text) {
      if (session.loading) return;
      var inp = root.querySelector('.ex-chat-input');
      var t = (typeof text === 'string' ? text : (inp ? inp.value : session.draft || '')).trim();
      if (!t) return;
      session.draft = '';
      session.send(t);
    }
  }

  // ── Inline chat (embedded in the AI Analysis page) ──
  var inlineSession = null;

  function attach() {
    var root = document.getElementById('ai-chat-root');
    if (!root) return; // not on the AI page right now
    if (!inlineSession) {
      var nsKey = (E.state && E.state.selectedNs) || 'all';
      inlineSession = new Session('exalm.chat.ns.' + nsKey, {
        findingId: '',
        getNamespace: function () { return (E.state && E.state.selectedNs && E.state.selectedNs !== 'all') ? E.state.selectedNs : ''; }
      });
      inlineSession.onChange = paintInline;
      inlineSession.hydrate();
    }
    paintInline(root);
  }

  function paintInline(rootArg) {
    var root = rootArg || document.getElementById('ai-chat-root');
    if (!root || !inlineSession) return;
    var active = document.activeElement;
    var wasFocused = !!(active && active.classList && active.classList.contains('ex-chat-input') && root.contains(active));
    var caret = wasFocused ? active.selectionStart : 0;
    root.innerHTML = renderChat(inlineSession, { seedHTML: E.legacyNarrativeHTML ? E.legacyNarrativeHTML() : '', starters: INLINE_STARTERS, maxHeight: '54vh' });
    wire(root, inlineSession);
    // The cumulative investigation tree lives in the sibling pane; expanded
    // state persists across repaints via openKeys held on the session.
    var treeRoot = document.getElementById('ai-tree-root');
    if (treeRoot && window.ExalmTree) {
      inlineSession.treeOpenKeys = inlineSession.treeOpenKeys || {};
      window.ExalmTree.renderHTML(
        window.ExalmTree.buildModel(inlineSession.messages, inlineSession.focus),
        treeRoot, inlineSession.treeOpenKeys);
    }
    if (wasFocused) {
      var inp = root.querySelector('.ex-chat-input');
      if (inp) { inp.focus(); try { inp.setSelectionRange(caret, caret); } catch (e) {} }
    }
  }

  // ── Scoped chat (✦ Investigate on a specific finding, in the overlay) ──
  var scopedSessions = {};

  function openScoped(findingId) {
    if (!window.ExalmPanels || !window.ExalmPanels.overlay) return;
    var f = E.finding ? E.finding(findingId) : null;
    var title = '✦ Investigating ' + esc(f ? f.title : findingId);
    var session = scopedSessions[findingId];
    if (!session) {
      session = new Session('exalm.chat.finding.' + findingId, {
        findingId: findingId,
        getNamespace: function () { return f ? (f.nsKey || f.ns || '') : ''; }
      });
      scopedSessions[findingId] = session;
    }
    function paint() {
      var mount = document.querySelector('#ex-overlay .ex-chat-mount');
      if (!mount) return;
      mount.innerHTML = renderChat(session, { starters: scopedStarters(f), maxHeight: '58vh' });
      wire(mount, session);
    }
    session.onChange = paint;
    window.ExalmPanels.overlay(title, '<div class="ex-chat-mount"></div>');
    paint();
    session.hydrate();
  }

  // Print support: browsers don't reliably render closed <details> content
  // even with print CSS, so expand everything before printing (covers both
  // the Print button and Ctrl+P) and restore afterwards.
  var reCloseAfterPrint = [];
  window.addEventListener('beforeprint', function () {
    reCloseAfterPrint = [];
    document.querySelectorAll('details:not([open])').forEach(function (d) {
      d.open = true;
      reCloseAfterPrint.push(d);
    });
  });
  window.addEventListener('afterprint', function () {
    reCloseAfterPrint.forEach(function (d) { d.open = false; });
    reCloseAfterPrint = [];
  });

  window.ExalmChat = { attach: attach, openScoped: openScoped };
  // dashboard.js's first paint may already have happened before this module
  // loads (script tags run in order, after the page's initial render call).
  attach();
})();
