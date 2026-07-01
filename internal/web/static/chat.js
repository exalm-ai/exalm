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
    this.loading = false;
    this.error = null;
    this.draft = '';
    this.hydrated = false;
    this.lastSuggestions = [];
    this.onChange = null;
  }
  Session.prototype.notify = function () { if (this.onChange) this.onChange(); };
  Session.prototype.hydrate = function () {
    var self = this;
    if (!self.id || self.hydrated) return;
    self.hydrated = true;
    fetch('/api/chat/' + encodeURIComponent(self.id))
      .then(function (r) { if (!r.ok) throw new Error('not found'); return r.json(); })
      .then(function (conv) { self.id = conv.id; self.messages = conv.messages || []; self.notify(); })
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
      self.id = conv.id; self.messages = conv.messages || []; self.loading = false;
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

  function metaRow(msg, session) {
    var out = '';
    var conf = E.confBadge ? E.confBadge(msg.confidence) : '';
    if (conf) out += '<div style="margin-top:9px;">' + conf + '</div>';
    out += expandable('Investigation steps', stepsHTML(msg.steps));
    out += expandable('Supporting evidence', (msg.evidence && msg.evidence.length && E.evidenceHTML) ? E.evidenceHTML(msg.evidence) : '', (msg.evidence || []).length || null);
    out += expandable('Investigation timeline', timelineHTML(msg.timeline));
    if (msg.fixes && msg.fixes.length && E.fixSectionsHTML) {
      out += expandable('Suggested fixes', E.fixSectionsHTML(msg.fixes, session.scope.findingId || ''), msg.fixes.length);
    }
    return out;
  }

  function bubble(msg, session) {
    if (msg.role === 'user') {
      return '<div style="display:flex;justify-content:flex-end;margin-bottom:12px;">' +
        '<div style="max-width:78%;background:var(--accent);color:#04222b;border-radius:14px;padding:10px 14px;font-size:13px;line-height:1.5;white-space:pre-wrap;">' + esc(msg.content) + '</div></div>';
    }
    var bodyHTML = E.mdToHtml ? E.mdToHtml(msg.content) : esc(msg.content);
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

  function renderChat(session, opts) {
    opts = opts || {};
    var lastAssistant = lastAssistantMessage(session.messages);
    session.lastSuggestions = (lastAssistant && lastAssistant.suggestions && lastAssistant.suggestions.length) ? lastAssistant.suggestions : (opts.starters || []);
    return '<div class="ex-chat-scroll" style="max-height:' + (opts.maxHeight || '520px') + ';overflow-y:auto;padding:2px 2px 10px;">' + renderBody(session, opts) + '</div>' + inputBarHTML(session);
  }

  // ── Event wiring (delegated once per root; root.innerHTML is replaced on
  // every repaint, but the root element itself is stable, so the listener
  // survives) ──
  function wire(root, session) {
    if (root._exWired) return;
    root._exWired = true;
    root.addEventListener('click', function (e) {
      if (e.target.closest('.ex-chat-send')) { doSend(); return; }
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

  window.ExalmChat = { attach: attach, openScoped: openScoped };
  // dashboard.js's first paint may already have happened before this module
  // loads (script tags run in order, after the page's initial render call).
  attach();
})();
