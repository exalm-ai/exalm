package web

// chat_export_html.go renders a persisted investigation as a STANDALONE
// HTML report — inline CSS, no external assets, @media print styles so the
// browser's Print → Save-as-PDF produces a clean document. Every piece of
// conversation content is escaped via html/template; nothing user-authored
// is emitted raw.

import (
	"fmt"
	"html/template"
	"strings"

	"github.com/exalm-ai/exalm/pkg/plugin"
)

// conversationHTML renders the full investigation report.
func conversationHTML(c *plugin.Conversation, analyzer string) string {
	esc := template.HTMLEscapeString
	var b strings.Builder

	title := "Investigation report"
	if c.Focus != "" {
		title += " — " + c.Focus
	}

	b.WriteString(`<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>` + esc(title) + `</title>
<style>
  body { font-family: 'Segoe UI', system-ui, sans-serif; margin: 0 auto; max-width: 860px; padding: 32px 24px; color: #1a2433; background: #fff; line-height: 1.55; }
  h1 { font-size: 22px; border-bottom: 2px solid #0e9bc4; padding-bottom: 8px; }
  h2 { font-size: 16px; margin-top: 28px; color: #0b3a4a; }
  h3 { font-size: 13.5px; margin-top: 18px; text-transform: uppercase; letter-spacing: .5px; color: #5a6b82; }
  table { border-collapse: collapse; width: 100%; font-size: 12.5px; margin: 8px 0; }
  th, td { border: 1px solid #dfe6ef; padding: 5px 9px; text-align: left; vertical-align: top; }
  th { background: #f4f8fc; }
  code, pre { font-family: 'Consolas', monospace; font-size: 12px; background: #f4f8fc; border-radius: 5px; }
  code { padding: 1px 6px; }
  pre { padding: 9px 12px; white-space: pre-wrap; border: 1px solid #dfe6ef; }
  .meta { color: #5a6b82; font-size: 12.5px; }
  .label { display: inline-block; font-family: 'Consolas', monospace; font-size: 11px; font-weight: 700; background: #eaf0f7; color: #0e9bc4; border-radius: 9px; padding: 0 7px; margin-right: 5px; }
  .score { font-weight: 700; color: #0f9d6b; }
  .question { background: #f4f8fc; border-left: 3px solid #0e9bc4; padding: 8px 13px; margin: 18px 0 8px; font-weight: 600; }
  .fix-temp { border-left: 3px solid #ea7317; padding-left: 10px; margin: 6px 0; }
  .fix-root { border-left: 3px solid #0f9d6b; padding-left: 10px; margin: 6px 0; }
  .fix-prev { border-left: 3px solid #2563eb; padding-left: 10px; margin: 6px 0; }
  footer { margin-top: 36px; color: #90a0b5; font-size: 11.5px; border-top: 1px solid #dfe6ef; padding-top: 10px; }
  @media print { body { padding: 0; max-width: none; } .question { break-inside: avoid; } table { break-inside: avoid; } }
</style></head><body>
`)

	fmt.Fprintf(&b, "<h1>%s</h1>\n", esc(title))
	b.WriteString(`<p class="meta">`)
	if analyzer != "" {
		fmt.Fprintf(&b, "Analyzer: <code>%s</code> · ", esc(analyzer))
	}
	fmt.Fprintf(&b, "Conversation <code>%s</code>", esc(c.ID))
	if !c.CreatedAt.IsZero() {
		fmt.Fprintf(&b, " · Started %s · Last updated %s",
			esc(c.CreatedAt.UTC().Format("2006-01-02 15:04 UTC")), esc(c.UpdatedAt.UTC().Format("2006-01-02 15:04 UTC")))
	}
	b.WriteString("</p>\n")

	// ── Executive summary (from the latest assistant turn) ──
	if last := lastAssistantMsg(c); last != nil {
		b.WriteString("<h2>Executive summary</h2>\n<table>\n")
		if c.Focus != "" {
			fmt.Fprintf(&b, "<tr><th>Focus resource</th><td><code>%s</code></td></tr>\n", esc(c.Focus))
		}
		if len(last.Hypotheses) > 0 {
			fmt.Fprintf(&b, "<tr><th>Root cause (most likely)</th><td>%s</td></tr>\n", esc(last.Hypotheses[0].Title))
		}
		if last.Score > 0 {
			fmt.Fprintf(&b, `<tr><th>Confidence</th><td><span class="score">%d%%</span> — %s</td></tr>`+"\n",
				last.Score, esc(last.ScoreRationale))
		}
		if fp := c.Fingerprint; fp != "" {
			fmt.Fprintf(&b, "<tr><th>Symptom</th><td><code>%s</code></td></tr>\n", esc(strings.SplitN(fp, "\x1f", 2)[0]))
		}
		fmt.Fprintf(&b, "<tr><th>Turns</th><td>%d</td></tr>\n", len(c.Messages)/2)
		b.WriteString("</table>\n")
	}

	// ── Per-turn technical transcript ──
	for _, m := range c.Messages {
		if m.Role == "user" {
			fmt.Fprintf(&b, `<div class="question">Q: %s</div>`+"\n", esc(m.Content))
			continue
		}
		fmt.Fprintf(&b, "<pre>%s</pre>\n", esc(m.Content))
		if m.Score > 0 {
			fmt.Fprintf(&b, `<p class="meta">Confidence <span class="score">%d%%</span> — %s</p>`+"\n", m.Score, esc(m.ScoreRationale))
		}
		if len(m.Plan) > 0 {
			b.WriteString("<h3>Investigation plan</h3>\n<table><tr><th>Step</th><th>Collector</th><th>Edge</th><th>Status</th><th>Why</th></tr>\n")
			for _, ps := range m.Plan {
				status := ps.Status
				if ps.FromCache {
					status += " (cached)"
				}
				fmt.Fprintf(&b, "<tr><td>%s</td><td><code>%s</code></td><td>%s</td><td>%s</td><td>%s</td></tr>\n",
					esc(ps.ID), esc(ps.Collector), esc(ps.Edge), esc(status), esc(ps.Reason))
			}
			b.WriteString("</table>\n")
		}
		if len(m.Hypotheses) > 0 {
			b.WriteString("<h3>Hypotheses considered</h3>\n<table><tr><th>#</th><th>Hypothesis</th><th>Score</th><th>For</th><th>Against</th></tr>\n")
			for i, h := range m.Hypotheses {
				fmt.Fprintf(&b, "<tr><td>%d</td><td>%s</td><td>%d</td><td>%s</td><td>%s</td></tr>\n",
					i+1, esc(h.Title), h.Score, esc(strings.Join(h.EvidenceFor, ", ")), esc(strings.Join(h.EvidenceAgainst, ", ")))
			}
			b.WriteString("</table>\n")
		}
		if len(m.Evidence) > 0 {
			b.WriteString("<h3>Evidence</h3>\n")
			for _, e := range m.Evidence {
				fmt.Fprintf(&b, `<p><span class="label">%s</span><code>%s/%s</code>`, esc(orDot(e.Label)), esc(e.Kind), esc(e.Source))
				if e.Edge != "" {
					fmt.Fprintf(&b, ` <span class="meta">edge %s</span>`, esc(e.Edge))
				}
				if e.FromCache {
					b.WriteString(` <span class="meta">(cached)</span>`)
				}
				b.WriteString("</p>\n")
				if e.Excerpt != "" {
					fmt.Fprintf(&b, "<pre>%s</pre>\n", esc(e.Excerpt))
				}
				if e.Anchor != "" {
					fmt.Fprintf(&b, `<p class="meta">reproduce: <code>%s</code></p>`+"\n", esc(e.Anchor))
				}
			}
		}
		writeHTMLFixes(&b, m.Fixes, m.Prevention)
		if len(m.Timeline) > 0 {
			b.WriteString("<h3>Timeline</h3>\n<table><tr><th>Time</th><th>Event</th><th>Detail</th></tr>\n")
			for _, ev := range m.Timeline {
				fmt.Fprintf(&b, "<tr><td><code>%s</code></td><td>%s</td><td>%s</td></tr>\n",
					esc(ev.At.Format("15:04:05")), esc(ev.Label), esc(ev.Detail))
			}
			b.WriteString("</table>\n")
		}
	}

	b.WriteString("<footer>Generated by Exalm — evidence excerpts are redacted before storage. Print this page to produce a PDF.</footer>\n</body></html>\n")
	return b.String()
}

func lastAssistantMsg(c *plugin.Conversation) *plugin.ConversationMessage {
	for i := len(c.Messages) - 1; i >= 0; i-- {
		if c.Messages[i].Role == "assistant" {
			return &c.Messages[i]
		}
	}
	return nil
}

func orDot(s string) string {
	if s == "" {
		return "•"
	}
	return s
}

func writeHTMLFixes(b *strings.Builder, fixes, prevention []plugin.RemediationAction) {
	esc := template.HTMLEscapeString
	var temp, root []plugin.RemediationAction
	for _, fx := range fixes {
		if fx.FixType == "root-cause" {
			root = append(root, fx)
		} else {
			temp = append(temp, fx)
		}
	}
	writeGroup := func(title, class string, actions []plugin.RemediationAction) {
		if len(actions) == 0 {
			return
		}
		fmt.Fprintf(b, "<h3>%s</h3>\n", esc(title))
		for _, fx := range actions {
			fmt.Fprintf(b, `<div class="%s">%s`, class, esc(fx.Description))
			if fx.KubectlCmd != "" {
				fmt.Fprintf(b, "<br><code>%s</code>", esc(fx.KubectlCmd))
			}
			b.WriteString("</div>\n")
		}
	}
	writeGroup("Immediate mitigation (temporary)", "fix-temp", temp)
	writeGroup("Root-cause fix", "fix-root", root)
	writeGroup("Prevention", "fix-prev", prevention)
}
