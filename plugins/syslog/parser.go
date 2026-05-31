package syslog

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// parseSyslog auto-detects per line: RFC 5424, RFC 3164, or journalctl JSON.
// It filters lines to priority <= 4 (emerg, alert, crit, err, warning) and
// produces a compact one-line-per-event view for the LLM.
func parseSyslog(chunk []byte) (string, error) {
	lines := strings.Split(string(chunk), "\n")
	var (
		out      strings.Builder
		kept     int
		dropped  int
		hostHist = map[string]int{}
		unitHist = map[string]int{}
	)

	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}

		ev, ok := parseLine(line)
		if !ok {
			continue
		}
		if ev.priority > 4 {
			dropped++
			continue
		}
		hostHist[ev.host]++
		unitHist[ev.tag]++
		fmt.Fprintf(&out, "%s | %s | host=%s tag=%s | %s\n",
			ev.timestamp, prioName(ev.priority), ev.host, ev.tag, ev.message)
		kept++
	}

	var header strings.Builder
	fmt.Fprintf(&header, "syslog summary — %d severe events, %d info-level dropped\n\n", kept, dropped)
	if len(unitHist) > 0 {
		fmt.Fprintf(&header, "Top tags/units:\n")
		for _, kv := range topNStrInt(unitHist, 6) {
			fmt.Fprintf(&header, "  %s : %d\n", kv.k, kv.v)
		}
		fmt.Fprintln(&header)
	}
	if len(hostHist) > 1 {
		fmt.Fprintf(&header, "Top hosts:\n")
		for _, kv := range topNStrInt(hostHist, 6) {
			fmt.Fprintf(&header, "  %s : %d\n", kv.k, kv.v)
		}
		fmt.Fprintln(&header)
	}
	if kept > 0 {
		fmt.Fprintln(&header, "Events:")
	}
	return header.String() + out.String(), nil
}

type event struct {
	timestamp string
	host      string
	tag       string
	priority  int
	message   string
}

var (
	rfc5424Re = regexp.MustCompile(`^<(\d+)>\d+ (\S+) (\S+) (\S+) (\S+) (\S+) (.*)$`)
	rfc3164Re = regexp.MustCompile(`^<(\d+)>([A-Z][a-z]{2} {1,2}\d+ \d{2}:\d{2}:\d{2}) (\S+) ([^:]+): (.*)$`)
	bsdRe     = regexp.MustCompile(`^([A-Z][a-z]{2} {1,2}\d+ \d{2}:\d{2}:\d{2}) (\S+) ([^:]+): (.*)$`)
)

// parseLine returns false if the line isn't a recognized syslog/journal format.
func parseLine(line string) (event, bool) {
	// journalctl -o json produces one JSON object per line.
	if strings.HasPrefix(line, "{") && strings.HasSuffix(line, "}") {
		return parseJournalctl(line)
	}
	// RFC 5424: "<PRI>VERSION TIMESTAMP HOST APP-NAME PROCID MSGID MSG"
	if m := rfc5424Re.FindStringSubmatch(line); m != nil {
		pri, _ := strconv.Atoi(m[1])
		return event{
			timestamp: m[2],
			host:      m[3],
			tag:       m[4],
			priority:  pri & 7, // low 3 bits are severity
			message:   m[7],
		}, true
	}
	// RFC 3164 with PRI: "<PRI>MMM dd hh:mm:ss host tag: msg"
	if m := rfc3164Re.FindStringSubmatch(line); m != nil {
		pri, _ := strconv.Atoi(m[1])
		return event{
			timestamp: m[2],
			host:      m[3],
			tag:       m[4],
			priority:  pri & 7,
			message:   m[5],
		}, true
	}
	// Bare BSD syslog (no PRI, common in /var/log/messages)
	if m := bsdRe.FindStringSubmatch(line); m != nil {
		return event{
			timestamp: m[1],
			host:      m[2],
			tag:       m[3],
			priority:  6, // default informational
			message:   m[4],
		}, true
	}
	return event{}, false
}

// parseJournalctl handles one line of `journalctl -o json` output.
func parseJournalctl(line string) (event, bool) {
	var rec map[string]any
	if err := json.Unmarshal([]byte(line), &rec); err != nil {
		return event{}, false
	}
	prio := 6
	if v, ok := rec["PRIORITY"].(string); ok {
		if n, err := strconv.Atoi(v); err == nil {
			prio = n
		}
	}
	host, _ := rec["_HOSTNAME"].(string)
	unit, _ := rec["_SYSTEMD_UNIT"].(string)
	if unit == "" {
		unit, _ = rec["SYSLOG_IDENTIFIER"].(string)
	}
	msg, _ := rec["MESSAGE"].(string)
	ts, _ := rec["__REALTIME_TIMESTAMP"].(string)
	return event{
		timestamp: ts,
		host:      host,
		tag:       unit,
		priority:  prio,
		message:   msg,
	}, true
}

func prioName(p int) string {
	switch p {
	case 0:
		return "emerg"
	case 1:
		return "alert"
	case 2:
		return "crit"
	case 3:
		return "err"
	case 4:
		return "warning"
	case 5:
		return "notice"
	case 6:
		return "info"
	case 7:
		return "debug"
	default:
		return "unknown"
	}
}

type kv struct {
	k string
	v int
}

func topNStrInt(m map[string]int, n int) []kv {
	out := make([]kv, 0, len(m))
	for k, v := range m {
		out = append(out, kv{k, v})
	}
	for i := 0; i < len(out) && i < n; i++ {
		max := i
		for j := i + 1; j < len(out); j++ {
			if out[j].v > out[max].v {
				max = j
			}
		}
		out[i], out[max] = out[max], out[i]
	}
	if len(out) > n {
		out = out[:n]
	}
	return out
}
