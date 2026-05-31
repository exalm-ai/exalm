package iis

import (
	"fmt"
	"strconv"
	"strings"
)

// parseW3C normalizes IIS W3C Extended log content. It honors `#Fields:`
// headers (which can change mid-file when IIS rolls config) and surfaces
// summary counters the LLM can reason about: 5xx-per-minute, slow requests,
// top status codes.
func parseW3C(chunk []byte) (string, error) {
	lines := strings.Split(string(chunk), "\n")
	var fields []string

	var (
		total      int
		statusHist = map[string]int{}
		slowReqs   []string
		errorLines []string
		uriHist    = map[string]int{}
		methodHist = map[string]int{}
		ipHist     = map[string]int{}
		errPerMin  = map[string]int{}
	)

	const slowMs = 5000
	const maxSlow = 10
	const maxErr = 15

	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "#") {
			if strings.HasPrefix(line, "#Fields:") {
				fields = strings.Fields(strings.TrimPrefix(line, "#Fields:"))
			}
			continue
		}
		parts := strings.Fields(line)
		if len(fields) == 0 || len(parts) < len(fields) {
			continue
		}
		total++

		rec := map[string]string{}
		for i, f := range fields {
			rec[f] = parts[i]
		}
		status := rec["sc-status"]
		statusHist[status]++
		methodHist[rec["cs-method"]]++
		uriHist[rec["cs-uri-stem"]]++
		if ip := rec["c-ip"]; ip != "" {
			ipHist[ip]++
		}

		if status != "" && status[0] == '5' {
			minuteBucket := rec["date"] + " " + truncTo(rec["time"], 5) // "HH:MM"
			errPerMin[minuteBucket]++
			if len(errorLines) < maxErr {
				errorLines = append(errorLines, fmt.Sprintf("%s %s %s %s %s -> %s", rec["date"], rec["time"], rec["cs-method"], rec["cs-uri-stem"], rec["c-ip"], status))
			}
		}
		if ms, err := strconv.Atoi(rec["time-taken"]); err == nil && ms >= slowMs {
			if len(slowReqs) < maxSlow {
				slowReqs = append(slowReqs, fmt.Sprintf("%dms %s %s %s -> %s", ms, rec["cs-method"], rec["cs-uri-stem"], rec["c-ip"], status))
			}
		}
	}

	var b strings.Builder
	fmt.Fprintf(&b, "IIS W3C summary — %d request(s) parsed\n\n", total)
	fmt.Fprintf(&b, "Top status codes:\n")
	for _, kv := range topN(statusHist, 6) {
		fmt.Fprintf(&b, "  %s : %d\n", kv.k, kv.v)
	}
	if len(errPerMin) > 0 {
		fmt.Fprintf(&b, "\n5xx error bursts (per minute):\n")
		for _, kv := range topN(errPerMin, 5) {
			fmt.Fprintf(&b, "  %s : %d 5xx\n", kv.k, kv.v)
		}
	}
	if len(slowReqs) > 0 {
		fmt.Fprintf(&b, "\nSlow requests (>=%dms):\n", slowMs)
		for _, s := range slowReqs {
			fmt.Fprintf(&b, "  %s\n", s)
		}
	}
	if len(errorLines) > 0 {
		fmt.Fprintf(&b, "\nSample 5xx lines:\n")
		for _, s := range errorLines {
			fmt.Fprintf(&b, "  %s\n", s)
		}
	}
	fmt.Fprintf(&b, "\nTop URIs:\n")
	for _, kv := range topN(uriHist, 8) {
		fmt.Fprintf(&b, "  %s : %d\n", kv.k, kv.v)
	}
	fmt.Fprintf(&b, "\nTop methods:\n")
	for _, kv := range topN(methodHist, 4) {
		fmt.Fprintf(&b, "  %s : %d\n", kv.k, kv.v)
	}
	if len(ipHist) > 0 {
		fmt.Fprintf(&b, "\nTop client IPs:\n")
		for _, kv := range topN(ipHist, 8) {
			fmt.Fprintf(&b, "  %s : %d\n", kv.k, kv.v)
		}
	}
	return b.String(), nil
}

type kv struct {
	k string
	v int
}

func topN(m map[string]int, n int) []kv {
	out := make([]kv, 0, len(m))
	for k, v := range m {
		out = append(out, kv{k, v})
	}
	// simple selection sort: maps are small here (status codes, URIs, IPs).
	for i := 0; i < len(out) && i < n; i++ {
		maxIdx := i
		for j := i + 1; j < len(out); j++ {
			if out[j].v > out[maxIdx].v {
				maxIdx = j
			}
		}
		out[i], out[maxIdx] = out[maxIdx], out[i]
	}
	if len(out) > n {
		out = out[:n]
	}
	return out
}

func truncTo(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
