package httplog

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Combined log format: IP - user [date] "METHOD URI PROTO" status size "referer" "ua"
var combinedRe = regexp.MustCompile(`^(\S+) \S+ (\S+) \[([^\]]+)\] "(\S+) (\S+) (\S+)" (\d+) (\S+)(?: "([^"]*)" "([^"]*)")?(?:\s+(\d+(?:\.\d+)?))?`)

// Apache error log: [date] [level] [pid] [client IP] msg
var apacheErrRe = regexp.MustCompile(`^\[([^\]]+)\] \[(\w+)\](?: \[pid \d+(?::tid \d+)?\])?(?: \[client ([^\]]+)\])? (.*)$`)

// Nginx error log: date level [pid#tid] msg
var nginxErrRe = regexp.MustCompile(`^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) \[(\w+)\] \d+#\d+:\s*(.*)$`)

// parseHTTP detects access vs error log per line and emits a compact summary
// the LLM can analyze.
func parseHTTP(chunk []byte) (string, error) {
	lines := strings.Split(string(chunk), "\n")
	var (
		accessTotal int
		errTotal    int
		statusHist  = map[string]int{}
		methodHist  = map[string]int{}
		uriHist     = map[string]int{}
		ipHist      = map[string]int{}
		errPerMin   = map[string]int{}
		slowReqs    []string
		errSamples  []string
		errLevels   = map[string]int{}
	)
	const slowMs = 5000
	const maxSamples = 12

	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		if m := combinedRe.FindStringSubmatch(line); m != nil {
			accessTotal++
			ip, ts, method, uri, status := m[1], m[3], m[4], m[5], m[7]
			statusHist[status]++
			methodHist[method]++
			uriHist[uri]++
			if ip != "" {
				ipHist[ip]++
			}
			if status != "" && status[0] == '5' {
				bucket := truncTo(ts, 17) // "dd/Mon/yyyy:hh:mm"
				errPerMin[bucket]++
				if len(errSamples) < maxSamples {
					errSamples = append(errSamples, fmt.Sprintf("%s %s %s %s %s", ts, method, uri, ip, status))
				}
			}
			if rt := m[11]; rt != "" {
				if sec, err := strconv.ParseFloat(rt, 64); err == nil && sec*1000 >= slowMs {
					if len(slowReqs) < maxSamples {
						slowReqs = append(slowReqs, fmt.Sprintf("%.0fms %s %s %s -> %s", sec*1000, method, uri, ip, status))
					}
				}
			}
			continue
		}
		if m := apacheErrRe.FindStringSubmatch(line); m != nil {
			errTotal++
			errLevels[m[2]]++
			if len(errSamples) < maxSamples {
				errSamples = append(errSamples, fmt.Sprintf("apache %s [%s] %s", m[1], m[2], m[4]))
			}
			continue
		}
		if m := nginxErrRe.FindStringSubmatch(line); m != nil {
			errTotal++
			errLevels[m[2]]++
			if len(errSamples) < maxSamples {
				errSamples = append(errSamples, fmt.Sprintf("nginx %s [%s] %s", m[1], m[2], m[3]))
			}
			continue
		}
	}

	var b strings.Builder
	fmt.Fprintf(&b, "HTTP log summary — %d access record(s), %d error record(s)\n\n", accessTotal, errTotal)
	if len(statusHist) > 0 {
		fmt.Fprintf(&b, "Top status codes:\n")
		for _, kv := range topN(statusHist, 6) {
			fmt.Fprintf(&b, "  %s : %d\n", kv.k, kv.v)
		}
		fmt.Fprintln(&b)
	}
	if len(errPerMin) > 0 {
		fmt.Fprintf(&b, "5xx bursts:\n")
		for _, kv := range topN(errPerMin, 5) {
			fmt.Fprintf(&b, "  %s : %d 5xx\n", kv.k, kv.v)
		}
		fmt.Fprintln(&b)
	}
	if len(slowReqs) > 0 {
		fmt.Fprintf(&b, "Slow requests (>=%dms):\n", slowMs)
		for _, s := range slowReqs {
			fmt.Fprintf(&b, "  %s\n", s)
		}
		fmt.Fprintln(&b)
	}
	if len(errLevels) > 0 {
		fmt.Fprintf(&b, "Error log levels:\n")
		for _, kv := range topN(errLevels, 6) {
			fmt.Fprintf(&b, "  %s : %d\n", kv.k, kv.v)
		}
		fmt.Fprintln(&b)
	}
	if len(uriHist) > 0 {
		fmt.Fprintf(&b, "Top URIs:\n")
		for _, kv := range topN(uriHist, 8) {
			fmt.Fprintf(&b, "  %s : %d\n", kv.k, kv.v)
		}
		fmt.Fprintln(&b)
	}
	if len(ipHist) > 0 {
		fmt.Fprintf(&b, "Top client IPs:\n")
		for _, kv := range topN(ipHist, 8) {
			fmt.Fprintf(&b, "  %s : %d\n", kv.k, kv.v)
		}
		fmt.Fprintln(&b)
	}
	if len(errSamples) > 0 {
		fmt.Fprintf(&b, "Sample error/5xx lines:\n")
		for _, s := range errSamples {
			fmt.Fprintf(&b, "  %s\n", s)
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

func truncTo(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
