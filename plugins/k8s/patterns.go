package k8s

import (
	"regexp"
	"strings"
)

// logPattern is a named regex applied to log content.
type logPattern struct {
	Category string
	Re       *regexp.Regexp
}

// defaultLogPatterns covers the four service-level signal categories.
// Order matters: more specific patterns run first.
var defaultLogPatterns = []logPattern{
	{
		Category: "db-error",
		Re: regexp.MustCompile(
			`(?i)(connection refused|deadlock detected|too many connections|` +
				`max_connections|could not connect to server|` +
				`connection pool exhausted|timeout acquiring connection|` +
				`driver: bad connection|constraint violation)`),
	},
	{
		Category: "http-5xx",
		Re: regexp.MustCompile(
			// Match common log formats: nginx, Apache, JSON, structured
			`(?:HTTP/[0-9.]+ |"status":\s*|status[=: ]+|" )(5\d{2})(?:[", \r\n]|$)`),
	},
	{
		Category: "latency",
		Re: regexp.MustCompile(
			// Matches: "took 2341ms", "duration=3.2s", "latency: 1500ms", "response_time=2.1s"
			`(?i)(?:duration|took|elapsed|latency|response[_\-]?time)[=:\s]+` +
				`(?:[0-9]+\.)?[0-9]{4,}m?s|` + // >= 1000ms
				`(?i)(?:duration|took|elapsed|latency|response[_\-]?time)[=:\s]+` +
				`[1-9][0-9]*\.[0-9]+s`), // decimal seconds >= 1.0 (e.g. 2.3s)
	},
	{
		Category: "dependency",
		Re: regexp.MustCompile(
			`(?i)(circuit.?breaker|ECONNREFUSED|no route to host|` +
				`connection timed out|upstream unavailable|` +
				`service unavailable|bad gateway|` +
				`\"503\"|\"504\"|status 503|status 504|HTTP 503|HTTP 504)`),
	},
	{
		Category: "disk-error",
		Re: regexp.MustCompile(
			`(?i)(no space left on device|ENOSPC|disk quota exceeded|` +
				`read.?only file system|input.?output error|file system full|` +
				`failed to load log segment|unclean shutdown.*log dir)`),
	},
	{
		Category: "cpu-throttle",
		Re: regexp.MustCompile(
			`(?i)(cpu.{0,10}throttl|throttled.{0,10}cpu|cfs.{0,10}throttl|` +
				`container.*cpu.*limit.*reached|cpu.{0,5}limit.*reached|` +
				`cpu usage.{0,10}[89][0-9]%|cpu usage.{0,10}100%)`),
	},
	{
		Category: "rbac-forbidden",
		Re: regexp.MustCompile(
			`(?i)(forbidden.*resource|unauthorized.*api|403 Forbidden|` +
				`cannot list resource|cannot get resource|cannot watch resource|` +
				`User.*cannot.*in API group|serviceaccount.*forbidden)`),
	},
	{
		Category: "cert-expiry",
		Re: regexp.MustCompile(
			`(?i)(certificate.*expired|x509.*expired|x509.*certificate.*valid|` +
				`tls.*handshake.*fail|certificate has expired|` +
				`not yet valid.*current time|TLS handshake failed.*certificate)`),
	},
	{
		Category: "oom-system",
		Re: regexp.MustCompile(
			`(?i)(killed process.*out of memory|oom.kill.event|` +
				`oom-kill-event|Out of memory: Killed process|` +
				`memory cgroup out of memory)`),
	},
	{
		// probe-failure catches application-level messages emitted when a
		// health endpoint is slow or unhealthy. Complements the Kubernetes
		// Unhealthy event detection in findings.go with log-level signal.
		Category: "probe-failure",
		Re: regexp.MustCompile(
			`(?i)(readiness probe failed|liveness probe failed|startup probe failed|` +
				`probe.*failed.*timeout|http probe failed with statuscode|` +
				`health.*check.*fail|healthcheck.*fail)`),
	},
	{
		// latency-p99 catches high-percentile latency reported in structured logs.
		// Complements the general latency pattern (which targets p50-ish averages)
		// by specifically flagging P95/P99 tail latency spikes.
		Category: "latency-p99",
		Re: regexp.MustCompile(
			`(?i)(?:p99|p95|p999|percentile[_\-]?9[59]|99th|95th)[=:\s]+` +
				`(?:[0-9]+\.)?[0-9]{4,}(?:ms|milliseconds?)|` + // >=1000ms
				`(?i)(?:p99|p95|p999|percentile[_\-]?9[59]|99th|95th)[=:\s]+` +
				`(?:[2-9][0-9]*|[1-9][0-9]{2,})(?:\.[0-9]+)?s`), // >=2s
	},
}

// scanLogPatterns runs all default patterns over log content and returns
// aggregated anomalies. Only unhealthy-container logs are scanned.
func scanLogPatterns(content string) []LogAnomaly {
	if content == "" {
		return nil
	}
	lines := strings.Split(content, "\n")
	counts := make(map[string]int, len(defaultLogPatterns))
	samples := make(map[string]string, len(defaultLogPatterns))

	for _, line := range lines {
		if line == "" {
			continue
		}
		for _, p := range defaultLogPatterns {
			if p.Re.MatchString(line) {
				counts[p.Category]++
				if _, seen := samples[p.Category]; !seen {
					s := line
					if len(s) > 120 {
						s = s[:120] + "…"
					}
					samples[p.Category] = s
				}
			}
		}
	}

	var anomalies []LogAnomaly
	// Emit in a stable order matching defaultLogPatterns.
	for _, p := range defaultLogPatterns {
		if c := counts[p.Category]; c > 0 {
			anomalies = append(anomalies, LogAnomaly{
				Category: p.Category,
				Count:    c,
				Sample:   samples[p.Category],
			})
		}
	}
	return anomalies
}
