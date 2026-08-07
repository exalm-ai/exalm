package cloudtrail

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// ctRecord is the subset of an AWS CloudTrail record we care about. Fields
// match the real CloudTrail JSON schema exactly (json tags), so a record
// straight from AWS unmarshals without transformation.
type ctRecord struct {
	UserIdentity struct {
		Type      string `json:"type"`
		UserName  string `json:"userName"`
		ARN       string `json:"arn"`
		AccountID string `json:"accountId"`
	} `json:"userIdentity"`
	EventTime        string          `json:"eventTime"`
	EventSource      string          `json:"eventSource"`
	EventName        string          `json:"eventName"`
	AWSRegion        string          `json:"awsRegion"`
	SourceIPAddress  string          `json:"sourceIPAddress"`
	UserAgent        string          `json:"userAgent"`
	ErrorCode        string          `json:"errorCode"`
	ErrorMessage     string          `json:"errorMessage"`
	ResponseElements json.RawMessage `json:"responseElements"`
}

// principal returns the best available identity label for a record.
func (r *ctRecord) principal() string {
	if r.UserIdentity.UserName != "" {
		return r.UserIdentity.UserName
	}
	if r.UserIdentity.ARN != "" {
		return r.UserIdentity.ARN
	}
	if r.UserIdentity.Type != "" {
		return r.UserIdentity.Type
	}
	return "unknown"
}

// isRoot reports whether the record was made with root account credentials.
func (r *ctRecord) isRoot() bool { return strings.EqualFold(r.UserIdentity.Type, "Root") }

// loginFailed reports whether this is a failed ConsoleLogin attempt. AWS
// records failures via a non-empty ErrorMessage or a
// responseElements.ConsoleLogin == "Failure" marker; checking both catches
// the console's actual behavior without over-fitting one shape.
func (r *ctRecord) loginFailed() bool {
	if r.EventName != "ConsoleLogin" {
		return false
	}
	if r.ErrorMessage != "" {
		return true
	}
	return strings.Contains(strings.ToLower(string(r.ResponseElements)), "failure")
}

// deletionRe matches destructive API calls across AWS services.
var deletionRe = regexp.MustCompile(`(?i)^(Delete|Terminate|Remove)`)

// privEscRe matches IAM API calls commonly used for privilege escalation.
var privEscRe = regexp.MustCompile(`(?i)^(PutUserPolicy|PutRolePolicy|AttachUserPolicy|AttachRolePolicy|CreateAccessKey|CreateLoginProfile|AddUserToGroup|UpdateAssumeRolePolicy)$`)

// notable reports whether an event is worth showing the LLM: root usage,
// any recorded error/denial, a destructive call, a privilege-escalation
// call, or a console login. Routine successful Describe/List/Get calls —
// the bulk of any real CloudTrail log — are dropped, mirroring how
// parseSyslog drops info-level lines.
func (r *ctRecord) notable() bool {
	return r.isRoot() || r.ErrorCode != "" || r.EventName == "ConsoleLogin" ||
		deletionRe.MatchString(r.EventName) || privEscRe.MatchString(r.EventName)
}

// parseCloudTrail renders a compact, LLM-facing summary of one NDJSON chunk:
// one CloudTrail record per line. Non-JSON or unparseable lines are skipped,
// never fail the chunk — the corpus (parseEvents) still keeps every event;
// only this narrative view is filtered and summarized.
func parseCloudTrail(chunk []byte) (string, error) {
	lines := strings.Split(string(chunk), "\n")
	var (
		out         strings.Builder
		kept        int
		dropped     int
		eventHist   = map[string]int{}
		errorHist   = map[string]int{}
		rootEvents  int
		errorEvents int
	)

	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		var r ctRecord
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			continue
		}
		if !r.notable() {
			dropped++
			continue
		}
		eventHist[r.EventName]++
		if r.ErrorCode != "" {
			errorHist[r.ErrorCode]++
			errorEvents++
		}
		if r.isRoot() {
			rootEvents++
		}
		detail := fmt.Sprintf("%s | %s called %s from %s", r.EventTime, r.principal(), r.EventName, r.SourceIPAddress)
		if r.ErrorCode != "" {
			detail += fmt.Sprintf(" — %s: %s", r.ErrorCode, r.ErrorMessage)
		}
		fmt.Fprintln(&out, detail)
		kept++
	}

	var header strings.Builder
	fmt.Fprintf(&header, "cloudtrail summary — %d notable events, %d routine calls dropped, %d root-account events, %d error/denied events\n\n",
		kept, dropped, rootEvents, errorEvents)
	if len(eventHist) > 0 {
		fmt.Fprintln(&header, "Top event names:")
		for _, kv := range topNStrInt(eventHist, 6) {
			fmt.Fprintf(&header, "  %s : %d\n", kv.k, kv.v)
		}
		fmt.Fprintln(&header)
	}
	if len(errorHist) > 0 {
		fmt.Fprintln(&header, "Top error codes:")
		for _, kv := range topNStrInt(errorHist, 6) {
			fmt.Fprintf(&header, "  %s : %d\n", kv.k, kv.v)
		}
		fmt.Fprintln(&header)
	}
	if kept > 0 {
		fmt.Fprintln(&header, "Events:")
	}
	return header.String() + out.String(), nil
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
