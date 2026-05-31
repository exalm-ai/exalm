package eventlog

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

// eventRecord is a relaxed view of a Get-WinEvent record. Field names match
// the property names ConvertTo-Json emits.
type eventRecord struct {
	TimeCreated      string `json:"TimeCreated"`
	Id               int    `json:"Id"`
	Level            int    `json:"Level"`
	LevelDisplayName string `json:"LevelDisplayName"`
	ProviderName     string `json:"ProviderName"`
	LogName          string `json:"LogName"`
	MachineName      string `json:"MachineName"`
	Message          string `json:"Message"`
	UserId           string `json:"UserId"`
	RecordId         int64  `json:"RecordId"`
}

// parseEvents normalizes a chunk of PowerShell JSON into a compact, one-event-per-line
// text form the LLM can read efficiently. It filters to Level <= 3 (Critical/Error/Warning)
// — informational events overwhelm the context window and hide the signal.
func parseEvents(chunk []byte) (string, error) {
	chunk = bytes.TrimSpace(chunk)
	if len(chunk) == 0 {
		return "", nil
	}

	events, raw, err := decodeEvents(chunk)
	if err != nil {
		// Not JSON we recognize — pass through as-is so the LLM still has something to read.
		return string(chunk), nil
	}
	if len(events) == 0 {
		// Decoded but had no records — return original.
		return raw, nil
	}

	var b strings.Builder
	kept := 0
	for _, e := range events {
		if e.Level != 0 && e.Level > 3 {
			continue
		}
		level := e.LevelDisplayName
		if level == "" {
			level = levelName(e.Level)
		}
		fmt.Fprintf(&b, "%s | EventID=%d | Level=%s | Provider=%s | Log=%s | Host=%s\n",
			e.TimeCreated, e.Id, level, e.ProviderName, e.LogName, e.MachineName)
		msg := strings.TrimSpace(e.Message)
		if msg != "" {
			for _, line := range strings.Split(msg, "\n") {
				fmt.Fprintf(&b, "    %s\n", strings.TrimSpace(line))
			}
		}
		b.WriteByte('\n')
		kept++
	}
	if kept == 0 {
		fmt.Fprintln(&b, "(no critical/error/warning events in this chunk)")
	}
	return b.String(), nil
}

// decodeEvents accepts either a single object or a JSON array of objects.
// ConvertTo-Json emits the array form when there are multiple records and a
// bare object when there is only one.
func decodeEvents(chunk []byte) ([]eventRecord, string, error) {
	trimmed := bytes.TrimLeft(chunk, " \t\r\n")
	if len(trimmed) == 0 {
		return nil, "", nil
	}
	if trimmed[0] == '[' {
		var arr []eventRecord
		if err := json.Unmarshal(trimmed, &arr); err != nil {
			return nil, string(chunk), err
		}
		return arr, "", nil
	}
	if trimmed[0] == '{' {
		var one eventRecord
		if err := json.Unmarshal(trimmed, &one); err != nil {
			return nil, string(chunk), err
		}
		return []eventRecord{one}, "", nil
	}
	return nil, "", fmt.Errorf("unrecognized JSON shape")
}

func levelName(n int) string {
	switch n {
	case 1:
		return "Critical"
	case 2:
		return "Error"
	case 3:
		return "Warning"
	case 4:
		return "Information"
	case 5:
		return "Verbose"
	default:
		return "Unknown"
	}
}
