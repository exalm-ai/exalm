package k8s

import (
	"strings"
	"testing"
	"time"
)

func TestFormat_NoPods(t *testing.T) {
	s := Snapshot{Namespace: "default", TotalPods: 5}
	out := Format(s, 200*1024)
	if !strings.Contains(out, "No unhealthy pods found") {
		t.Errorf("expected no-issues message, got: %q", out)
	}
}

func TestFormat_BasicPod(t *testing.T) {
	s := Snapshot{
		Namespace: "prod",
		TotalPods: 3,
		UnhealthyPods: []PodSummary{
			{Namespace: "prod", Name: "api-7d9f", Phase: "Running", Reason: "CrashLoopBackOff", RestartCount: 7, Age: "2h"},
		},
	}
	out := Format(s, 200*1024)
	if !strings.Contains(out, "prod/api-7d9f") {
		t.Errorf("pod name missing: %q", out)
	}
	if !strings.Contains(out, "CrashLoopBackOff") {
		t.Errorf("reason missing: %q", out)
	}
	if !strings.Contains(out, "Restarts: 7") {
		t.Errorf("restart count missing: %q", out)
	}
}

func TestFormat_ByteCapOmitsPods(t *testing.T) {
	pods := make([]PodSummary, 50)
	for i := range pods {
		pods[i] = PodSummary{
			Namespace: "default",
			Name:      "pod-" + string(rune('a'+i%26)),
			Phase:     "Running",
			Reason:    "CrashLoopBackOff",
			Age:       "1h",
		}
	}
	s := Snapshot{TotalPods: 50, UnhealthyPods: pods}
	out := Format(s, 1000)
	// Allow a small tolerance for the omitted-pods trailer line.
	if len(out) > 1100 {
		t.Errorf("output length %d exceeds cap (1000) by too much", len(out))
	}
	if !strings.Contains(out, "omitted") {
		t.Errorf("expected omitted notice, got: %q", out)
	}
}

func TestFormat_HardTruncation(t *testing.T) {
	pod := PodSummary{
		Namespace: "ns",
		Name:      "big-pod",
		Phase:     "Running",
		Reason:    "CrashLoopBackOff",
		Age:       "1h",
		LogTails:  []LogTail{{Container: "app", Lines: strings.Repeat("x", 5000)}},
	}
	s := Snapshot{TotalPods: 1, UnhealthyPods: []PodSummary{pod}}
	out := Format(s, 200)
	if len(out) > 250 {
		t.Errorf("output length %d far exceeds 200-byte cap", len(out))
	}
}

func TestFormat_EventsGroupedByPod(t *testing.T) {
	s := Snapshot{
		Namespace: "default",
		TotalPods: 1,
		UnhealthyPods: []PodSummary{
			{Namespace: "default", Name: "crash-1", Phase: "Running", Reason: "CrashLoopBackOff"},
		},
		Events: []EventSummary{
			{PodName: "crash-1", Reason: "BackOff", Message: "back-off restarting", Count: 5, LastSeen: "3m ago"},
			{PodName: "other-pod", Reason: "BackOff", Message: "should not appear", Count: 1, LastSeen: "1m ago"},
		},
	}
	out := Format(s, 200*1024)
	if !strings.Contains(out, "back-off restarting") {
		t.Errorf("event for crash-1 missing: %q", out)
	}
	if strings.Contains(out, "should not appear") {
		t.Errorf("event for unrelated pod leaked into output: %q", out)
	}
}

func TestFormat_PriorityOrder(t *testing.T) {
	s := Snapshot{
		TotalPods: 2,
		UnhealthyPods: []PodSummary{
			{Name: "crash-pod", Reason: "CrashLoopBackOff", Score: 100, Namespace: "default", Phase: "Running"},
			{Name: "slow-pod", Reason: "NotReady", Score: 40, Namespace: "default", Phase: "Running"},
		},
	}
	out := Format(s, 200*1024)
	crashIdx := strings.Index(out, "crash-pod")
	slowIdx := strings.Index(out, "slow-pod")
	if crashIdx == -1 || slowIdx == -1 {
		t.Fatalf("both pods should appear in output")
	}
	if crashIdx > slowIdx {
		t.Errorf("higher-scored pod should appear before lower-scored pod")
	}
}

func TestHumanAge(t *testing.T) {
	cases := []struct {
		d    time.Duration
		want string
	}{
		{30 * time.Second, "30s"},
		{90 * time.Second, "1m"},
		{3600 * time.Second, "1h"},
		{25 * time.Hour, "1d"},
	}
	for _, tc := range cases {
		got := humanAge(tc.d)
		if got != tc.want {
			t.Errorf("humanAge(%v) = %q, want %q", tc.d, got, tc.want)
		}
	}
}
