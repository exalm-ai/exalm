package k8s

import (
	"time"

	corev1 "k8s.io/api/core/v1"
)

const (
	pendingThreshold  = 5 * time.Minute
	notReadyThreshold = 5 * time.Minute
)

// healthResult is non-zero when a pod is unhealthy.
type healthResult struct {
	reason string
	score  int
}

// waitingScores maps container waiting reasons to base severity scores.
// Higher score = shown first in the LLM payload.
var waitingScores = map[string]int{
	// Init container failures
	"Init:Error":            95,
	"Init:CrashLoopBackOff": 95,
	"PodInitializing":       50, // still initialising — only flag if too long
	// Main container failures
	"CrashLoopBackOff":           100,
	"OOMKilled":                  90,
	"ImagePullBackOff":           80,
	"ErrImagePull":               80,
	"CreateContainerConfigError": 75,
	"CreateContainerError":       70,
	"RunContainerError":          65,
}

// checkHealth returns a populated healthResult if the pod is unhealthy,
// or a zero value if the pod looks healthy.
func checkHealth(pod corev1.Pod, now time.Time) healthResult {
	if pod.Status.Phase == corev1.PodFailed {
		// Evicted pods have a distinct reason and actionable fix (node pressure).
		if pod.Status.Reason == "Evicted" {
			return healthResult{reason: "Evicted", score: 80}
		}
		return healthResult{reason: "Failed", score: 85}
	}

	// Init containers are checked first: a stuck init container blocks
	// the whole pod regardless of main container state.
	for _, cs := range pod.Status.InitContainerStatuses {
		if r := checkContainerStatus(cs); r.reason != "" {
			return r
		}
	}

	// Main containers.
	for _, cs := range pod.Status.ContainerStatuses {
		if r := checkContainerStatus(cs); r.reason != "" {
			return r
		}
	}

	age := now.Sub(pod.CreationTimestamp.Time)
	if pod.Status.Phase == corev1.PodPending && age > pendingThreshold {
		return healthResult{reason: "Pending", score: 60}
	}

	if pod.Status.Phase == corev1.PodRunning && age > notReadyThreshold {
		for _, cs := range pod.Status.ContainerStatuses {
			if !cs.Ready {
				return healthResult{reason: "NotReady", score: 40}
			}
		}
	}

	return healthResult{}
}

// checkContainerStatus evaluates one container status (init or main).
func checkContainerStatus(cs corev1.ContainerStatus) healthResult {
	if cs.State.Waiting != nil {
		reason := cs.State.Waiting.Reason
		if score, ok := waitingScores[reason]; ok {
			bonus := int(cs.RestartCount)
			if bonus > 30 {
				bonus = 30
			}
			return healthResult{reason: reason, score: score + bonus}
		}
	}
	if t := cs.LastTerminationState.Terminated; t != nil && t.Reason == "OOMKilled" {
		bonus := int(cs.RestartCount)
		if bonus > 30 {
			bonus = 30
		}
		return healthResult{reason: "OOMKilled", score: 90 + bonus}
	}
	return healthResult{}
}
