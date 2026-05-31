package k8s

import (
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func makePod(phase corev1.PodPhase, cs []corev1.ContainerStatus, age time.Duration) corev1.Pod {
	return corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "test-pod",
			Namespace:         "default",
			CreationTimestamp: metav1.NewTime(time.Now().Add(-age)),
		},
		Status: corev1.PodStatus{
			Phase:             phase,
			ContainerStatuses: cs,
		},
	}
}

func waiting(reason string) corev1.ContainerState {
	return corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: reason}}
}

func TestCheckHealth(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name          string
		pod           corev1.Pod
		wantUnhealthy bool
		wantReason    string
		wantScoreMin  int
	}{
		{
			name: "healthy running pod",
			pod: makePod(corev1.PodRunning, []corev1.ContainerStatus{
				{Name: "app", Ready: true},
			}, 10*time.Minute),
			wantUnhealthy: false,
		},
		{
			name:          "failed phase",
			pod:           makePod(corev1.PodFailed, nil, time.Minute),
			wantUnhealthy: true,
			wantReason:    "Failed",
			wantScoreMin:  80,
		},
		{
			name: "CrashLoopBackOff",
			pod: makePod(corev1.PodRunning, []corev1.ContainerStatus{
				{Name: "app", Ready: false, State: waiting("CrashLoopBackOff")},
			}, time.Minute),
			wantUnhealthy: true,
			wantReason:    "CrashLoopBackOff",
			wantScoreMin:  100,
		},
		{
			name: "ImagePullBackOff",
			pod: makePod(corev1.PodRunning, []corev1.ContainerStatus{
				{Name: "app", Ready: false, State: waiting("ImagePullBackOff")},
			}, time.Minute),
			wantUnhealthy: true,
			wantReason:    "ImagePullBackOff",
			wantScoreMin:  80,
		},
		{
			name: "OOMKilled in last termination",
			pod: makePod(corev1.PodRunning, []corev1.ContainerStatus{
				{
					Name:         "app",
					Ready:        false,
					RestartCount: 2,
					LastTerminationState: corev1.ContainerState{
						Terminated: &corev1.ContainerStateTerminated{Reason: "OOMKilled"},
					},
				},
			}, time.Minute),
			wantUnhealthy: true,
			wantReason:    "OOMKilled",
			wantScoreMin:  90,
		},
		{
			name:          "pending too long",
			pod:           makePod(corev1.PodPending, nil, 10*time.Minute),
			wantUnhealthy: true,
			wantReason:    "Pending",
			wantScoreMin:  60,
		},
		{
			name:          "pending not yet at threshold",
			pod:           makePod(corev1.PodPending, nil, 2*time.Minute),
			wantUnhealthy: false,
		},
		{
			name: "running but not ready too long",
			pod: makePod(corev1.PodRunning, []corev1.ContainerStatus{
				{Name: "app", Ready: false},
			}, 10*time.Minute),
			wantUnhealthy: true,
			wantReason:    "NotReady",
			wantScoreMin:  40,
		},
		{
			name: "running not ready but recent — not yet unhealthy",
			pod: makePod(corev1.PodRunning, []corev1.ContainerStatus{
				{Name: "app", Ready: false},
			}, 2*time.Minute),
			wantUnhealthy: false,
		},
		{
			name: "restart bonus capped at 30",
			pod: makePod(corev1.PodRunning, []corev1.ContainerStatus{
				{Name: "app", Ready: false, RestartCount: 500, State: waiting("CrashLoopBackOff")},
			}, time.Minute),
			wantUnhealthy: true,
			wantReason:    "CrashLoopBackOff",
			wantScoreMin:  130, // 100 + 30 cap
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := checkHealth(tc.pod, now)
			if tc.wantUnhealthy && r.reason == "" {
				t.Errorf("expected unhealthy pod, got healthy")
			}
			if !tc.wantUnhealthy && r.reason != "" {
				t.Errorf("expected healthy pod, got reason=%q score=%d", r.reason, r.score)
			}
			if tc.wantReason != "" && r.reason != tc.wantReason {
				t.Errorf("reason = %q, want %q", r.reason, tc.wantReason)
			}
			if tc.wantScoreMin > 0 && r.score < tc.wantScoreMin {
				t.Errorf("score = %d, want >= %d", r.score, tc.wantScoreMin)
			}
		})
	}
}
