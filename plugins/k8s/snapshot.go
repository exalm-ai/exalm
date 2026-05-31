// Package k8s implements `exalm k8s analyze`.
//
// It connects to the user's cluster via kubeconfig, collects unhealthy
// pod state, warning events and log tails, redacts all data, and asks
// the configured LLM for a prioritised diagnostic report.
package k8s

import "time"

// Snapshot is the cluster state collected before LLM analysis.
// Plain Go types only — no k8s API imports, keeping the formatter
// and most tests free of client-go.
type Snapshot struct {
	Namespace     string // empty = cluster-wide
	TotalPods     int
	UnhealthyPods []PodSummary
	Events        []EventSummary
	NodeIssues    []NodeIssue
	Deployments   []DeploymentSummary
	HPAs          []HPASummary
	Quotas        []QuotaSummary
	PVCIssues     []PVCIssue
	ServiceIssues []ServiceIssue

	// Phase 1 extended analyzers
	IngressIssues       []IngressHealth
	ResourceGaps        []ResourceGap
	UncoveredNamespaces []string // namespaces with pods but no NetworkPolicy
	RBACRisks           []RBACRisk
	ReplicaSetIssues    []ReplicaSetIssue
	StatefulSetIssues   []StatefulSetIssue
	FailedJobs          []JobIssue
	CronJobIssues       []CronJobIssue

	// Phase 2 extended analyzers
	SelectorMismatches   []SelectorMismatch    // services whose selector matches no running pods
	CrossNamespaceIssues []CrossNamespaceIssue // cross-namespace connectivity problems

	// Phase 3 IaC change detection
	IaCChanges []IaCChange // ArgoCD Application and Helm release change events
}

// IngressHealth records an Ingress with broken references.
type IngressHealth struct {
	Namespace        string
	Name             string
	MissingClass     bool
	MissingBackends  []string // service names not found
	MissingTLSSecret []string // secret names not found
}

// ResourceGap records a container with missing CPU or memory limits.
type ResourceGap struct {
	Namespace      string
	PodName        string
	ContainerName  string
	DeploymentName string // owning Deployment, if resolved; used for add-limits remediation
	MissingCPU     bool
	MissingMemory  bool
	BestEffort     bool // true when both requests AND limits are absent
}

// RBACRisk records a ClusterRoleBinding or RoleBinding with excessive permissions.
type RBACRisk struct {
	Kind      string // "ClusterRoleBinding" or "RoleBinding"
	Name      string
	Namespace string // empty for ClusterRoleBinding
	Reason    string // "cluster-admin binding" | "wildcard verbs on secrets"
	Subject   string // "serviceaccount:ns/name"
}

// ReplicaSetIssue records a ReplicaSet where ready < desired.
type ReplicaSetIssue struct {
	Namespace string
	Name      string
	Desired   int32
	Ready     int32
	Orphaned  bool // not owned by a Deployment
}

// StatefulSetIssue records a StatefulSet with a readiness or rollout problem.
type StatefulSetIssue struct {
	Namespace    string
	Name         string
	Desired      int32
	Ready        int32
	StuckRollout bool // currentRevision != updateRevision
}

// JobIssue records a permanently-failed batch Job.
type JobIssue struct {
	Namespace string
	Name      string
	Failed    int32
	Reason    string
}

// CronJobIssue records a CronJob with a scheduling or suspension problem.
type CronJobIssue struct {
	Namespace    string
	Name         string
	Suspended    bool
	LastSchedule string // human-readable age or "never"
}

// PodSummary describes one unhealthy pod.
type PodSummary struct {
	Namespace    string
	Name         string
	Phase        string
	Reason       string
	Score        int
	RestartCount int32
	Age          string
	HasNoLimits  bool // true if any container has no CPU or memory limit
	LogTails     []LogTail
	LogAnomalies []LogAnomaly
}

// LogTail holds the tail of one container's log stream.
type LogTail struct {
	Container string
	Lines     string
	Error     string // non-empty if the fetch failed
}

// LogAnomaly is a pattern match found inside a container's logs.
type LogAnomaly struct {
	Category string // "http-5xx", "latency", "db-error", "dependency"
	Count    int
	Sample   string // first matching line (truncated)
}

// EventSummary is one Kubernetes Warning event linked to a pod.
type EventSummary struct {
	Namespace string
	PodName   string
	Reason    string
	Message   string
	Count     int32
	LastSeen  string
	Density   float64 // events per second (Count / window); >1 = spike
}

// NodeIssue records a node with at least one unhealthy condition.
type NodeIssue struct {
	Name       string
	Conditions []string
}

// DeploymentSummary describes a Deployment that is not fully available.
type DeploymentSummary struct {
	Namespace   string
	Name        string
	Desired     int32
	Available   int32
	Unavailable int32
	StallReason string // e.g. "ProgressDeadlineExceeded"
}

// HPASummary describes an HPA that cannot scale or has a condition issue.
type HPASummary struct {
	Namespace       string
	Name            string
	TargetKind      string
	TargetName      string
	CurrentReplicas int32
	DesiredReplicas int32
	MinReplicas     int32
	MaxReplicas     int32
	Issue           string // human-readable condition reason
}

// QuotaSummary is one resource dimension of a ResourceQuota.
type QuotaSummary struct {
	Namespace string
	Resource  string // "cpu", "memory", "pods"
	Used      string
	Hard      string
	UsedPct   int
}

// PVCIssue records a PersistentVolumeClaim that is not yet bound.
type PVCIssue struct {
	Namespace    string
	Name         string
	Phase        string // "Pending", "Lost"
	StorageClass string
	Reason       string
}

// ServiceIssue records a Service with no backing endpoints.
type ServiceIssue struct {
	Namespace string
	Name      string
	Issue     string // e.g. "no ready endpoints — pod selector may not match any running pod"
}

// SelectorMismatch records a Service whose selector doesn't match any running pod.
// When a deployment exists in the same namespace with pods that differ by only
// one or two labels, we generate a suggested JSON merge patch to fix the service.
type SelectorMismatch struct {
	Namespace      string
	ServiceName    string
	Selector       map[string]string // service's current (broken) selector
	SuggestedPatch string            // JSON merge patch to apply to the service
	DeploymentName string            // likely owning deployment name (if found)
	MatchingLabel  string            // human-readable: "app=api-gateway" (what pods actually have)
}

// CrossNamespaceIssue records a pod in one namespace that appears unable to
// reach a service in another namespace, typically because NetworkPolicy blocks
// the traffic. Detected by log pattern matching + policy inspection.
type CrossNamespaceIssue struct {
	SourceNamespace string
	TargetNamespace string
	ServiceName     string // target service name
	Protocol        string // "TCP" | "UDP"
	Port            int32
	Reason          string // "no egress NetworkPolicy allows traffic to target namespace"
}

// IaCChange records an infrastructure-as-code change event detected in the cluster.
type IaCChange struct {
	Source    string // "argocd" | "helm"
	Name      string // Application or release name
	Namespace string
	SyncedAt  time.Time // last sync/deploy time
	Version   string    // ArgoCD revision or Helm chart version
	Status    string    // "Synced" | "OutOfSync" | "Degraded" | "deployed" | "failed"
	Message   string    // status message or description
}
