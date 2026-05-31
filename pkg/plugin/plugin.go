// Package plugin defines the public contract every Exalm plugin implements.
//
// Plugins are added under the plugins/ directory and registered in
// cmd/exalm/main.go. Each plugin exposes one or more Subcommands, e.g.
// `exalm logs summarize` or `exalm k8s analyze`.
//
// # SAFETY MODEL
//
// Plugins MUST declare via Mutates() whether they can change state in the
// user's environment. The CLI refuses to run any mutating plugin without
// the --apply flag and an explicit confirmation prompt. For Phase 1 every
// plugin is read-only.
//
// # PRIVACY MODEL
//
// Plugins MUST call Redactor.Redact() on any data they extract from the
// user's environment BEFORE passing it to the LLM. There are no exceptions.
// See internal/redact for the implementation.
package plugin

import (
	"context"
	"io"
	"time"
)

// Plugin is the contract every Exalm plugin implements.
type Plugin interface {
	// Name is the command-line name of the plugin (e.g. "logs", "k8s").
	// Invoked as: `exalm <name> <subcommand> [args...]`.
	Name() string

	// Description is a short human-readable description shown in --help.
	Description() string

	// Mutates reports whether any of this plugin's subcommands can modify
	// state in the user's environment. If true, the CLI gates execution
	// behind --apply + a confirmation prompt.
	Mutates() bool

	// Subcommands returns the actions this plugin supports.
	Subcommands() []Subcommand
}

// Subcommand is a specific action a plugin can perform.
type Subcommand struct {
	Name        string
	Description string
	// Mutates reports whether this specific subcommand can modify state in the
	// user's environment. The CLI gates execution behind --apply when true.
	// Plugins that expose a mix of read-only and mutating subcommands should set
	// this per subcommand rather than relying solely on Plugin.Mutates().
	Mutates bool
	// Run executes the action and returns a structured Report.
	Run func(ctx context.Context, args RunArgs) (Report, error)
}

// RunArgs is the runtime context passed to every Subcommand.Run invocation.
// All I/O streams are injected so plugins are easy to test.
type RunArgs struct {
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
	// Flags holds single-valued flags (the common case).
	Flags map[string]string
	// FlagsMulti holds repeatable flags such as --file ./a.log --file ./b.log
	// or --file './logs/*.log'. The single-valued Flags map continues to mirror
	// the last value of any repeatable flag for backward compatibility.
	FlagsMulti map[string][]string
	Args       []string
	LLM        LLMClient
	Redactor   Redactor
}

// Report is the structured output a plugin returns. The renderer in
// internal/output formats it as Markdown or JSON depending on flags.
type Report struct {
	Title    string    `json:"title"`
	Summary  string    `json:"summary"`
	Findings []Finding `json:"findings,omitempty"`
	// Raw holds the unstructured LLM output. Plugins that don't yet parse
	// findings can put the full response here.
	Raw string `json:"raw,omitempty"`
}

// Finding is one diagnostic item inside a Report.
type Finding struct {
	Severity    Severity           `json:"severity"`
	Category    string             `json:"category,omitempty"` // e.g. "Pods", "Security", "Networking", "Resources"
	Title       string             `json:"title"`
	Detail      string             `json:"detail"`
	Suggestion  string             `json:"suggestion,omitempty"`
	Remediation *RemediationAction `json:"remediation,omitempty"`
	// LikelyCause is set by the change-correlation engine when a cluster
	// mutation (deploy, RBAC change, config edit) was observed in the 30
	// minutes preceding this finding's first observation. nil otherwise.
	//
	// Strength: komodor — "Change-correlation RCA engine: automatically ties
	// failures to the recent change most likely to have caused them."
	LikelyCause *ChangeRef `json:"likely_cause,omitempty"`
	// Evidence is the verifiable chain of log lines, metric values, events,
	// and changes supporting this finding. Populated by internal/evidence.
	//
	// Strength: openobserve — "AI SRE Agent shows complete evidence chain ...
	// verifiable, not a black box." We expose it as first-class data in
	// every finding, not just in agent text output.
	Evidence []EvidenceItem `json:"evidence,omitempty"`
	// Source identifies which plugin or data source produced this finding.
	// Examples: "k8s/prod-cluster", "logs/app.log", "aws_cost/us-east-1".
	// Set by the plugin; used by the dashboard to group multi-source findings.
	Source string `json:"source,omitempty"`
}

// ChangeRef is a lightweight pointer into the changestore. Stays decoupled
// from the changestore package so plugin/ stays import-free of internal/.
type ChangeRef struct {
	ID        string `json:"id"`
	Kind      string `json:"kind"`
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name"`
	Actor     string `json:"actor,omitempty"`
	// AgoSeconds is "how many seconds before now the change happened" at the
	// time the finding was correlated. Easier for UIs than absolute time
	// because the UI doesn't need to pick a "now" anchor.
	AgoSeconds int64  `json:"ago_seconds"`
	DiffURL    string `json:"diff_url,omitempty"`
}

// EvidenceItem is one verifiable fact backing a finding.
type EvidenceItem struct {
	// Kind is "log", "metric", "event", or "change".
	Kind string `json:"kind"`
	// Source identifies the origin (pod name, metric query, event reason,
	// change ID).
	Source string `json:"source"`
	// Excerpt is a short verbatim quote (already redacted).
	Excerpt string `json:"excerpt,omitempty"`
	// At is when the evidence was captured / observed.
	At time.Time `json:"at,omitempty"`
	// Anchor is a deep link or kubectl command the user can run to retrieve
	// the full context. Example: "kubectl logs -n ns pod --tail 200".
	Anchor string `json:"anchor,omitempty"`
}

// RemediationAction describes how a finding can be automatically remediated.
//
// For Kubernetes findings set Kind and the relevant k8s fields; KubectlCmd
// is shown in the UI as the equivalent kubectl one-liner.
//
// For Windows/Linux shell findings leave the k8s fields empty and set:
//   - Shell: "powershell" or "bash"
//   - KubectlCmd: the actual shell command to display and copy
//   - Warning: optional safety note shown in the confirmation modal
type RemediationAction struct {
	Kind        string `json:"kind"`              // "rollout-restart" | "resume-cronjob" | "delete-pod" | "shell"
	Namespace   string `json:"namespace"`         // k8s namespace (k8s only)
	Resource    string `json:"resource"`          // k8s resource kind (k8s only)
	Name        string `json:"name"`              // k8s resource name (k8s only)
	PatchJSON   string `json:"patch_json"`        // JSON merge patch payload (k8s only)
	KubectlCmd  string `json:"kubectl_cmd"`       // command to display/copy (kubectl or shell one-liner)
	Description string `json:"description"`       // human-readable summary shown in the modal
	Shell       string `json:"shell,omitempty"`   // "powershell" | "bash" | "" (kubectl)
	Warning     string `json:"warning,omitempty"` // safety note shown before applying
}

// Severity ranks findings from informational to critical.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// LLMClient is the abstraction over LLM providers. Implementations live
// in internal/llm (Claude, OpenAI, Ollama, ...).
type LLMClient interface {
	// Name identifies the provider, e.g. "claude", "openai", "ollama".
	Name() string
	// Complete sends a single completion request and returns the response.
	Complete(ctx context.Context, req CompleteRequest) (CompleteResponse, error)
}

// CompleteRequest is a provider-agnostic completion request.
type CompleteRequest struct {
	System      string
	Messages    []Message
	MaxTokens   int
	Temperature float64
}

// Message is one turn in a conversation.
type Message struct {
	Role    string // "user" or "assistant"
	Content string
}

// CompleteResponse is the provider-agnostic response.
type CompleteResponse struct {
	Content      string
	InputTokens  int
	OutputTokens int
}

// Redactor scrubs sensitive content before it leaves the process.
//
// Plugins MUST pass any data through Redact() before sending it to the LLM.
// Implementations live in internal/redact.
type Redactor interface {
	Redact(input string) string
}
