package plugin

import (
	"fmt"
	"hash/fnv"
	"strings"
)

// Entity is the canonical identity of something Exalm observes: a Kubernetes
// pod or deployment, a Linux host, an IIS site, a systemd unit, an AWS
// principal. It is the join key that lets a finding, the evidence behind it,
// the changes that preceded it, and the conversation about it all refer to the
// same thing.
//
// Before this type existed, identity was expressed six different ways —
// investigate.Target{Scope,Name}, ChangeRef{Kind,Namespace,Name}, a dozen
// per-issue structs each re-declaring Namespace/Name, and free text inside
// Finding.Title that three separate regex parsers pulled apart again. Entity
// replaces the shared parts of that without forcing any single domain to
// change how it collects.
//
// Only Name is required. Namespace is empty for cluster-scoped and non-k8s
// resources; Cluster doubles as the host or account scope for non-k8s domains
// (a syslog host, an AWS account). Every field is optional in JSON so adding
// Entity to an existing payload does not change the wire format for producers
// that have not populated it yet.
type Entity struct {
	// Kind is the resource type: "Pod", "Deployment", "Node", "Service",
	// "PVC", "Host", "Unit", "Site", "Principal". Free-form by design —
	// each domain names its own resources.
	Kind string `json:"kind,omitempty"`
	// Cluster scopes the entity: a Kubernetes cluster, a syslog host, an AWS
	// account. Distinguishes same-named resources across environments.
	Cluster string `json:"cluster,omitempty"`
	// Namespace is the k8s namespace, or empty for cluster-scoped and
	// non-k8s resources.
	Namespace string `json:"namespace,omitempty"`
	// Name is the resource name. The only required field.
	Name string `json:"name"`
	// UID is the domain's own stable identifier when it has one (a k8s
	// object UID). Preferred over Kind/Namespace/Name for identity when set.
	UID string `json:"uid,omitempty"`
	// Labels carries domain metadata (k8s labels, log facility). Never
	// include secret values — entities are persisted and rendered.
	Labels map[string]string `json:"labels,omitempty"`
}

// IsZero reports whether the entity carries no identity at all.
func (e Entity) IsZero() bool { return e.Name == "" && e.UID == "" }

// Path returns the "namespace/name" form used throughout Exalm — the same
// shape as investigate.Target.String() and Conversation.Focus, so an Entity
// can be handed to anything that already speaks that convention. Returns just
// the name when there is no namespace.
func (e Entity) Path() string {
	if e.Namespace == "" {
		return e.Name
	}
	return e.Namespace + "/" + e.Name
}

// String renders the entity for display: "Pod prod/api-0", or "prod/api-0"
// when the kind is unknown.
func (e Entity) String() string {
	if e.Kind == "" {
		return e.Path()
	}
	return e.Kind + " " + e.Path()
}

// ID returns a stable identifier for this entity. The same resource produces
// the same ID across collections, so findings, evidence, and changes can be
// grouped by entity without string matching. UID wins when present because it
// is the domain's own identity and survives renames.
func (e Entity) ID() string {
	h := fnv.New32a()
	if e.UID != "" {
		_, _ = h.Write([]byte("uid\x1f" + e.UID))
	} else {
		_, _ = h.Write([]byte(e.Kind + "\x1f" + e.Cluster + "\x1f" + e.Namespace + "\x1f" + e.Name))
	}
	return fmt.Sprintf("e%08x", h.Sum32())
}

// Matches reports whether other refers to the same resource. A zero field on
// either side is treated as "unspecified" and does not block the match, so a
// filter like Entity{Namespace: "prod"} selects everything in that namespace.
func (e Entity) Matches(other Entity) bool {
	if e.UID != "" && other.UID != "" {
		return e.UID == other.UID
	}
	eq := func(a, b string) bool { return a == "" || b == "" || a == b }
	return eq(e.Kind, other.Kind) && eq(e.Cluster, other.Cluster) &&
		eq(e.Namespace, other.Namespace) && eq(e.Name, other.Name)
}

// ParseEntityFromTitle recovers "namespace/name" from a finding title such as
// "CrashLoopBackOff: prod/api-gateway-7c9b" or "Log db-error in prod/api".
// It returns a zero Entity when nothing matches.
//
// This is the single implementation of a heuristic that previously existed as
// near-identical copies in internal/evidence and plugins/k8s. It stays
// deliberately conservative: a namespace containing a dot is rejected so image
// paths like gcr.io/google-containers are never mistaken for a resource.
//
// Prefer setting Finding.Entity at the point of collection, where the real
// identity is known. This exists for findings whose producer has not been
// migrated yet, and for titles that arrive from outside.
func ParseEntityFromTitle(title, kind string) Entity {
	for _, sep := range []string{": ", " in ", "blocked: "} {
		i := strings.Index(title, sep)
		if i < 0 {
			continue
		}
		rest := title[i+len(sep):]
		slash := strings.Index(rest, "/")
		if slash <= 0 {
			continue
		}
		ns := rest[:slash]
		name := firstToken(strings.TrimRight(rest[slash+1:], " .,;"))
		if name == "" || strings.Contains(ns, ".") || !isDNSIdent(ns) {
			continue
		}
		return Entity{Kind: kind, Namespace: ns, Name: name}
	}
	return Entity{}
}

// isDNSIdent reports whether s looks like a DNS-style resource identifier
// (letters, digits, hyphens; at least two characters).
func isDNSIdent(s string) bool {
	if len(s) < 2 {
		return false
	}
	for _, r := range s {
		if r != '-' && (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') {
			return false
		}
	}
	return true
}

// firstToken returns the first whitespace-delimited token of s.
func firstToken(s string) string {
	if i := strings.IndexAny(s, " \t\n"); i >= 0 {
		return s[:i]
	}
	return s
}
