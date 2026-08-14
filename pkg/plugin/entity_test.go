package plugin

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestEntity_PathAndString(t *testing.T) {
	cases := []struct {
		name     string
		e        Entity
		wantPath string
		wantStr  string
	}{
		{"namespaced with kind", Entity{Kind: "Pod", Namespace: "prod", Name: "api-0"}, "prod/api-0", "Pod prod/api-0"},
		{"no kind", Entity{Namespace: "prod", Name: "api-0"}, "prod/api-0", "prod/api-0"},
		{"cluster-scoped", Entity{Kind: "Node", Name: "worker-3"}, "worker-3", "Node worker-3"},
		{"non-k8s host", Entity{Kind: "Host", Cluster: "db-01", Name: "db-01"}, "db-01", "Host db-01"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.e.Path(); got != tc.wantPath {
				t.Errorf("Path() = %q, want %q", got, tc.wantPath)
			}
			if got := tc.e.String(); got != tc.wantStr {
				t.Errorf("String() = %q, want %q", got, tc.wantStr)
			}
		})
	}
}

func TestEntity_IsZero(t *testing.T) {
	if !(Entity{}).IsZero() {
		t.Error("empty entity should be zero")
	}
	if !(Entity{Kind: "Pod", Namespace: "prod"}).IsZero() {
		t.Error("kind+namespace without a name or uid carries no identity")
	}
	if (Entity{Name: "api-0"}).IsZero() {
		t.Error("a named entity is not zero")
	}
	if (Entity{UID: "abc-123"}).IsZero() {
		t.Error("a uid-only entity is not zero")
	}
}

func TestEntity_IDStableAndDistinct(t *testing.T) {
	a := Entity{Kind: "Pod", Cluster: "prod-cluster", Namespace: "prod", Name: "api-0"}
	aCopy := Entity{Kind: "Pod", Cluster: "prod-cluster", Namespace: "prod", Name: "api-0"}
	if a.ID() != aCopy.ID() {
		t.Error("identical entities must hash to the same ID across collections")
	}

	// Every identity field must participate in the hash.
	for _, other := range []Entity{
		{Kind: "Deployment", Cluster: "prod-cluster", Namespace: "prod", Name: "api-0"},
		{Kind: "Pod", Cluster: "staging-cluster", Namespace: "prod", Name: "api-0"},
		{Kind: "Pod", Cluster: "prod-cluster", Namespace: "staging", Name: "api-0"},
		{Kind: "Pod", Cluster: "prod-cluster", Namespace: "prod", Name: "api-1"},
	} {
		if a.ID() == other.ID() {
			t.Errorf("ID collision between %+v and %+v", a, other)
		}
	}

	// Labels are metadata, not identity.
	labelled := a
	labelled.Labels = map[string]string{"app": "api"}
	if labelled.ID() != a.ID() {
		t.Error("labels must not change entity identity")
	}
}

func TestEntity_UIDWinsOverNameForIdentity(t *testing.T) {
	// A renamed resource keeps its identity when the domain supplies a UID.
	before := Entity{Kind: "Pod", Namespace: "prod", Name: "api-0", UID: "uid-1"}
	after := Entity{Kind: "Pod", Namespace: "prod", Name: "api-renamed", UID: "uid-1"}
	if before.ID() != after.ID() {
		t.Error("entities sharing a UID must share an ID")
	}
	different := Entity{Kind: "Pod", Namespace: "prod", Name: "api-0", UID: "uid-2"}
	if before.ID() == different.ID() {
		t.Error("different UIDs must not collide")
	}
}

func TestEntity_Matches(t *testing.T) {
	pod := Entity{Kind: "Pod", Cluster: "c1", Namespace: "prod", Name: "api-0"}

	// An unspecified field on the filter side means "any".
	if !pod.Matches(Entity{Namespace: "prod"}) {
		t.Error("namespace-only filter should match")
	}
	if !(Entity{Namespace: "prod"}).Matches(pod) {
		t.Error("Matches should be symmetric for unspecified fields")
	}
	if pod.Matches(Entity{Namespace: "staging"}) {
		t.Error("a different namespace must not match")
	}
	if pod.Matches(Entity{Kind: "Deployment"}) {
		t.Error("a different kind must not match")
	}
	// UID is decisive when both sides have one.
	a := Entity{Kind: "Pod", Name: "x", UID: "u1"}
	b := Entity{Kind: "Service", Name: "y", UID: "u1"}
	if !a.Matches(b) {
		t.Error("matching UIDs should match regardless of other fields")
	}
}

func TestParseEntityFromTitle(t *testing.T) {
	cases := []struct {
		title string
		want  string // Path(), or "" when nothing should be parsed
	}{
		{"CrashLoopBackOff: prod/api-gateway-7c9b", "prod/api-gateway-7c9b"},
		{"Log db-error in exalm-prod/api-gateway", "exalm-prod/api-gateway"},
		{"Selector mismatch: prod/order-gateway", "prod/order-gateway"},
		{"Egress blocked: prod/payment-api", "prod/payment-api"},
		{"PVC near capacity: analytics/data-pvc (94%)", "analytics/data-pvc"},
		// Image paths must never be mistaken for a resource.
		{"ImagePullBackOff: gcr.io/google-containers/pause", ""},
		// Nothing resource-shaped to find.
		{"Node worker-3 unreachable", ""},
		{"", ""},
	}
	for _, tc := range cases {
		t.Run(tc.title, func(t *testing.T) {
			got := ParseEntityFromTitle(tc.title, "Pod")
			if tc.want == "" {
				if !got.IsZero() {
					t.Errorf("expected no entity, got %+v", got)
				}
				return
			}
			if got.Path() != tc.want {
				t.Errorf("Path() = %q, want %q", got.Path(), tc.want)
			}
			if got.Kind != "Pod" {
				t.Errorf("Kind = %q, want the kind passed in", got.Kind)
			}
		})
	}
}

func TestFindingID_EntityDisambiguatesAndStaysBackCompatible(t *testing.T) {
	base := Finding{Category: "Pods", Title: "CrashLoopBackOff", Source: "k8s/c1"}

	// Findings with no entity keep their historical ID, so finding_id values
	// already persisted on conversations continue to resolve.
	withNilEntity := base
	withZeroEntity := base
	withZeroEntity.Entity = &Entity{}
	if base.ID() != withNilEntity.ID() || base.ID() != withZeroEntity.ID() {
		t.Error("a nil or zero entity must not change the finding ID")
	}

	// Two pods hitting the same symptom under the same title used to collide.
	a := base
	a.Entity = &Entity{Kind: "Pod", Namespace: "prod", Name: "api-0"}
	b := base
	b.Entity = &Entity{Kind: "Pod", Namespace: "prod", Name: "api-1"}
	if a.ID() == b.ID() {
		t.Error("findings on different entities must have different IDs")
	}
	if a.ID() == base.ID() {
		t.Error("setting an entity should specialise the ID")
	}

	// Still stable across re-collections.
	aAgain := base
	aAgain.Entity = &Entity{Kind: "Pod", Namespace: "prod", Name: "api-0"}
	if a.ID() != aAgain.ID() {
		t.Error("the same finding must hash identically across collections")
	}
}

func TestFinding_NewFieldsOmittedFromJSONWhenUnset(t *testing.T) {
	// Adding Entity/FirstSeen/LastSeen/Count must not change the wire format
	// for producers that have not populated them.
	raw, err := json.Marshal(Finding{Severity: SeverityHigh, Title: "x", Detail: "y"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, key := range []string{`"entity"`, `"count"`, `"first_seen"`, `"last_seen"`} {
		if strings.Contains(string(raw), key) {
			t.Errorf("unset field %s should be omitted, got %s", key, raw)
		}
	}
	// The specific trap: a plain time.Time cannot be omitted by encoding/json,
	// so an unknown observation time would serialise as the year 1 and any
	// consumer plotting it would place the finding in 0001. The timestamps are
	// pointers precisely to make "unknown" absent rather than ancient.
	if strings.Contains(string(raw), "0001-01-01") {
		t.Errorf("unknown timestamps must be absent, not the zero instant: %s", raw)
	}
}

func TestFinding_TimestampsRoundTripWhenSet(t *testing.T) {
	at := time.Date(2026, 8, 12, 9, 30, 0, 0, time.UTC)
	raw, err := json.Marshal(Finding{Title: "x", FirstSeen: &at, LastSeen: &at, Count: 3})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var back Finding
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back.FirstSeen == nil || !back.FirstSeen.Equal(at) {
		t.Errorf("FirstSeen did not round-trip: %v", back.FirstSeen)
	}
	if back.LastSeen == nil || !back.LastSeen.Equal(at) {
		t.Errorf("LastSeen did not round-trip: %v", back.LastSeen)
	}
	if back.Count != 3 {
		t.Errorf("Count = %d, want 3", back.Count)
	}
}
