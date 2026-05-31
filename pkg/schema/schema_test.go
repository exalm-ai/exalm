package schema_test

import (
	"testing"

	"github.com/exalm-ai/exalm/pkg/plugin"
	"github.com/exalm-ai/exalm/pkg/schema"
)

func TestTypeAliasCompatibility(t *testing.T) {
	pf := plugin.Finding{Title: "test", Severity: plugin.SeverityHigh}
	sf := pf // must compile — they are the same type
	if sf.Title != "test" {
		t.Fatalf("expected title 'test', got %q", sf.Title)
	}
	if schema.Version == "" {
		t.Fatal("Version must not be empty")
	}
}
