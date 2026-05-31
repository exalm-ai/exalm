// Package gitprovider defines the interface for creating fix PRs across git hosting providers.
//
// SRE use case: Exalm generates a structured fix document from k8s findings and opens
// a PR so the team can review and apply remediation steps. GitProvider abstracts where
// that PR lands — GitHub, GitLab, Bitbucket, or Azure DevOps — enabling enterprise
// teams on any git platform to receive automated fix suggestions.
//
// Adding a new provider:
//  1. Add a file <provider>.go implementing Provider.
//  2. Add a case in NewFromFlags() in factory.go.
//  3. Document required env vars in docs/configuration.md.
package gitprovider

import (
	"context"

	"github.com/exalm-ai/exalm/pkg/plugin"
)

// Provider creates a pull request containing Exalm's fix recommendations.
type Provider interface {
	// Name identifies the provider, e.g. "github", "gitlab".
	Name() string
	// CreateFixPR opens a PR with a remediation document and returns its URL.
	CreateFixPR(ctx context.Context, report plugin.Report) (prURL string, err error)
}

// Options is the common configuration shared by all providers.
type Options struct {
	// Token is the API token or personal access token.
	Token string
	// BaseURL overrides the API endpoint for self-hosted instances
	// (e.g. GitHub Enterprise, GitLab self-managed). Leave empty for cloud.
	BaseURL    string
	Owner      string // org or username
	Repo       string // repository name
	BaseBranch string // branch to base the PR on; defaults to "main"
}
