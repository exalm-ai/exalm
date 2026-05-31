package gitprovider

import (
	"context"
	"errors"

	"github.com/exalm-ai/exalm/pkg/plugin"
)

// Bitbucket implements Provider using the Bitbucket Cloud REST API v2.
//
// SRE use case: teams using Atlassian Bitbucket receive Exalm fix pull requests
// in their existing workflow without requiring a GitHub or GitLab account.
//
// TODO: implement using the Bitbucket REST API v2:
//
//	POST /2.0/repositories/{workspace}/{repo_slug}/refs/branches  — create branch
//	POST /2.0/repositories/{workspace}/{repo_slug}/src             — commit EXALM_FIXES.md
//	POST /2.0/repositories/{workspace}/{repo_slug}/pullrequests    — open PR
//
// API reference: https://developer.atlassian.com/cloud/bitbucket/rest/
// Authentication: App passwords (username + app_password) or OAuth 2.0.
// Note: opts.Token should be "username:app_password" for basic auth.
type Bitbucket struct{}

// NewBitbucket constructs a Bitbucket Cloud provider. Token is required.
func NewBitbucket(opts Options) (*Bitbucket, error) {
	if opts.Token == "" {
		return nil, errors.New("bitbucket: token is required (format: username:app_password)")
	}
	// TODO: validate credentials and resolve workspace/repo slug on construction.
	return nil, errors.New("bitbucket provider: not yet implemented — see plugins/k8s/github.go for the GitHub reference implementation")
}

// Name returns "bitbucket".
func (b *Bitbucket) Name() string { return "bitbucket" }

// CreateFixPR opens a Bitbucket pull request with a remediation document.
// TODO: implement after NewBitbucket is functional.
func (b *Bitbucket) CreateFixPR(_ context.Context, _ plugin.Report) (string, error) {
	return "", errors.New("bitbucket provider: not yet implemented")
}
