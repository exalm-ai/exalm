package gitprovider

import (
	"context"
	"errors"

	"github.com/exalm-ai/exalm/pkg/plugin"
)

// GitLab implements Provider using the GitLab REST API.
//
// SRE use case: enterprises running GitLab self-managed or GitLab.com receive
// Exalm fix merge requests in their existing workflow without requiring GitHub.
//
// TODO: implement using the GitLab Projects API:
//
//	POST /projects/:id/repository/branches  — create fix branch
//	POST /projects/:id/repository/files     — commit EXALM_FIXES.md
//	POST /projects/:id/merge_requests       — open merge request
//
// API reference: https://docs.gitlab.com/ee/api/merge_requests.html
// The project ID must be resolved from opts.Owner/opts.Repo via:
//
//	GET /api/v4/projects?search=<repo> or GET /api/v4/projects/<owner>%2F<repo>
type GitLab struct{}

// NewGitLab constructs a GitLab provider. Token is required.
func NewGitLab(opts Options) (*GitLab, error) {
	if opts.Token == "" {
		return nil, errors.New("gitlab: token is required (set GITLAB_TOKEN or --github-token)")
	}
	// TODO: validate token and resolve project ID from owner/repo on construction.
	return nil, errors.New("gitlab provider: not yet implemented — see plugins/k8s/github.go for the GitHub reference implementation")
}

// Name returns "gitlab".
func (g *GitLab) Name() string { return "gitlab" }

// CreateFixPR opens a GitLab merge request with a remediation document.
// TODO: implement after NewGitLab is functional.
func (g *GitLab) CreateFixPR(_ context.Context, _ plugin.Report) (string, error) {
	return "", errors.New("gitlab provider: not yet implemented")
}
