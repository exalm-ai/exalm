package gitprovider

import "fmt"

// NewFromFlags constructs a Provider from a provider name string and Options.
// The name is the value of the --git-provider flag (default "github").
//
// Supported values:
//   - "github" (default)  — GitHub.com or GitHub Enterprise (set BaseURL for GHE)
//   - "gitlab"            — GitLab.com or self-managed GitLab
//   - "bitbucket"         — Bitbucket Cloud
//   - "azuredevops"       — Azure DevOps
func NewFromFlags(provider string, opts Options) (Provider, error) {
	switch provider {
	case "", "github":
		return NewGitHub(opts)
	case "gitlab":
		return NewGitLab(opts)
	case "bitbucket":
		return NewBitbucket(opts)
	case "azuredevops":
		return NewAzureDevOps(opts)
	default:
		return nil, fmt.Errorf("unknown git provider %q — supported: github, gitlab, bitbucket, azuredevops", provider)
	}
}
