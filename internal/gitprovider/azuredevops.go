package gitprovider

import (
	"context"
	"errors"

	"github.com/exalm-ai/exalm/pkg/plugin"
)

// AzureDevOps implements Provider using the Azure DevOps REST API.
//
// SRE use case: enterprise teams using Azure DevOps (formerly VSTS/TFS) receive
// Exalm fix pull requests in their existing workflow — a major enterprise adoption
// requirement for organisations standardised on the Microsoft toolchain.
//
// TODO: implement using the Azure DevOps REST API:
//
//	POST /{org}/{project}/_apis/git/repositories/{repoId}/refs  — create branch
//	POST /{org}/{project}/_apis/git/repositories/{repoId}/pushes — commit EXALM_FIXES.md
//	POST /{org}/{project}/_apis/git/repositories/{repoId}/pullrequests — open PR
//
// API reference: https://learn.microsoft.com/en-us/rest/api/azure/devops/git/
// Authentication: Personal Access Token (PAT) via Basic auth (base64 ":pat").
// opts.Owner = org name, opts.Repo = repository name.
// opts.BaseURL = "https://dev.azure.com/{org}/{project}" (required).
type AzureDevOps struct{}

// NewAzureDevOps constructs an Azure DevOps provider. Token and BaseURL are required.
func NewAzureDevOps(opts Options) (*AzureDevOps, error) {
	if opts.Token == "" {
		return nil, errors.New("azuredevops: personal access token is required (set --github-token to the PAT)")
	}
	if opts.BaseURL == "" {
		return nil, errors.New("azuredevops: BaseURL is required (format: https://dev.azure.com/{org}/{project})")
	}
	// TODO: validate token and resolve repository ID from opts.Repo on construction.
	return nil, errors.New("azuredevops provider: not yet implemented — see plugins/k8s/github.go for the GitHub reference implementation")
}

// Name returns "azuredevops".
func (a *AzureDevOps) Name() string { return "azuredevops" }

// CreateFixPR opens an Azure DevOps pull request with a remediation document.
// TODO: implement after NewAzureDevOps is functional.
func (a *AzureDevOps) CreateFixPR(_ context.Context, _ plugin.Report) (string, error) {
	return "", errors.New("azuredevops provider: not yet implemented")
}
