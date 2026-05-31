package gitprovider

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/exalm-ai/exalm/pkg/plugin"
)

const defaultGitHubAPIURL = "https://api.github.com"

// GitHub implements Provider using the GitHub REST API.
type GitHub struct {
	opts   Options
	apiURL string
	http   *http.Client
}

// NewGitHub constructs a GitHub provider. Token is required.
func NewGitHub(opts Options) (*GitHub, error) {
	if opts.Token == "" {
		return nil, fmt.Errorf("github: token is required (set GITHUB_TOKEN or --github-token)")
	}
	if opts.BaseBranch == "" {
		opts.BaseBranch = "main"
	}
	apiURL := opts.BaseURL
	if apiURL == "" {
		apiURL = defaultGitHubAPIURL
	}
	return &GitHub{
		opts:   opts,
		apiURL: apiURL,
		http:   &http.Client{Timeout: 30 * time.Second},
	}, nil
}

// Name returns "github".
func (g *GitHub) Name() string { return "github" }

// CreateFixPR creates a branch "exalm/fix-<timestamp>", commits EXALM_FIXES.md,
// and opens a pull request. Returns the HTML URL of the created PR.
func (g *GitHub) CreateFixPR(ctx context.Context, report plugin.Report) (string, error) {
	branch := fmt.Sprintf("exalm/fix-%d", time.Now().Unix())

	baseSHA, err := g.getBranchSHA(ctx, g.opts.BaseBranch)
	if err != nil {
		return "", fmt.Errorf("get base branch sha: %w", err)
	}

	content := buildPRBody(report)

	blobSHA, err := g.createBlob(ctx, content)
	if err != nil {
		return "", fmt.Errorf("create blob: %w", err)
	}

	treeSHA, err := g.createTree(ctx, baseSHA, "EXALM_FIXES.md", blobSHA)
	if err != nil {
		return "", fmt.Errorf("create tree: %w", err)
	}

	commitSHA, err := g.createCommit(ctx, "chore: add Exalm Kubernetes fix suggestions", treeSHA, baseSHA)
	if err != nil {
		return "", fmt.Errorf("create commit: %w", err)
	}

	if err := g.createRef(ctx, branch, commitSHA); err != nil {
		return "", fmt.Errorf("create branch: %w", err)
	}

	prURL, err := g.createPR(ctx, branch, g.opts.BaseBranch, report)
	if err != nil {
		return "", fmt.Errorf("create pr: %w", err)
	}
	return prURL, nil
}

// buildPRBody renders the markdown file committed to the PR branch.
func buildPRBody(report plugin.Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Exalm Fix Suggestions\n\nGenerated: %s\n\n", time.Now().UTC().Format(time.RFC3339))
	fmt.Fprintf(&b, "## Summary\n\n%s\n\n", report.Summary)

	actionable := 0
	for _, f := range report.Findings {
		if f.Remediation != nil {
			actionable++
		}
	}
	if actionable == 0 {
		b.WriteString("## Findings\n\nNo auto-fixable findings. See suggestions below.\n\n")
	} else {
		fmt.Fprintf(&b, "## Findings (%d auto-fixable)\n\n", actionable)
	}

	for _, f := range report.Findings {
		fmt.Fprintf(&b, "### [%s] %s\n\n", strings.ToUpper(string(f.Severity)), f.Title)
		if f.Detail != "" {
			fmt.Fprintf(&b, "**Detail:** %s\n\n", f.Detail)
		}
		if f.Suggestion != "" {
			fmt.Fprintf(&b, "**Suggestion:** %s\n\n", f.Suggestion)
		}
		if f.Remediation != nil {
			fmt.Fprintf(&b, "**Auto-fix:**\n\n```sh\n%s\n```\n\n", f.Remediation.KubectlCmd)
		}
	}
	return b.String()
}

// ── GitHub REST client ─────────────────────────────────────────────────────

func (g *GitHub) do(ctx context.Context, method, path string, body any) (map[string]any, error) {
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			return nil, fmt.Errorf("encode body: %w", err)
		}
	}
	url := g.apiURL + path
	req, err := http.NewRequestWithContext(ctx, method, url, &buf) //nolint:gosec // G107: URL is the GitHub API endpoint from config
	if err != nil {
		return nil, fmt.Errorf("new request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+g.opts.Token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")

	resp, err := g.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http %s %s: %w", method, url, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)

	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("github api %s %s: status %d: %s", method, path, resp.StatusCode, string(raw))
	}
	var result map[string]any
	if err := json.Unmarshal(raw, &result); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return result, nil
}

func (g *GitHub) getBranchSHA(ctx context.Context, branch string) (string, error) {
	path := fmt.Sprintf("/repos/%s/%s/git/ref/heads/%s", g.opts.Owner, g.opts.Repo, branch)
	res, err := g.do(ctx, http.MethodGet, path, nil)
	if err != nil {
		return "", err
	}
	obj, _ := res["object"].(map[string]any)
	sha, _ := obj["sha"].(string)
	if sha == "" {
		return "", fmt.Errorf("empty sha for branch %s", branch)
	}
	return sha, nil
}

func (g *GitHub) createBlob(ctx context.Context, content string) (string, error) {
	encoded := base64.StdEncoding.EncodeToString([]byte(content))
	res, err := g.do(ctx, http.MethodPost,
		fmt.Sprintf("/repos/%s/%s/git/blobs", g.opts.Owner, g.opts.Repo),
		map[string]string{"content": encoded, "encoding": "base64"},
	)
	if err != nil {
		return "", err
	}
	sha, _ := res["sha"].(string)
	if sha == "" {
		return "", fmt.Errorf("empty sha from blob creation")
	}
	return sha, nil
}

func (g *GitHub) createTree(ctx context.Context, baseSHA, filename, blobSHA string) (string, error) {
	res, err := g.do(ctx, http.MethodPost,
		fmt.Sprintf("/repos/%s/%s/git/trees", g.opts.Owner, g.opts.Repo),
		map[string]any{
			"base_tree": baseSHA,
			"tree":      []map[string]string{{"path": filename, "mode": "100644", "type": "blob", "sha": blobSHA}},
		},
	)
	if err != nil {
		return "", err
	}
	sha, _ := res["sha"].(string)
	if sha == "" {
		return "", fmt.Errorf("empty sha from tree creation")
	}
	return sha, nil
}

func (g *GitHub) createCommit(ctx context.Context, message, treeSHA, parentSHA string) (string, error) {
	res, err := g.do(ctx, http.MethodPost,
		fmt.Sprintf("/repos/%s/%s/git/commits", g.opts.Owner, g.opts.Repo),
		map[string]any{"message": message, "tree": treeSHA, "parents": []string{parentSHA}},
	)
	if err != nil {
		return "", err
	}
	sha, _ := res["sha"].(string)
	if sha == "" {
		return "", fmt.Errorf("empty sha from commit creation")
	}
	return sha, nil
}

func (g *GitHub) createRef(ctx context.Context, branch, sha string) error {
	_, err := g.do(ctx, http.MethodPost,
		fmt.Sprintf("/repos/%s/%s/git/refs", g.opts.Owner, g.opts.Repo),
		map[string]string{"ref": "refs/heads/" + branch, "sha": sha},
	)
	return err
}

func (g *GitHub) createPR(ctx context.Context, head, base string, report plugin.Report) (string, error) {
	title := fmt.Sprintf("Exalm: fix suggestions (%s)", time.Now().UTC().Format("2006-01-02"))
	body := fmt.Sprintf("## Exalm Analysis\n\n%s\n\nSee `EXALM_FIXES.md` for detailed findings.", report.Summary)

	res, err := g.do(ctx, http.MethodPost,
		fmt.Sprintf("/repos/%s/%s/pulls", g.opts.Owner, g.opts.Repo),
		map[string]string{"title": title, "body": body, "head": head, "base": base},
	)
	if err != nil {
		return "", err
	}
	url, _ := res["html_url"].(string)
	if url == "" {
		return "", fmt.Errorf("empty html_url from PR creation")
	}
	return url, nil
}
