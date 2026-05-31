package redact

import "regexp"

// Pattern is a single named redaction rule.
type Pattern struct {
	Name    string
	Regex   *regexp.Regexp
	Replace string // replacement string; supports $1 backreferences
}

// DefaultPatterns are applied unconditionally. Be conservative: false
// positives are far less harmful than leaks. Add tests for every pattern
// in redact_test.go.
//
// Order matters: more specific patterns should run first.
var DefaultPatterns = []Pattern{
	{
		Name:    "aws-access-key",
		Regex:   regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`),
		Replace: "[REDACTED:AWS_ACCESS_KEY]",
	},
	{
		Name:    "aws-temp-access-key",
		Regex:   regexp.MustCompile(`\bASIA[0-9A-Z]{16}\b`),
		Replace: "[REDACTED:AWS_TEMP_KEY]",
	},
	{
		Name: "aws-secret-access-key",
		// Heuristic: 40-char base64-ish strings labeled as secret keys.
		Regex:   regexp.MustCompile(`(?i)(aws_secret_access_key|secret[_-]?key)\s*[:=]\s*["']?[A-Za-z0-9/+=]{40}["']?`),
		Replace: "${1}=[REDACTED:AWS_SECRET_KEY]",
	},
	{
		Name:    "github-token",
		Regex:   regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{36,}\b`),
		Replace: "[REDACTED:GITHUB_TOKEN]",
	},
	{
		Name:    "anthropic-key",
		Regex:   regexp.MustCompile(`\bsk-ant-[A-Za-z0-9_\-]{20,}\b`),
		Replace: "[REDACTED:ANTHROPIC_KEY]",
	},
	{
		Name:    "openai-key",
		Regex:   regexp.MustCompile(`\bsk-[A-Za-z0-9]{20,}\b`),
		Replace: "[REDACTED:OPENAI_KEY]",
	},
	{
		Name:    "google-api-key",
		Regex:   regexp.MustCompile(`\bAIza[0-9A-Za-z_\-]{35}\b`),
		Replace: "[REDACTED:GOOGLE_API_KEY]",
	},
	{
		Name:    "slack-token",
		Regex:   regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9\-]{10,}\b`),
		Replace: "[REDACTED:SLACK_TOKEN]",
	},
	{
		Name:    "stripe-key",
		Regex:   regexp.MustCompile(`\b(sk|rk|pk)_(live|test)_[A-Za-z0-9]{20,}\b`),
		Replace: "[REDACTED:STRIPE_KEY]",
	},
	{
		Name:    "jwt",
		Regex:   regexp.MustCompile(`\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b`),
		Replace: "[REDACTED:JWT]",
	},
	{
		Name:    "bearer-token",
		Regex:   regexp.MustCompile(`(?i)bearer\s+[A-Za-z0-9._\-/+=]{20,}`),
		Replace: "Bearer [REDACTED:BEARER_TOKEN]",
	},
	{
		Name:    "private-key-block",
		Regex:   regexp.MustCompile(`(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----`),
		Replace: "[REDACTED:PRIVATE_KEY_BLOCK]",
	},
	{
		Name:    "password-assignment",
		Regex:   regexp.MustCompile(`(?i)(password|passwd|pwd)\s*[:=]\s*["']?[^\s"',;]{4,}["']?`),
		Replace: "${1}=[REDACTED:PASSWORD]",
	},
	{
		Name:    "connection-string",
		Regex:   regexp.MustCompile(`\b([a-z][a-z0-9+]{1,}://[^:\s]+):([^@\s]+)@`),
		Replace: "${1}:[REDACTED:CONN_PASSWORD]@",
	},
	{
		Name:    "azure-storage-key",
		Regex:   regexp.MustCompile(`\bAccountKey=[A-Za-z0-9+/=]{60,}`),
		Replace: "AccountKey=[REDACTED:AZURE_STORAGE_KEY]",
	},
	{
		// Base64-encoded docker config JSON sometimes surfaces verbatim in k8s events.
		Name:    "docker-config-json",
		Regex:   regexp.MustCompile(`(?i)(\.dockerconfigjson|dockerconfigjson)\s*[:=]\s*["']?[A-Za-z0-9+/=]{40,}["']?`),
		Replace: "${1}=[REDACTED:DOCKER_CONFIG]",
	},
	{
		// Windows user/group SID. Leaks domain structure and account identity.
		Name:    "windows-sid",
		Regex:   regexp.MustCompile(`\bS-1-5-21-\d+-\d+-\d+-\d+\b`),
		Replace: "[REDACTED:WINDOWS_SID]",
	},
	{
		// NTLM hash (LM:NT). Surface in pass-the-hash dumps and some event log payloads.
		Name:    "ntlm-hash",
		Regex:   regexp.MustCompile(`\b[a-fA-F0-9]{32}:[a-fA-F0-9]{32}\b`),
		Replace: "[REDACTED:NTLM_HASH]",
	},
}

// OptionalPatterns are off by default; turn on with config flags. They
// have higher false-positive rates and may distort the LLM's analysis.
var OptionalPatterns = map[string]Pattern{
	"email": {
		Name:    "email",
		Regex:   regexp.MustCompile(`\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b`),
		Replace: "[REDACTED:EMAIL]",
	},
	"ipv4": {
		Name:    "ipv4",
		Regex:   regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`),
		Replace: "[REDACTED:IPV4]",
	},
	"credit-card": {
		Name:    "credit-card",
		Regex:   regexp.MustCompile(`\b(?:\d[ -]*?){13,19}\b`),
		Replace: "[REDACTED:CREDIT_CARD]",
	},
	"internal-ipv4": {
		// RFC1918 ranges. Off by default — IP addresses are often signal,
		// not noise, in IIS/syslog/nginx analyses.
		Name:    "internal-ipv4",
		Regex:   regexp.MustCompile(`\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b`),
		Replace: "[REDACTED:INTERNAL_IPV4]",
	},
	"windows-account": {
		// DOMAIN\username — only redacts on AD-shaped prefixes that look like SAM names.
		// Conservative to avoid hitting Windows paths like C:\Users\Public.
		Name:    "windows-account",
		Regex:   regexp.MustCompile(`\b[A-Z][A-Z0-9_\-]{1,15}\\[A-Za-z0-9._\-$]{1,20}\b`),
		Replace: "[REDACTED:WINDOWS_ACCOUNT]",
	},
	"linux-username": {
		// Usernames in sshd/sudo/login log lines. Targets the common shapes:
		// "password for X", "session opened for user X", "Invalid user X", "USER=X".
		// Off by default — usernames are often legitimate signal.
		Name:    "linux-username",
		Regex:   regexp.MustCompile(`(?i)\b(password for(?:\s+invalid\s+user)?|session\s+(?:opened|closed)\s+for\s+user|invalid\s+user|by\s+user|USER=|user)\s+([a-z_][a-z0-9_\-]{0,31})\b`),
		Replace: "${1} [REDACTED:LINUX_USER]",
	},
}
