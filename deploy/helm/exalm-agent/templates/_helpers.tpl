{{/*
Common chart helpers — naming, labels, and secret resolution.
*/}}

{{/*
Expand the name of the chart.
*/}}
{{- define "exalm-agent.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Fully qualified app name: <release>-<chart>, truncated to 63 chars (DNS-1123).
*/}}
{{- define "exalm-agent.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Chart name + version, used in the helm.sh/chart label.
*/}}
{{- define "exalm-agent.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Standard recommended labels (Kubernetes app.kubernetes.io/* scheme).
*/}}
{{- define "exalm-agent.labels" -}}
helm.sh/chart: {{ include "exalm-agent.chart" . }}
{{ include "exalm-agent.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: exalm
{{- end }}

{{/*
Selector labels used in Deployment/Service selectors. Must be stable across upgrades.
*/}}
{{- define "exalm-agent.selectorLabels" -}}
app.kubernetes.io/name: {{ include "exalm-agent.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
ServiceAccount name — generated or referenced.
*/}}
{{- define "exalm-agent.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "exalm-agent.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Name of the Secret holding the LLM API key.
- If llm.existingSecret is set, use that.
- Otherwise the chart will create a Secret named after the release.
*/}}
{{- define "exalm-agent.secretName" -}}
{{- if .Values.llm.existingSecret }}
{{- .Values.llm.existingSecret }}
{{- else }}
{{- include "exalm-agent.fullname" . }}
{{- end }}
{{- end }}

{{/*
Map provider → secret key. Used by both deployment.yaml and secret.yaml so the
two stay in sync.
*/}}
{{- define "exalm-agent.providerSecretKey" -}}
{{- if eq .Values.llm.provider "claude" -}}
anthropic-api-key
{{- else if eq .Values.llm.provider "openai" -}}
openai-api-key
{{- else if eq .Values.llm.provider "openrouter" -}}
openrouter-api-key
{{- else -}}
{{/* providers that don't need a secret (e.g. ollama) */}}
{{- end -}}
{{- end }}

{{/*
Map provider → env-var name expected by the binary (see internal/config/config.go).
*/}}
{{- define "exalm-agent.providerEnvName" -}}
{{- if eq .Values.llm.provider "claude" -}}
ANTHROPIC_API_KEY
{{- else if eq .Values.llm.provider "openai" -}}
OPENAI_API_KEY
{{- else if eq .Values.llm.provider "openrouter" -}}
OPENROUTER_API_KEY
{{- else -}}
{{- end -}}
{{- end }}

{{/*
Validate the provider value at template-render time.
*/}}
{{- define "exalm-agent.validateProvider" -}}
{{- $valid := list "claude" "openai" "ollama" "openrouter" -}}
{{- if not (has .Values.llm.provider $valid) -}}
{{- fail (printf "llm.provider %q is not supported — must be one of: claude, openai, ollama, openrouter" .Values.llm.provider) -}}
{{- end -}}
{{- end }}
