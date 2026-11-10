{{/* Chart name, truncated to the 63 char DNS label limit. */}}
{{- define "kevgate.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "kevgate.fullname" -}}
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

{{- define "kevgate.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "kevgate.selectorLabels" -}}
app.kubernetes.io/name: {{ include "kevgate.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "kevgate.labels" -}}
helm.sh/chart: {{ include "kevgate.chart" . }}
{{ include "kevgate.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: kevgate
{{- end }}

{{- define "kevgate.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "kevgate.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/* Image reference. Digest wins over tag when both are set. */}}
{{- define "kevgate.image" -}}
{{- if .Values.image.digest }}
{{- printf "%s@%s" .Values.image.repository .Values.image.digest }}
{{- else }}
{{- printf "%s:%s" .Values.image.repository (default .Chart.AppVersion .Values.image.tag) }}
{{- end }}
{{- end }}

{{- define "kevgate.apiKeysSecretName" -}}
{{- if .Values.apiKeys.existingSecret }}
{{- .Values.apiKeys.existingSecret }}
{{- else }}
{{- printf "%s-api-keys" (include "kevgate.fullname" .) }}
{{- end }}
{{- end }}

{{/* Guard rails evaluated once from the Deployment template. */}}
{{- define "kevgate.validate" -}}
{{- if and (or (gt (int .Values.replicaCount) 1) .Values.autoscaling.enabled) (not .Values.scaling.acknowledgeSqliteSplitState) }}
{{- fail "kevgate keeps state in SQLite: replicaCount > 1 or autoscaling.enabled splits state across pods. Set scaling.acknowledgeSqliteSplitState=true only for stateless testing." }}
{{- end }}
{{- if and (eq .Values.app.env "prod") (not .Values.apiKeys.existingSecret) (not .Values.apiKeys.create) }}
{{- fail "app.env=prod requires API keys: set apiKeys.existingSecret or apiKeys.create=true with apiKeys.entries." }}
{{- end }}
{{- if and .Values.apiKeys.create (not .Values.apiKeys.existingSecret) (empty .Values.apiKeys.entries) }}
{{- fail "apiKeys.create=true needs at least one entry in apiKeys.entries." }}
{{- end }}
{{- if and .Values.image.tag (eq .Values.image.tag "latest") }}
{{- fail "image.tag=latest is not allowed; use a version tag or image.digest." }}
{{- end }}
{{- end }}
