{{/* vim: set filetype=mustache: */}}
{{/*
Expand the name of the chart.
*/}}
{{- define "vault-secrets-webhook.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "vault-secrets-webhook.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "vault-secrets-webhook.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "vault-secrets-webhook.selfSignedIssuer" -}}
{{ printf "%s-selfsign" (include "vault-secrets-webhook.fullname" .) }}
{{- end -}}

{{- define "vault-secrets-webhook.rootCAIssuer" -}}
{{ printf "%s-ca" (include "vault-secrets-webhook.fullname" .) }}
{{- end -}}

{{- define "vault-secrets-webhook.rootCACertificate" -}}
{{ printf "%s-ca" (include "vault-secrets-webhook.fullname" .) }}
{{- end -}}

{{- define "vault-secrets-webhook.servingCertificate" -}}
{{ printf "%s-webhook-tls" (include "vault-secrets-webhook.fullname" .) }}
{{- end -}}

{{/*
Overrideable version for container image tags.
*/}}
{{- define "vault-secrets-webhook.bank-vaults.version" -}}
{{- .Values.image.tag | default (printf "%s" .Chart.AppVersion) -}}
{{- end -}}

{{/*
Create the name of the service account to use
*/}}
{{- define "vault-secrets-webhook.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "vault-secrets-webhook.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}
