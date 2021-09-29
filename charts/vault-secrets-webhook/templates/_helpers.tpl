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
{{- define "vault-secrets-webhook.vault-env.version" -}}
{{- .Values.vaultEnv.tag | default (printf "%s" .Chart.AppVersion) -}}
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

{{/*
Return the target Kubernetes version.
https://github.com/bitnami/charts/blob/master/bitnami/common/templates/_capabilities.tpl
*/}}
{{- define "vault-secrets-webhook.capabilities.kubeVersion" -}}
{{- default .Capabilities.KubeVersion.Version .Values.kubeVersion -}}
{{- end -}}

{{/*
Return the appropriate apiVersion for policy.
*/}}
{{- define "vault-secrets-webhook.capabilities.policy.apiVersion" -}}
{{- if semverCompare "<1.21-0" (include "vault-secrets-webhook.capabilities.kubeVersion" .) -}}
{{- print "policy/v1beta1" -}}
{{- else -}}
{{- print "policy/v1" -}}
{{- end -}}
{{- end -}}

{{/*
Return the appropriate apiVersion for ingress.
*/}}
{{- define "vault-secrets-webhook.capabilities.ingress.apiVersion" -}}
{{- if .Values.ingress -}}
{{- if .Values.ingress.apiVersion -}}
{{- .Values.ingress.apiVersion -}}
{{- else if semverCompare "<1.14-0" (include "vault-secrets-webhook.capabilities.kubeVersion" .) -}}
{{- print "extensions/v1beta1" -}}
{{- else if semverCompare "<1.19-0" (include "vault-secrets-webhook.capabilities.kubeVersion" .) -}}
{{- print "networking.k8s.io/v1beta1" -}}
{{- else -}}
{{- print "networking.k8s.io/v1" -}}
{{- end }}
{{- else if semverCompare "<1.14-0" (include "vault-secrets-webhook.capabilities.kubeVersion" .) -}}
{{- print "extensions/v1beta1" -}}
{{- else if semverCompare "<1.19-0" (include "vault-secrets-webhook.capabilities.kubeVersion" .) -}}
{{- print "networking.k8s.io/v1beta1" -}}
{{- else -}}
{{- print "networking.k8s.io/v1" -}}
{{- end -}}
{{- end -}}
