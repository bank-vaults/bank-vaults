{{/* vim: set filetype=mustache: */}}
{{/*
Expand the name of the chart.
*/}}
{{- define "vault-operator.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "vault-operator.fullname" -}}
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
{{- define "vault-operator.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Determines if the current executing Helm environment is v3 or not.
If yes, it returns the string "helm3", otherwise it returns "".
*/}}
{{- define "isHelm3" -}}
{{- if hasKey (toJson .Chart | fromJson) "type" -}}
{{- "helm3" -}}
{{- else -}}
{{- "" -}}
{{- end -}}
{{- end -}}

{{/*
Overrideable version for container image tags.
*/}}
{{- define "bank-vaults.version" -}}
{{- .Values.image.tag | default (printf "%s" .Chart.AppVersion) -}}
{{- end -}}

{{/*
Image pull secrets
*/}}
{{- define "vault-operator.imagePullSecrets" -}}
{{- if .Values.global }}
    {{- if .Values.global.imagePullSecrets }}
imagePullSecrets:
        {{- range .Values.global.imagePullSecrets }}
  - name: {{ . }}
        {{- end }}
    {{- else if .Values.image.imagePullSecrets }}
imagePullSecrets:
        {{- range .Values.image.imagePullSecrets }}
  - name: {{ . }}
        {{- end }}
    {{- end -}}
{{- else if .Values.image.imagePullSecrets }}
imagePullSecrets:
    {{- range .Values.image.imagePullSecrets }}
  - name: {{ . }}
    {{- end }}
{{- end -}}
{{- end -}}