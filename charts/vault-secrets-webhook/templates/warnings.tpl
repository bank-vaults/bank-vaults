{{/* this file is for generating warnings about incorrect usage of the chart */}}

{{- if .Values.certificate.generate  }}
{{- if .Values.certificate.useCertManager }}
    {{ fail "It is not allowed to both set certificate.generate=true and certificate.useCertManager=true."}}
{{- end }}
{{- end }}

{{- if .Values.webhookClientConfig.useUrl -}}
{{- if or (not .Values.webhookClientConfig.url )  }}
  {{ fail "When webhookClientConfig.useUrl=true webhookClientConfig.url should be set and not empty "}}
{{- end }}
{{- end }}