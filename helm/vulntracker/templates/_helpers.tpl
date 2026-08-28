{{- define "vulntracker.name" -}}
vulntracker
{{- end }}

{{- define "vulntracker.fullname" -}}
{{ .Release.Name }}-vulntracker
{{- end }}

{{- define "vulntracker.labels" -}}
app.kubernetes.io/name: {{ include "vulntracker.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}
