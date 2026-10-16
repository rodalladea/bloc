{{- define "bloc.name" -}}
{{- printf "%s-bloc" .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- define "bloc.selector" -}}
app.kubernetes.io/name: bloc
app.kubernetes.io/instance: {{ .Release.Name | quote }}
{{- end -}}
{{- define "bloc.labels" -}}
{{ include "bloc.selector" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service | quote }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | quote }}
{{- end -}}
