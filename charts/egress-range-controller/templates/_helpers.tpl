{{- define "erc.name" -}}egress-range-controller{{- end -}}
{{- define "erc.fullname" -}}
{{- if contains "egress-range-controller" .Release.Name -}}{{ .Release.Name | trunc 63 | trimSuffix "-" }}{{- else -}}{{ printf "%s-egress-range-controller" .Release.Name | trunc 63 | trimSuffix "-" }}{{- end -}}
{{- end -}}
{{- define "erc.labels" -}}
app.kubernetes.io/name: {{ include "erc.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{- end -}}
{{- define "erc.selectorLabels" -}}
app.kubernetes.io/name: {{ include "erc.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}
{{- define "erc.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}{{ default (include "erc.fullname" .) .Values.serviceAccount.name }}{{- else -}}{{ default "default" .Values.serviceAccount.name }}{{- end -}}
{{- end -}}
{{- define "erc.image" -}}
{{- if .Values.image.digest -}}{{ .Values.image.repository }}@{{ .Values.image.digest }}{{- else -}}{{ .Values.image.repository }}:{{ default .Chart.AppVersion .Values.image.tag }}{{- end -}}
{{- end -}}
{{- define "erc.leaseName" -}}egress-range-controller.egress.greybeard.support{{- end -}}
