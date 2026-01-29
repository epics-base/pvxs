{{- define "pvxs-lab.image" -}}
{{- $u := .Values.dockerUsername | default "georgeleveln" -}}
{{- $name := required "image name is required" .name -}}
{{- $tag := .tag | default "latest" -}}
{{- printf "%s/%s:%s" $u $name $tag -}}
{{- end -}}
{{- define "pvxs-lab.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "pvxs-lab.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s" (include "pvxs-lab.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "pvxs-lab.labels" -}}
app.kubernetes.io/name: {{ include "pvxs-lab.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "pvxs-lab.gatewayService" -}}
{{ include "pvxs-lab.fullname" . }}-gateway
{{- end -}}
{{- define "pvxs-lab.pvacmsService" -}}
{{ include "pvxs-lab.fullname" . }}-pvacms
{{- end -}}
{{- define "pvxs-lab.testiocService" -}}
{{ include "pvxs-lab.fullname" . }}-testioc
{{- end -}}
{{- define "pvxs-lab.tstiocService" -}}
{{ include "pvxs-lab.fullname" . }}-tstioc
{{- end -}}
