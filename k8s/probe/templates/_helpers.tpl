{{/*
Names are fixed, not derived from the release name. They end up in a DSN, in an
ingress and in whatever else points here from outside the chart, and a name that
moves when someone renames the release turns those into silent misroutes.
*/}}
{{- define "probe.name" -}}
{{ .Values.nameOverride | default "fed-probe" }}
{{- end -}}

{{/*
The chart installs into wingsvpn whether or not -n was passed. Helm still keeps
its release metadata in the namespace of -n, so pass "-n wingsvpn" as well or
"helm list -n wingsvpn" will not find the release it just installed.
*/}}
{{- define "probe.namespace" -}}
{{ .Values.namespace | default .Release.Namespace }}
{{- end -}}

