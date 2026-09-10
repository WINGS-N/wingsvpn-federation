{{/*
Names are fixed, not derived from the release name. They end up in a DSN, in an
ingress and in whatever else points here from outside the chart, and a name that
moves when someone renames the release turns those into silent misroutes.
*/}}
{{- define "node.name" -}}
{{ .Values.nameOverride | default "fed-node" }}
{{- end -}}

{{/*
The chart installs into wingsvpn whether or not -n was passed. Helm still keeps
its release metadata in the namespace of -n, so pass "-n wingsvpn" as well or
"helm list -n wingsvpn" will not find the release it just installed.
*/}}
{{- define "node.namespace" -}}
{{ .Values.namespace | default .Release.Namespace }}
{{- end -}}

{{- define "node.secretName" -}}
{{- if .Values.existingSecret -}}
{{ .Values.existingSecret }}
{{- else -}}
{{ include "node.name" . }}-secrets
{{- end -}}
{{- end -}}

{{/*
Capabilities rather than privileged: kernel WireGuard needs NET_ADMIN to drive
netlink and create the interface, and NET_BIND_SERVICE to sit on 443. Nothing
here needs the rest of what privileged hands over.
*/}}
{{- define "node.securityContext" -}}
{{- if .Values.privileged -}}
privileged: true
{{- else -}}
capabilities:
  add:
    - NET_ADMIN
    - NET_BIND_SERVICE
    # Сырой сокет на wg-интерфейсе: у релея нет ни sniffing, ни access-лога, и
    # куда ходят его клиенты, видно только из расшифрованных пакетов
    - NET_RAW
{{- end }}
{{- end -}}
