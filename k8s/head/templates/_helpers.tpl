{{/*
Names are fixed, not derived from the release name. They end up in a DSN, in an
ingress and in whatever else points here from outside the chart, and a name that
moves when someone renames the release turns those into silent misroutes.
*/}}
{{- define "head.name" -}}
{{ .Values.nameOverride | default "fed-head" }}
{{- end -}}

{{/*
The chart installs into wingsvpn whether or not -n was passed. Helm still keeps
its release metadata in the namespace of -n, so pass "-n wingsvpn" as well or
"helm list -n wingsvpn" will not find the release it just installed.
*/}}
{{- define "head.namespace" -}}
{{ .Values.namespace | default .Release.Namespace }}
{{- end -}}

{{- define "head.image" -}}
{{ .Values.image.repository }}:{{ .Values.image.tag }}
{{- end -}}

{{- define "head.secretName" -}}
{{- if .Values.existingSecret -}}
{{ .Values.existingSecret }}
{{- else -}}
{{ include "head.name" . }}-secrets
{{- end -}}
{{- end -}}

{{/*
The head takes its whole configuration on the command line, so the flags are
built once here and shared by the Deployment and by anything that needs to show
an operator what is actually running.
*/}}
{{- define "head.args" -}}
- head
- -listen
- 0.0.0.0:{{ .Values.head.agentPort }}
- -advertise
- {{ required "head.advertise is required: it is the address nodes dial after enrolling" .Values.head.advertise | quote }}
- -panel-listen
- 0.0.0.0:{{ .Values.head.panelPort }}
- -provision-listen
- :{{ .Values.head.provisionPort }}
- -sub-listen
- 0.0.0.0:{{ .Values.head.subPort }}
{{- if .Values.head.probeSecret }}
- -probe-listen
- 0.0.0.0:{{ .Values.head.probePort }}
{{- end }}
- -state
- /var/lib/wings/federation/registry.json
- -allocations
- /var/lib/wings/federation/allocations.json
- -tcp-port
- {{ .Values.head.tcpPort | quote }}
- -xhttp-port
- {{ .Values.head.xhttpPort | quote }}
{{- if .Values.head.subBase }}
- -sub-base
- {{ .Values.head.subBase | quote }}
{{- end }}
{{- if .Values.ingressRoute.enabled }}
- -ingress-route
- {{ .Values.ingressRoute.name | quote }}
- -ingress-service
- {{ .Values.ingressRoute.service | quote }}
- -ingress-port
- {{ .Values.ingressRoute.port | quote }}
{{- end }}
{{- if .Values.head.agentRelease }}
- -agent-release
- {{ .Values.head.agentRelease | quote }}
{{- end }}
{{- if .Values.chain.enabled }}
# Публикация эпох в цепочку. Не хватит хоть одного значения - она не заводится,
# и эпохи просто копятся в базе: это законный режим, а не поломка
- -chain-rpc
- {{ .Values.chain.rpc | quote }}
- -chain-program
- {{ required "chain.program нужен, когда публикация включена" .Values.chain.program | quote }}
- -chain-key
- /var/lib/wings/federation/chain-key.json
- -chain-treasury
- {{ required "chain.treasury нужен, из него уходят выплаты" .Values.chain.treasury | quote }}
- -chain-mint
- {{ required "chain.mint нужен, на нём донорам заводятся счета" .Values.chain.mint | quote }}
{{- end }}
{{- if .Values.head.donationGB }}
- -donation-gb
- {{ .Values.head.donationGB | quote }}
{{- end }}
{{- if .Values.head.payoutMicroPerGiB }}
- -payout-micro-per-gib
- {{ .Values.head.payoutMicroPerGiB | quote }}
{{- end }}
{{- if .Values.head.payoutPeriod }}
- -payout-period
- {{ .Values.head.payoutPeriod | quote }}
{{- end }}
{{- if .Values.head.realityAuto }}
- -reality-auto
{{- else if .Values.head.realityDest }}
- -reality-dest
- {{ .Values.head.realityDest | quote }}
{{- end }}
{{- if .Values.head.realityPQ }}
- -reality-pq
{{- end }}
{{- if .Values.head.requireProbe }}
- -require-probe
{{- end }}
{{- end -}}

{{- define "head.pgName" -}}
{{ include "head.name" . }}-pg
{{- end -}}

{{/*
Куда голова ходит за состоянием. Собирается из тех же values, что засевают
кластер, чтобы пароль был записан ровно один раз.
*/}}
{{- define "head.dsn" -}}
postgres://{{ .Values.postgres.owner }}:{{ .Values.postgres.password }}@{{ include "head.pgName" . }}-rw.{{ include "head.namespace" . }}.svc.cluster.local:5432/{{ .Values.postgres.database }}?sslmode={{ .Values.postgres.sslmode }}
{{- end -}}
