FROM golang:1.26-alpine AS builder
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags "-s -w" -o /out/wingsv-fed ./cmd/wingsv-fed

FROM alpine:3.22
# Лейбл привязывает пакет в ghcr к этому репозиторию - без привязки токен Actions
# не имеет прав на пакет и пуш отбивается permission_denied
LABEL org.opencontainers.image.source="https://github.com/WINGS-N/wingsvpn-federation"
# Alpine rather than scratch on purpose: the node chart enrols and then execs the
# agent from a shell wrapper, and the kernel-module preflight is a shell script
# too. A distroless image would break both for the sake of a few megabytes.
# iptables нужен агенту: порт данных выбирается под ноду, и открыть его в
# файрволе хоста больше некому - без этого релей слушает, а хост с политикой
# DROP молча съедает весь DTLS
RUN apk add --no-cache ca-certificates tzdata iptables
COPY --from=builder /out/wingsv-fed /usr/local/bin/wingsv-fed
# The agent downloads and supervises Xray itself, so nothing else belongs here.
ENTRYPOINT ["/usr/local/bin/wingsv-fed"]
