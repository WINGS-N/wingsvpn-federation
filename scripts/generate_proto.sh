#!/usr/bin/env bash
set -euo pipefail
# Generates the public gRPC stubs. They live in gen/ rather than internal/ because
# the WINGS-N/3x-ui fork imports them to join the federation.
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PATH="$PATH:$(go env GOPATH)/bin"
protoc --proto_path="$ROOT/proto" \
  --go_out="$ROOT" --go_opt=module=wingsnet.org/federation \
  --go-grpc_out="$ROOT" --go-grpc_opt=module=wingsnet.org/federation \
  "$ROOT/proto/federation.proto" "$ROOT/proto/headpanel.proto"

# The relay's control.proto is vendored rather than imported as a module: its
# module path names the original upstream author, so a plain go get would fetch
# somebody else's contract instead of our fork's. Refresh with sync_vendored.sh
protoc --proto_path="$ROOT/proto/vendored" \
  --go_out="$ROOT" --go_opt=module=wingsnet.org/federation \
  --go_opt=Mcontrol.proto=wingsnet.org/federation/gen/controlpb \
  --go-grpc_out="$ROOT" --go-grpc_opt=module=wingsnet.org/federation \
  --go-grpc_opt=Mcontrol.proto=wingsnet.org/federation/gen/controlpb \
  "$ROOT/proto/vendored/control.proto"

# Формат ссылок и подписок приложения. Схема живёт в репозитории приложения и
# копируется сюда: голова обязана собирать ровно то, что приложение разбирает
protoc --proto_path="$ROOT/proto/vendored" \
  --go_out="$ROOT" --go_opt=module=wingsnet.org/federation \
  --go_opt=Mwingsv.proto=wingsnet.org/federation/gen/wingsvpb \
  "$ROOT/proto/vendored/wingsv.proto"

# Контракт провижна: релей на ноде спрашивает у головы, кому выдавать wg-пир
protoc --proto_path="$ROOT/proto/vendored" \
  --go_out="$ROOT" --go_opt=module=wingsnet.org/federation \
  --go_opt=Mprovisioning.proto=wingsnet.org/federation/gen/provisioningpb \
  --go-grpc_out="$ROOT" --go-grpc_opt=module=wingsnet.org/federation \
  --go-grpc_opt=Mprovisioning.proto=wingsnet.org/federation/gen/provisioningpb \
  "$ROOT/proto/vendored/provisioning.proto"

# Управляющий контракт Xray. Он вендорится, а не тянется модулем: импорт ядра
# утащил бы за собой пол-апстрима, а нам нужны ровно эти сообщения. Пакет один
# на все файлы, поэтому имена сообщений в них не должны пересекаться
protoc --proto_path="$ROOT/proto/vendored" \
  --go_out="$ROOT" --go_opt=module=wingsnet.org/federation \
  --go-grpc_out="$ROOT" --go-grpc_opt=module=wingsnet.org/federation \
  $(find "$ROOT/proto/vendored/xray" -name '*.proto' | sort)

# Модель судьи. Отдельным файлом, потому что её версия живёт своей жизнью и
# меняется чаще, чем контракт флота
protoc --proto_path="$ROOT/proto" \
  --go_out="$ROOT" --go_opt=module=wingsnet.org/federation \
  "$ROOT/proto/model.proto"

# Приём от клиента через панель. Отдельно от headpanel.proto нарочно, см.
# комментарий в самом файле
protoc --proto_path="$ROOT/proto" \
  --go_out="$ROOT" --go_opt=module=wingsnet.org/federation \
  --go-grpc_out="$ROOT" --go-grpc_opt=module=wingsnet.org/federation \
  "$ROOT/proto/intake.proto"
