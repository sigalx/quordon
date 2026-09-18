FROM golang:1.26-alpine AS build

ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
COPY third_party/go-sql-driver/mysql/go.mod ./third_party/go-sql-driver/mysql/go.mod
COPY third_party/go-yaml/go.mod ./third_party/go-yaml/go.mod
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/quordon ./cmd/quordon

FROM alpine:3.23

RUN apk add --no-cache ca-certificates \
    && addgroup -S quordon \
    && adduser -S -G quordon -H -s /sbin/nologin quordon
COPY --from=build /out/quordon /usr/local/bin/quordon

USER quordon:quordon
EXPOSE 8080
ENV QUORDON_LISTEN=:8080
ENTRYPOINT ["/usr/local/bin/quordon"]
