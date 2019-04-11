ARG GO_VERSION=1.12

FROM golang:${GO_VERSION}-alpine AS builder

RUN apk add --update --no-cache ca-certificates make git curl mercurial

RUN mkdir -p /build
WORKDIR /build

COPY go.* /build/
RUN go mod download

COPY . /build
RUN go install ./cmd/vault-secrets-webhook

FROM alpine:3.9

RUN apk add --update libcap && rm -rf /var/cache/apk/*

COPY --from=builder /go/bin/vault-secrets-webhook /usr/local/bin/vault-secrets-webhook
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

ENV DEBUG false
USER 65534

ENTRYPOINT ["/usr/local/bin/vault-secrets-webhook"]
