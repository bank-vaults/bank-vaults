ARG GO_VERSION=1.13

FROM golang:${GO_VERSION}-alpine AS builder

RUN apk add --update --no-cache ca-certificates make git curl mercurial

ARG GOPROXY

RUN mkdir -p /build
WORKDIR /build

COPY go.* /build/
COPY pkg/sdk/go.* /build/pkg/sdk/
RUN go mod download

COPY . /build
RUN go mod download

COPY . /go/src/${PACKAGE}
RUN CGO_ENABLED=0 go build ./cmd/vault-env

FROM alpine:3.10

RUN apk add --update --no-cache ca-certificates
COPY --from=builder /build/vault-env /usr/local/bin/vault-env

# Avoid running as root or named user, to satisfy PSPs
USER 65534