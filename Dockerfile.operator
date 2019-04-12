ARG GO_VERSION=1.12

FROM golang:${GO_VERSION}-alpine AS builder

RUN apk add --update --no-cache ca-certificates make git curl mercurial

RUN mkdir -p /build
WORKDIR /build

COPY go.* /build/
RUN go mod download

COPY . /build
RUN go install ./operator/cmd/manager


FROM alpine:3.9

RUN apk add --no-cache ca-certificates

COPY --from=builder /go/bin/manager /usr/local/bin/vault-operator

USER 65534

ENTRYPOINT ["/usr/local/bin/vault-operator"]
