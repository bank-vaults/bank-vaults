ARG GO_VERSION=1.12

FROM golang:${GO_VERSION}-alpine AS builder

RUN apk add --update --no-cache ca-certificates make git curl mercurial

RUN mkdir -p /build
WORKDIR /build

COPY go.* /build/
RUN go mod download

COPY . /build
RUN go mod download

COPY . /go/src/${PACKAGE}
RUN CGO_ENABLED=0 go install ./cmd/vault-env


FROM vault:1.1.0

COPY --from=builder /go/bin/vault-env /usr/local/bin/vault-env
