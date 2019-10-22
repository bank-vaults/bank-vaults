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
RUN go install ./cmd/template
RUN go install ./cmd/bank-vaults


FROM alpine:3.10

RUN apk add --no-cache ca-certificates

COPY --from=builder /go/bin/template /usr/local/bin/template
COPY --from=builder /go/bin/bank-vaults /usr/local/bin/bank-vaults
USER 65534

ENTRYPOINT ["/usr/local/bin/bank-vaults"]
