ARG GO_VERSION=1.11

FROM golang:${GO_VERSION}-alpine AS builder

RUN apk add --update --no-cache ca-certificates make git curl mercurial

ARG PACKAGE=github.com/banzaicloud/bank-vaults

RUN mkdir -p /go/src/${PACKAGE}
WORKDIR /go/src/${PACKAGE}

COPY Gopkg.* Makefile /go/src/${PACKAGE}/
RUN make vendor

COPY . /go/src/${PACKAGE}
RUN go install ./cmd/bank-vaults


FROM alpine:3.7

RUN apk add --no-cache ca-certificates

COPY --from=builder /go/bin/bank-vaults /usr/local/bin/bank-vaults

ENTRYPOINT ["/usr/local/bin/bank-vaults"]
