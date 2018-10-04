FROM golang:1.11-alpine as golang
RUN apk add --update --no-cache ca-certificates curl git make
RUN mkdir -p /go/src/github.com/banzaicloud/bank-vaults
ADD Gopkg.* Makefile /go/src/github.com/banzaicloud/bank-vaults/
WORKDIR /go/src/github.com/banzaicloud/bank-vaults
RUN make vendor
ADD . /go/src/github.com/banzaicloud/bank-vaults
RUN go install ./operator/cmd/vault-operator


FROM alpine:3.7
RUN apk add --no-cache ca-certificates
COPY --from=golang /go/bin/vault-operator /usr/local/bin/vault-operator
RUN adduser -D vault-operator
USER vault-operator
ENTRYPOINT ["/usr/local/bin/vault-operator"]
