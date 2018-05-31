FROM alpine:3.6

ADD tmp/_output/bin/vault-operator /usr/local/bin/vault-operator

RUN adduser -D vault-operator
USER vault-operator
