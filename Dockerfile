FROM --platform=$BUILDPLATFORM tonistiigi/xx:1.3.0@sha256:904fe94f236d36d65aeb5a2462f88f2c537b8360475f6342e7599194f291fb7e AS xx

FROM --platform=$BUILDPLATFORM golang:1.21.3-alpine3.18@sha256:7fdfef9fb8674808f374632e3090605fef56a1e6c397cc3f7c451244eb46e253 AS builder

COPY --from=xx / /

RUN apk add --update --no-cache ca-certificates make git curl clang lld

ARG TARGETPLATFORM

RUN xx-apk --update --no-cache add musl-dev gcc

RUN xx-go --wrap

WORKDIR /usr/local/src/bank-vaults

ARG GOPROXY

ENV CGO_ENABLED=1

COPY go.* ./
RUN go mod download

COPY . .

RUN go build -o /usr/local/bin/bank-vaults ./cmd/bank-vaults/
RUN xx-verify /usr/local/bin/bank-vaults

RUN go build -o /usr/local/bin/template ./cmd/template/
RUN xx-verify /usr/local/bin/template

FROM alpine:3.18.4@sha256:eece025e432126ce23f223450a0326fbebde39cdf496a85d8c016293fc851978 AS common

RUN apk add --update --no-cache ca-certificates tzdata

# Install tools for accessing smart cards
RUN apk add --no-cache ccid opensc pcsc-lite-libs

COPY --from=builder /usr/local/bin/bank-vaults /usr/local/bin/bank-vaults
COPY --from=builder /usr/local/bin/template /usr/local/bin/template
COPY --from=builder /usr/local/src/bank-vaults/scripts/pcscd-entrypoint.sh /usr/local/bin/pcscd-entrypoint.sh

ENTRYPOINT ["bank-vaults"]

FROM common AS softhsm

RUN apk add --no-cache softhsm

USER 65534

# Initializing SoftHSM to be able to create a working example (only for dev),
# sharing the HSM device is emulated with a pre-created keypair in the image.
RUN softhsm2-util --init-token --free --label bank-vaults --so-pin bank-vaults --pin bank-vaults
RUN pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so --keypairgen --key-type rsa:2048 --pin bank-vaults --token-label bank-vaults --label bank-vaults

FROM common

USER 65534
