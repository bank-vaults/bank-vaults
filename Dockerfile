FROM --platform=$BUILDPLATFORM tonistiigi/xx:1.2.1@sha256:8879a398dedf0aadaacfbd332b29ff2f84bc39ae6d4e9c0a1109db27ac5ba012 AS xx

FROM --platform=$BUILDPLATFORM golang:1.20.4-alpine3.16@sha256:6469405d7297f82d56195c90a3270b0806ef4bd897aa0628477d9959ab97a577 AS builder

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
