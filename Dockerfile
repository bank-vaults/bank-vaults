FROM --platform=$BUILDPLATFORM tonistiigi/xx:1.5.0@sha256:0c6a569797744e45955f39d4f7538ac344bfb7ebf0a54006a0a4297b153ccf0f AS xx

FROM --platform=$BUILDPLATFORM golang:1.23.2-alpine3.20@sha256:9dd2625a1ff2859b8d8b01d8f7822c0f528942fe56cfe7a1e7c38d3b8d72d679 AS builder

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

FROM alpine:3.20.3@sha256:beefdbd8a1da6d2915566fde36db9db0b524eb737fc57cd1367effd16dc0d06d AS common

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
