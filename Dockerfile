FROM --platform=$BUILDPLATFORM tonistiigi/xx:1.4.0@sha256:0cd3f05c72d6c9b038eb135f91376ee1169ef3a330d34e418e65e2a5c2e9c0d4 AS xx

FROM --platform=$BUILDPLATFORM golang:1.22.3-alpine3.18@sha256:d1a601b64de09e2fa38c95e55838961811d5ca11062a8f4230a5c434b3ae2a34 AS builder

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

FROM alpine:3.20.1@sha256:b89d9c93e9ed3597455c90a0b88a8bbb5cb7188438f70953fede212a0c4394e0 AS common

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
