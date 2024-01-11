FROM --platform=$BUILDPLATFORM tonistiigi/xx:1.3.0@sha256:904fe94f236d36d65aeb5a2462f88f2c537b8360475f6342e7599194f291fb7e AS xx

FROM --platform=$BUILDPLATFORM golang:1.21.6-alpine3.18@sha256:869193e7c30611d635c7bc3d1ed879039b7d24710a03474437d402f06825171e AS builder

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

FROM alpine:3.19.0@sha256:51b67269f354137895d43f3b3d810bfacd3945438e94dc5ac55fdac340352f48 AS common

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
