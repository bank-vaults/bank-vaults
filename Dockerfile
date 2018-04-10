FROM alpine:3.6

RUN apk add --update ca-certificates

COPY bank-vaults_linux_amd64 /usr/local/bin/bank-vaults

ENTRYPOINT ["/usr/local/bin/bank-vaults"]
