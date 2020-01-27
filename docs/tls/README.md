# TLS

Bank-Vaults tries to automates as much as possible for handling TLS certificates.

- The `vault-operator` automates the creation and renewal of TLS certificates for Vault.
- The `vault` Helm Chart automates the creation only of TLS certificates for Vault via [Sprig](https://masterminds.github.io/sprig/crypto.html).

The operator and the chart as well generates one Kubernetes Secret holding the TLS certificates, this is named `${VAULT_CR_NAME}-tls` (in `vault-tls` in most examples in this repo):

The Secret data keys are:
- `ca.crt`
- `server.crt`
- `server.key`

The operator doesn't overwrite this Secret holding the certificate if it already exists, so you can provide this certificate in any other way, for example using [cert-manager](https://cert-manager.io/) or simply placing it there manually.

## Operator custom TLS settings

There are some attributes that can influence the TLS settings in the operator:

```go
    // TLSExpiryThreshold is the Vault TLS certificate expiration threshold in Go's Duration format.
    // default: 168h
    TLSExpiryThreshold *time.Duration `json:"tlsExpiryThreshold,omitempty"`

    // TLSAdditionalHosts is a list of additional hostnames or IP addresses to add to the SAN on the automatically generated TLS certificate.
    // default:
    TLSAdditionalHosts []string `json:"tlsAdditionalHosts,omitempty"`

    // CANamespaces define a list of namespaces where the generated CA certificate for Vault should be distributed,
    // use ["*"] for all namespaces.
    // default:
    CANamespaces []string `json:"caNamespaces,omitempty"`
```

## Generating custom certificates with CFSSL for Bank-Vaults

If you don't wish to use the Helm or Operator genereted certificates the most easiest way to create a custom certificate for Bank-Vaults is [CFSSL](https://github.com/cloudflare/cfssl).
This directory holds a set of custom CFSSL configurations which are prepared for the Helm release name `vault` in the `default` namespace. Of course you can put any other certificates into the Secret below, this is just an example:

1. Create a CA first:

```bash
cfssl genkey -initca csr.json | cfssljson -bare ca
```

2. Create a server certificate:

```bash
cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=config.json -profile=server server.json | cfssljson -bare server
```

3. Put these certificates (and the server key) into a Kubernetes Secret:

```bash
kubectl create secret generic vault-tls --from-file=ca.crt=ca.pem --from-file=server.crt=server.pem --from-file=server.key=server-key.pem
```

4.  Install the Vault:

- With the chart which uses this certificate:

```bash
helm upgrade --install vault ../charts/vault --set tls.secretName=vault-tls
```

- With the operator:

```bash
kubectl apply -f vault-cr.yaml
```
