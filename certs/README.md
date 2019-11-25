# Generating custom certificates with CFSSL for Bank-Vaults

If you don't wish to use the Helm genereted certificates in the Helm chart, the most easiest way to create a custom certificate for Bank-Vaults is [CFSSL](https://github.com/cloudflare/cfssl).
This directory holds a set of custom CFSSL configurations which are prepared for the Helm release name `vault` in the `default` namespace. Of course you can put any other certificates into the Secret below, this is just a sample.

Create a CA first:

```bash
cfssl genkey -initca csr.json | cfssljson -bare ca
```

Create a server certificate:

```bash
cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=config.json -profile=server server.json | cfssljson -bare server
```

Put these certificates (and the server key) into a Kubernetes Secret:

```bash
kubectl create secret generic vault-tls --from-file=ca.crt=ca.pem --from-file=server.crt=server.pem --from-file=server.key=server-key.pem
```

Install the Vault chart which uses this certificate:

```bash
helm upgrade --install vault ../charts/vault --set tls.secretName=vault-tls
```
