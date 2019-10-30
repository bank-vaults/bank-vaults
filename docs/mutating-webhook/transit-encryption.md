# Transit Encryption

The transit secrets engine handles cryptographic functions on data in-transit. Vault doesn't store the data sent to the secrets engine. It can also be viewed as "cryptography as a service" or "encryption as a service". Detailed information about transit encryption can be found in [official documentation](https://www.vaultproject.io/docs/secrets/transit/index.html).

Currently transit encryption supported only on PODs mutation, Secrets and ConfigMaps will be supported in near future.

## Example

Enable the Transit secrets engine:

```bash
vault secrets enable transit
```

Create a named encryption key:

```bash
vault write -f transit/keys/my-key
```

Encrypt data with encryption key:

```bash
vault write transit/encrypt/my-key plaintext=$(base64 <<< "my secret data")
```

This deployment will be mutated by the webhook, since it has at least one environment variable having a value which is encrypted by Vault:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: vault-test
spec:
  replicas: 1
  selector:
    matchLabels:
      app.kubernetes.io/name: vault
  template:
    metadata:
      labels:
        app.kubernetes.io/name: vault
      annotations:
        vault.security.banzaicloud.io/vault-addr: "https://vault:8200" # optional, the address of the Vault service, default values is https://vault:8200
        vault.security.banzaicloud.io/vault-role: "default" # optional, the default value is the name of the ServiceAccount the Pod runs in, in case of Secrets and ConfigMaps it is "default"
        vault.security.banzaicloud.io/vault-skip-verify: "false" # optional, skip TLS verification of the Vault server certificate
        vault.security.banzaicloud.io/vault-tls-secret: "vault-tls" # optinal, the name of the Secret where the Vault CA cert is, if not defined it is not mounted
        vault.security.banzaicloud.io/vault-agent: "false" # optional, if true, a Vault Agent will be started to do Vault authentication, by default not needed and vault-env will do Kubernetes Service Account based Vault authentication
        vault.security.banzaicloud.io/vault-path: "kubernetes" # optional, the Kubernetes Auth mount path in Vault the default value is "kubernetes"
        vault.security.banzaicloud.io/transit-key-id: "my-key" # required if encrypted data was found; transit key id that created before
    spec:
      serviceAccountName: default
      containers:
      - name: alpine
        image: alpine
        command: ["sh", "-c", "echo $AWS_SECRET_ACCESS_KEY && echo going to sleep... && sleep 10000"]
        env:
        - name: AWS_SECRET_ACCESS_KEY
          # Value based on encrypted key that stored in Vault, so value from this example
          # not the same as you can get after `encrypt`
          value: vault:v1:8SDd3WHDOjf7mq69CyCqYjBXAiQQAVZRkFM13ok481zoCmHnSeDX9vyf7w==
```
