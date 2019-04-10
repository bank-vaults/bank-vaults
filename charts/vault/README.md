# Vault Helm Chart

This directory contains a Kubernetes Helm chart to deploy a Vault server. For further details of how are we using Vault read this [post](https://banzaicloud.com/blog/oauth2-vault/).

## Prerequisites Details

* Kubernetes 1.6+

## Chart Details

This chart will do the following:

* Implement a Vault deployment

Please note that a backend service for Vault (for example, Consul) must
be deployed beforehand and configured with the `vault.config` option. YAML
provided under this option will be converted to JSON for the final vault
`config.json` file.

Please also note that scaling to more than 1 replicas can be made successfully only with a configured HA Storage backend. By default this chart uses `file` backend, which is not HA.

> See https://www.vaultproject.io/docs/configuration/ for more information.

## Installing the Chart

To install the chart, use the following, this backs Vault with a Consul cluster:

```bash
helm init -c; 
helm repo add banzaicloud-stable http://kubernetes-charts.banzaicloud.com/branch/master
helm install vault
```

To install the chart backed with a Consul cluster, use the following:

```bash
helm install banzaicloud-stable/vault --set vault.config.storage.consul.address="myconsul-svc-name:8500",vault.config.storage.consul.path="vault"
```

An alternative `values.yaml` example using the Amazon S3 backend can be specified using:

```yaml
vault:
  config:
    storage:
      s3:
        access_key: "AWS-ACCESS-KEY"
        secret_key: "AWS-SECRET-KEY"
        bucket: "AWS-BUCKET"
        region: "eu-central-1"
```

An alternate example using Amazon custom secrets passed as environment variables to Vault:

```bash
# Create an aws secret with your AWS credentials
kubectl create secret generic aws --from-literal=AWS_ACCESS_KEY_ID=$AWS_ACCESS_KEY_ID --from-literal=AWS_SECRET_ACCESS_KEY=$AWS_SECRET_ACCESS_KEY

# Tell the chart to pass these as env vars to Vault and as a file mount if needed
helm install banzaicloud-stable/vault --set "vault.customSecrets[0].secretName=aws" --set "vault.customSecrets[0].mountPath=/vault/aws"
```

## Google Storage and KMS example

You can set up Vault to use Google KMS for sealing and Google Storage for storing your encrypted secrets. See the usage example below: 

```
# Create a google secret with your Secret Account Key file in json fromat.
kubectl create secret generic google --from-literal=GOOGLE_APPLICATION_CREDENTIALS=/etc/gcp/service-account.json --from-file=service-account.json=./service-account.json

# Tell the chart to pass these vars to Vault and as a file mount if needed
helm install banzaicloud-stable/vault \
--set "vault.customSecrets[0].secretName=google" \
--set "vault.customSecrets[0].mountPath=/etc/gcp" \
--set "vault.config.storage.gcs.bucket=[google-bucket-name]" \
--set "vault.config.seal.gcpckms.project=[google-project-id]" \
--set "vault.config.seal.gcpckms.region=[google-kms-region]" \
--set "vault.config.seal.gcpckms.key_ring=[google-kms-key-ring]" \
--set "vault.config.seal.gcpckms.crypto_key=[google-kms-crypto-key]" \
--set "unsealer.args[0]=--mode" \
--set "unsealer.args[1]=google-cloud-kms-gcs" \
--set "unsealer.args[2]=--google-cloud-kms-key-ring" \
--set "unsealer.args[3]=[google-kms-key-ring]" \
--set "unsealer.args[4]=--google-cloud-kms-crypto-key" \
--set "unsealer.args[5]=[google-kms-crypto-key]" \
--set "unsealer.args[6]=--google-cloud-kms-location" \
--set "unsealer.args[7]=global" \
--set "unsealer.args[8]=--google-cloud-kms-project" \
--set "unsealer.args[9]=[google-project-id]" \
--set "unsealer.args[10]=--google-cloud-storage-bucket" \
--set "unsealer.args[11]=[google-bucket-name]"
```

## Vault HA with MySQL backend

You can set up a HA Vault to use MySQL for storing your encrypted secrets. MySQL supports the HA coordination of Vault, see the [official docs](https://www.vaultproject.io/docs/configuration/storage/mysql.html) for more details.

See the complete working Helm example below:

```bash
# Install MySQL first with the official Helm chart, tell to create a user and a database called 'vault':
helm install --name mysql stable/mysql --set mysqlUser=vault --set mysqlDatabase=vault

# Install the Vault chart, tell it to use MySQL as the storage backend, also specify where the 'vault' user's password should be coming from (the MySQL chart generates a secret called 'mysql' holding the password):
helm install --name vault banzaicloud-stable/vault \
--set replicaCount=2 \
--set vault.config.storage.mysql.address=mysql:3306 \
--set vault.config.storage.mysql.username=vault \
--set vault.config.storage.mysql.password="[[.Env.MYSQL_PASSWORD]]" \
--set "vault.envSecrets[0].secretName=mysql" \
--set "vault.envSecrets[0].secretKey=mysql-password" \
--set "vault.envSecrets[0].envName=MYSQL_PASSWORD"
```

## Configuration

The following tables lists the configurable parameters of the vault chart and their default values.

|       Parameter         |           Description               |                         Default                     |
|-------------------------|-------------------------------------|-----------------------------------------------------|
| `image.pullPolicy`      | Container pull policy               | `IfNotPresent`                                      |
| `image.repository`      | Container image to use              | `vault`                                             |
| `image.tag`             | Container image tag to deploy       | `1.0.3`                                             |
| `vault.customSecrets`   | Custom secrets available to Vault   | `[]`                                                |
| `vault.envSecrets`      | Custom secrets available to Vault as env vars | `[]`                                    |
| `vault.config`          | Vault configuration                 | No default backend                                  |
| `vault.externalConfig`  | Vault API based configuration       | No default backend                                  |
| `replicaCount`          | k8s replicas                        | `1`                                                 |
| `resources.limits.cpu`  | Container requested CPU             | `nil`                                               |
| `resources.limits.memory` | Container requested memory        | `nil`                                               |
| `unsealer.args`         | Bank Vaults args | `["--mode", "k8s", "--k8s-secret-namespace", "default", "--k8s-secret-name", "bank-vaults"]` |

Specify each parameter using the `--set key=value[,key=value]` argument to `helm install`.

## Using Vault

Once the Vault pod is ready, it can be accessed using a `kubectl
port-forward`:

```bash
$ kubectl port-forward vault-pod 8200
$ export VAULT_ADDR=http://127.0.0.1:8200
$ vault status
```
