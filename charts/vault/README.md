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
helm install banzaicloud-stable/vault
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
| `image.tag`             | Container image tag to deploy       | `1.6.2`                                             |
| `ingress.enabled`       | Enables Ingress                     | `false`                                             |
| `ingress.annotations`   | Ingress annotations                 | `{}`                                                |
| `ingress.hosts`         | Ingress accepted hostnames with path| `[]`                                                |
| `ingress.tls`           | Ingress TLS configuration           | `[]`                                                |
| `vault.envs`            | Custom environment variables available to Vault | `[]`                                    |
| `vault.customSecrets`   | Custom secrets available to Vault   | `[]`                                                |
| `vault.envSecrets`      | Custom secrets available to Vault as env vars | `[]`                                      |
| `vault.config`          | Vault configuration                 | No default backend                                  |
| `vault.externalConfig`  | Vault API based configuration       | No default backend                                  |
| `replicaCount`          | k8s replicas                        | `1`                                                 |
| `resources.limits.cpu`  | Container requested CPU             | `nil`                                               |
| `resources.limits.memory` | Container requested memory        | `nil`                                               |
| `unsealer.args`         | Bank Vaults args                    | `["--mode", "k8s", "--k8s-secret-namespace", "default", "--k8s-secret-name", "bank-vaults"]` |
| `unsealer.image.tag`    | Bank Vaults image tag               | `.Chart.AppVersion`                                 |
| `rbac.psp.enabled`      | Use pod security policy             | `false`                                             |
| `nodeSelector`          | Node labels for pod assignment. https://kubernetes.io/docs/concepts/configuration/assign-pod-node/#nodeselector                                                   | `{}`                                                |
| `tolerations`           | List of node tolerations for the pods. https://kubernetes.io/docs/concepts/configuration/taint-and-toleration/                                                           | `[]`                                |
| `affinity`           | Node affinity settings for the pods. https://kubernetes.io/docs/concepts/scheduling-eviction/assign-pod-node/                                                          |  If not set it defaults to`podAntiAffinity` to `preferredDuringSchedulingIgnoredDuringExecution` |
| `labels`                | Additonal labels to be applied to the Vault StatefulSet and Pods | `{}`                   |
| `tls.secretName`        | Custom TLS certifcate secret name    | `""`                                               |

Specify each parameter using the `--set key=value[,key=value]` argument to `helm install`.

## Using Vault

Once the Vault pod is ready, it can be accessed using `kubectl port-forward`:

```bash
$ kubectl port-forward vault-pod 8200
$ export VAULT_ADDR=http://127.0.0.1:8200
$ vault status
```
## OpenShift Implementation

Tested with
* OpenShift Container Platform 3.11
* Helm 3

First create a new project named "vault"
```bash
oc new-app vault
```
Then create a new `scc` based on the `scc` restricted and add the capability "IPC_LOCK". Now add the new scc to the ServiceAccount vault of the new vault project:
```bash
oc adm policy add-scc-to-user <new_scc> system:serviceaccount:vault:vault
```

Or you can define users in `scc` directly and in this case, you only have to create the `scc`.
```
oc create -f <scc_file.yaml>
```

Example vault-restricted `scc` with defined user:
```yaml
apiVersion: security.openshift.io/v1
kind: SecurityContextConstraints
metadata:
  name: vault-restricted
  annotations:
    kubernetes.io/description: This is the least privileged SCC and it is used by vault users.
allowHostIPC: true
allowHostDirVolumePlugin: false
allowHostNetwork: false
allowHostPID: false
allowHostPorts: false
allowPrivilegeEscalation: true
allowPrivilegedContainer: false
defaultAddCapabilities: null
allowedCapabilities:
- IPC_LOCK
allowedUnsafeSysctls: null
fsGroup:
  type: RunAsAny
priority: null
readOnlyRootFilesystem: false
requiredDropCapabilities:
- KILL
- MKNOD
runAsUser:
  type: RunAsAny
seLinuxContext:
  type: MustRunAs
supplementalGroups:
  type: RunAsAny
volumes:
- configMap
- downwardAPI
- emptyDir
- persistentVolumeClaim
- projected
- secret
users:
- system:serviceaccount:default:vault
```

You will get the message, that the user system:serviceaccount:vault:vault doesn't exist, but that's ok.
In the next step you install the helm chart vault in the namespace "vault" with the following command:

```bash
helm install vault banzaicloud-stable/vault --set "unsealer.args[0]=--mode" --set "unsealer.args[1]=k8s" --set "unsealer.args[2]=--k8s-secret-namespace" --set "unsealer.args[3]=vault" --set "unsealer.args[4]=--k8s-secret-name" --set "unsealer.args[5]=bank-vaults"
```

Changing the values of the arguments of the unsealer is necessary because in the values.yaml the default namespace is used to store the secret. Creating the secret in the same namespace like vault is the easiest solution. In alternative you can create a role which allows creating and read secrets in the default namespace.
