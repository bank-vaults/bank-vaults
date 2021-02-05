# Vault Secrets webhook

This chart will install a mutating admission webhook, that injects an executable to containers in Pods which than can request secrets from Vault through environment variable definitions. Also, it can inject statically into ConfigMaps, Secrets, and CustomResources.

## Before you start

Before you install this chart you must create a namespace for it, this is due to the order in which the resources in the charts are applied (Helm collects all of the resources in a given Chart and it's dependencies, groups them by resource type, and then installs them in a predefined order (see [here](https://github.com/helm/helm/blob/release-2.10/pkg/tiller/kind_sorter.go#L29) - Helm 2.10).

The `MutatingWebhookConfiguration` gets created before the actual backend Pod which serves as the webhook itself, Kubernetes would like to mutate that pod as well, but it is not ready to mutate yet (infinite recursion in logic).

## Using External Vault Instances

You will need to add the following annotations to the resources that you wish to mutate:

```yaml
vault.security.banzaicloud.io/vault-addr: https://[URL FOR VAULT]
vault.security.banzaicloud.io/vault-path: [Auth path]
vault.security.banzaicloud.io/vault-role: [Auth role]
vault.security.banzaicloud.io/vault-skip-verify: "true" # Container is missing Trusted Mozilla roots too.
```

Be mindful how you reference Vault secrets itself. For KV v2 secrets, you will need to add the /data/ to the path of the secret.

```
PS C:\> vault kv get kv/rax/test
====== Metadata ======
Key              Value
---              -----
created_time     2019-09-21T16:55:26.479739656Z
deletion_time    n/a
destroyed        false
version          1

=========== Data ===========
Key                    Value
---                    -----
MYSQL_PASSWORD         3xtr3ms3cr3t
MYSQL_ROOT_PASSWORD    s3cr3t
```

The secret shown above is referenced like this:

```
vault:[ENGINE]/data/[SECRET_NAME]#KEY
vault:kv/rax/data/test#MYSQL_PASSWORD
```

If you want to use a specific key version, you can append it after the key so it becomes like this:

`vault:kv/rax/data/test#MYSQL_PASSWORD#1`

Omitting the version will tell Vault to pull the latest version.

## Installing the Chart

**In case of the K8s version is lower than 1.15 the namespace where you install the webhook must have a label of `name` with the namespace name as the label value, so the `namespaceSelector` in the `MutatingWebhookConfiguration` can skip the namespace of the webhook, so no self-mutation takes place. If the K8s version is 1.15 at least, the default `objectSelector` will prevent the self-mutation (you don't have to configure anything) and you are free to install to any namespace of your choice.**.


```bash
# You have to do this only in case you are not using Helm 3.2 or later and Kubernetes 1.15 or later.
WEBHOOK_NS=${WEBHOOK_NS:-vswh}
kubectl create namespace "${WEBHOOK_NS}"
kubectl label ns "${WEBHOOK_NS}" name="${WEBHOOK_NS}"
```

```bash
$ helm repo add banzaicloud-stable https://kubernetes-charts.banzaicloud.com/
$ helm repo update
```

```bash
$ helm upgrade --namespace vswh --install vswh banzaicloud-stable/vault-secrets-webhook --create-namespace
```

**NOTE**: `--wait` is sometimes necessary because of some Helm timing issues, please see [this issue](https://github.com/banzaicloud/banzai-charts/issues/888).

### Openshift 4.3
For security reasons, the `runAsUser` must be in the range between 1000570000 and 1000579999. By setting the value of `securityContext.runAsUser` to "", OpenShift chooses a valid User.

```bash
$ helm upgrade --namespace vswh --install vswh banzaicloud-stable/vault-secrets-webhook --set-string securityContext.runAsUser="" --create-namespace
```

### About GKE Private Clusters

When Google configure the control plane for private clusters, they automatically configure VPC peering between your Kubernetes cluster’s network in a separate Google managed project.

The auto-generated rules **only** open ports 10250 and 443 between masters and nodes. This means that to use the webhook component with a GKE private cluster, you must configure an additional firewall rule to allow your masters CIDR to access your webhook pod using the port 8443.

You can read more information on how to add firewall rules for the GKE control plane nodes in the [GKE docs](https://cloud.google.com/kubernetes-engine/docs/how-to/private-clusters#add_firewall_rules).

## Configuration

The following tables lists configurable parameters of the vault-secrets-webhook chart and their default values:

| Parameter                        | Description                                                                  | Default                             |
|----------------------------------|------------------------------------------------------------------------------|-------------------------------------|
| affinity                         | affinities to use                                                            | `{}`                                |
| debug                            | debug logs for webhook                                                       | `false`                             |
| image.pullPolicy                 | image pull policy                                                            | `IfNotPresent`                      |
| image.repository                 | image repo that contains the admission server                                | `ghcr.io/banzaicloud/vault-secrets-webhook` |
| image.tag                        | image tag                                                                    | `.Chart.AppVersion`                 |
| image.imagePullSecrets           | image pull secrets for private repositories                                  | `[]`                                |
| vaultEnv.repository             | image repo that contains the vault-env container                              | `ghcr.io/banzaicloud/vault-env`     |
| namespaceSelector                | namespace selector to use, will limit webhook scope                          | `{}`                                |
| objectSelector                | object selector to use, will limit webhook scope (K8s version 1.15+)            | `{}`                                |
| nodeSelector                     | node selector to use                                                         | `{}`                                |
| labels                           | extra labels to add to the deployment and pods                               | `{}`                                |
| podAnnotations                   | extra annotations to add to pod metadata                                     | `{}`                                |
| replicaCount                     | number of replicas                                                           | `2`                                 |
| resources                        | resources to request                                                         | `{}`                                |
| service.externalPort             | webhook service external port                                                | `443`                               |
| service.name                     | webhook service name                                                         | `vault-secrets-webhook`             |
| service.type                     | webhook service type                                                         | `ClusterIP`                         |
| tolerations                      | tolerations to add                                                           | `[]`                                |
| rbac.psp.enabled                 | use pod security policy                                                      | `false`                             |
| rbac.authDelegatorRole.enabled    | bind `system:auth-delegator` to the ServiceAccount                          | `false`                             |
| env.VAULT_IMAGE                  | vault image                                                                  | `vault:1.6.2`                       |
| volumes                          | extra volume definitions                                                     | `[]`                                |
| volumeMounts                     | extra volume mounts                                                          | `[]`                                |
| configMapMutation                | enable injecting values from Vault to ConfigMaps                             | `false`                             |
| customResourceMutations         | list of CustomResources to inject values from Vault                           | `[]`                                |
| podDisruptionBudget.enabled      | enable PodDisruptionBudget                                                   | `false`                             |
| podDisruptionBudget.minAvailable | represents the number of Pods that must be available (integer or percentage) | `1`                                 |
| certificate.generate             | should a new CA and TLS certificate be generated for the webhook             | `true`                              |
| certificate.useCertManager       | should request cert-manager for getting a new CA and TLS certificate         | `false`                             |
| certificate.servingCertificate   | should use an already externally defined Certificate by cert-manager         | `null`                              |
| certificate.ca.crt               | Base64 encoded CA certificate                                                | ``                                  |
| certificate.server.tls.crt       | Base64 encoded TLS certificate signed by the CA                              | ``                                  |
| certificate.server.tls.key       | Base64 encoded  private key of TLS certificate signed by the CA              | ``                                  |
| apiSideEffectValue               | Webhook sideEffect value                                                     | `NoneOnDryRun`                      |
| securityContext                  | Container security context for webhook deployment                            | `{ runAsUser: 65534, allowPrivaledgeEscalation: false }` |
| podSecurityContext               | Pod security context for webhook deployment                                  | `{}`                                |
| timeoutSeconds                   | Webhook timeoutSeconds value                                                 | ``                                  |
| hostNetwork                      | allow pod to use the node network namespace                                  | `false`                             |

### Certificate options

There are the following options for suppling the webhook with CA and TLS certificates.

#### Generate (default)

The default option is to let helm generate the CA and TLS certificates on deploy time.

This will renew the certificates on each deployment.

```
certificate:
    generate: true
```

#### Manually supplied

Another option is to generate everything manually and specify the TLS `crt` and `key` plus the CA `crt` as values.
These values need to be base64 encoded x509 certificates.

```yaml
certificate:
  generate: false
  server:
    tls:
      crt: LS0tLS1...
      key: LS0tLS1...
  ca:
    crt: LS0tLS1...
```

#### Using cert-manager

If you use cert-manager in your cluster, you can instruct cert-manager to manage everything.
The following options will let cert-manager generate TLS `certificate` and `key` plus the CA `certificate`.

```yaml
certificate:
  generate: false
  useCertManager: true
```
