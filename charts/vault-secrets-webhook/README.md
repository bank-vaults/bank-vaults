# Vault Secrets webhook

This chart will install a mutating admission webhook, that injects an executable to containers in a deployment/statefulset which than can request secrets from Vault through environment variable definitions.

## Before you start

Before you install this chart you must create a namespace for it, this is due to the order in which the resources in the charts are applied (Helm collects all of the resources in a given Chart and it's dependencies, groups them by resource type, and then installs them in a predefined order (see [here](https://github.com/helm/helm/blob/release-2.10/pkg/tiller/kind_sorter.go#L29) - Helm 2.10).

The `MutatingWebhookConfiguration` gets created before the actual backend Pod which serves as the webhook itself, Kubernetes would like to mutate that pod as well, but it is not ready to mutate yet (infinite recursion in logic).

### Creating the namespace

The namespace must have a label of `name` with the namespace name as it's value.

set the target namespace name or skip for the default name: vswh

```bash
export WEBHOOK_NS=`<namepsace>`
```

```bash
WEBHOOK_NS=${WEBHOOK_NS:-vswh}
echo kubectl create namespace "${WEBHOOK_NS}"
echo kubectl label ns "${WEBHOOK_NS}" name="${WEBHOOK_NS}"
```

## Installing the Chart

```bash
$ helm repo add banzaicloud-stable http://kubernetes-charts.banzaicloud.com/branch/master
$ helm repo update
```

```bash
$ helm upgrade --namespace vswh --install vswh banzaicloud-stable/vault-secrets-webhook
```

## Configuration

The following tables lists configurable parameters of the vault-secrets-webhook chart and their default values.

|               Parameter             |                    Description                    |                  Default                 |
| ----------------------------------- | ------------------------------------------------- | -----------------------------------------|
|affinity                             |affinities to use                                  |{}                                        |
|debug                                |debug logs for webhook                             |false                                     |
|image.pullPolicy                     |image pull policy                                  |IfNotPresent                              |
|image.repository                     |image repo that contains the admission server      |banzaicloud/vault-secrets-webhook         |
|image.tag                            |image tag                                          |latest                                    |
|image.imagePullSecrets               |image pull secrets for private repositories        |[]                                        |
|namespaceSelector                    |namespace selector to use, will limit webhook scope|{}                                        |
|nodeSelector                         |node selector to use                               |{}                                        |
|replicaCount                         |number of replicas                                 |1                                         |
|resources                            |resources to request                               |{}                                        |
|service.externalPort                 |webhook service external port                      |443                                       |
|service.internalPort                 |webhook service external port                      |443                                       |
|service.name                         |webhook service name                               |vault-secrets-webhook                     |
|service.type                         |webhook service type                               |ClusterIP                                 |
|tolerations                          |tolerations to add                                 |[]                                        |
|rabc.enabled                         |use rbac                                           |true                                      |
|rabc.psp.enabled                     |use pod security policy                            |false                                     |
|env.VAULT_IMAGE                      |vault image                                        |vault:latest                              |
|env.VAULT_ENV_IMAGE                  |vault-env image                                    |banzaicloud/vault-env:latest              |
