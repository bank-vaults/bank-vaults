# Vault Secrets webhook

This chart will install a mutating admission webhook, that injects an executable to containers in a deployment/statefulset which than can request secrets from Vault through environment variable definitions.

## Before you start

Before you install this chart you must create a namespace for it, this is due to the order in which the resources in the charts are applied (Helm collects all of the resources in a given Chart and it's dependencies, groups them by resource type, and then installs them in a predefined order (see [here](https://github.com/helm/helm/blob/release-2.10/pkg/tiller/kind_sorter.go#L29) - Helm 2.10).

The `MutatingWebhookConfiguration` gets created before the actual backend Pod which serves as the webhook itself, Kubernetes would like to mutate that pod as well, but it is not ready to mutate yet (infinite recursion in logic).

### Creating the namespace

The namespace must have a label of `name` with the namespace name as it's value.

set the target namespace name or skip for the default name: vswh

```bash
export WEBHOOK_NS=`<namespace>`
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
$ helm upgrade --namespace vswh --install vswh banzaicloud-stable/vault-secrets-webhook --wait
```

**NOTE**: `--wait` is necessary because of Helm timing issues, please see [this issue](https://github.com/banzaicloud/banzai-charts/issues/888).

### About GKE Private Clusters
When Google configure the control plane for private clusters, they automatically configure VPC peering between your Kubernetes cluster’s network in a separate Google managed project.

The auto-generated rules **only** open ports 10250 and 443 between masters and nodes. This means that in order to use the webhook component with a GKE private cluster, you must configure an additional firewall rule to allow your masters CIDR to access your webhook pod using the port 8443.

You can read more information on how to add firewall rules for the GKE control plane nodes in the [GKE docs](https://cloud.google.com/kubernetes-engine/docs/how-to/private-clusters#add_firewall_rules).
## Configuration

The following tables lists configurable parameters of the vault-secrets-webhook chart and their default values:

| Parameter              | Description                                         | Default                           |
| ---------------------- | --------------------------------------------------- | --------------------------------- |
| affinity               | affinities to use                                   | {}                                |
| debug                  | debug logs for webhook                              | false                             |
| image.pullPolicy       | image pull policy                                   | IfNotPresent                      |
| image.repository       | image repo that contains the admission server       | banzaicloud/vault-secrets-webhook |
| image.tag              | image tag                                           | latest                            |
| image.imagePullSecrets | image pull secrets for private repositories         | []                                |
| namespaceSelector      | namespace selector to use, will limit webhook scope | {}                                |
| nodeSelector           | node selector to use                                | {}                                |
| podAnnotations         | extra annotations to add to pod metadata            | {}                                |
| replicaCount           | number of replicas                                  | 1                                 |
| resources              | resources to request                                | {}                                |
| service.externalPort   | webhook service external port                       | 443                               |
| service.name           | webhook service name                                | vault-secrets-webhook             |
| service.type           | webhook service type                                | ClusterIP                         |
| tolerations            | tolerations to add                                  | []                                |
| rbac.enabled           | use rbac                                            | true                              |
| rbac.psp.enabled       | use pod security policy                             | false                             |
| env.VAULT_IMAGE        | vault image                                         | vault:latest                      |
| env.VAULT_ENV_IMAGE    | vault-env image                                     | banzaicloud/vault-env:latest      |
| volumes                | extra volume definitions                            | []                                |
| volumeMounts           | extra volume mounts                                 | []                                |
| configMapMutation      | enable injecting values from Vault to ConfigMaps    | false                             |
