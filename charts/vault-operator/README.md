# Vault Operator Helm Chart

This directory contains a Kubernetes Helm chart to deploy the Banzai Cloud Vault Operator.

## Prerequisites Details

* Kubernetes 1.6+
* Helm 3

## Chart Details

This chart will do the following:

* Install the Vault operator

Please note that a backend service for Vault (for example, Consul) must
be deployed beforehand and configured with the `vault.config` option. YAML
provided under this option will be converted to JSON for the final vault
`config.json` file.

> See https://github.com/banzaicloud/bank-vaults/tree/main/operator for more information on the Operator
> See https://www.vaultproject.io/docs/configuration/ for more information on storage options for Vault.

## Installing the Chart

### Fresh install

To install the chart on a fresh cluster, use the following:

```bash
helm repo add banzaicloud-stable https://kubernetes-charts.banzaicloud.com
helm upgrade --install vault-operator banzaicloud-stable/vault-operator
```

**Please note that the etcd-operator has been deprecated for a long time (chart and code as well), and the last version of the chart is not installable on Kubernetes 1.22 and onwards. We don't offer any kind of support for etcd-operator and automated etcd installations from now.**

### Helm2 -> Helm3 migration

If you have installed the chart with Helm 2 and now you are trying to upgrade it with Helm3 you have to be careful because Helm 3 will delete the Vault CRD from your cluster during the upgrade from Helm 2 (see https://github.com/helm/helm/issues/7279). To avoid that follow these steps:

```bash
# Make sure you are using Helm 3
helm version

# version.BuildInfo{Version:"v3.3.4", GitCommit:"a61ce5633af99708171414353ed49547cf05013d", GitTreeState:"clean", GoVersion:"go1.14.9"}

# Get the latest vault-operator chart
helm repo add banzaicloud-stable https://kubernetes-charts.banzaicloud.com
helm repo update

# Delete all Helm2 releases of the vault-operator manually wit kubectl to keep the resources in the cluster
kubectl delete configmaps -n kube-system vault-operator.v1
# Delete all resources except the Vault CRD
helm template vault-operator banzaicloud-stable/vault-operator | kubectl delete -f -
# Install the new Helm3 version of the chart
helm upgrade --install vault-operator banzaicloud-stable/charts/vault-operator
```

## Configuration

The following table lists the configurable parameters of the vault chart and their default values.

| Parameter                    | Description                                              | Default                      |
| ---------------------------- | -------------------------------------------------------- | ---------------------------- |
| `image.pullPolicy`           | Container pull policy                                    | `IfNotPresent`               |
| `image.repository`           | Container image to use                                   | `banzaicloud/vault-operator` |
| `image.bankVaultsRepository` | Container image to use for Bank-Vaults                   | `banzaicloud/bank-vaults`    |
| `image.tag`                  | Container image tag to deploy operator in                | `.Chart.AppVersion`          |
| `image.bankVaultsTag`        | Container image tag to deploy bank-vaults in             | `.Chart.AppVersion`          |
| `image.imagePullSecrets`     | Image pull secrets for private repositories              | `[]`                         |
| `replicaCount`               | k8s replicas                                             | `1`                          |
| `resources.requests.cpu`     | Container requested CPU                                  | `100m`                       |
| `resources.requests.memory`  | Container requested memory                               | `128Mi`                      |
| `resources.limits.cpu`       | Container CPU limit                                      | `100m`                       |
| `resources.limits.memory`    | Container memory limit                                   | `256Mi`                      |
| `crdAnnotations`             | Annotations for the Vault CRD                            | `{}`                         |
| `securityContext`            | Container security context for vault-operator deployment | `{}`                         |
| `podSecurityContext`         | Pod security context for vault-operator deployment       | `{}`                         |
| `psp.enabled`                | Deploy PSP resources                                     | `false`                      |
| `psp.vaultSA`                | Used service account for vault                           | `vault`                      |

Specify each parameter using the `--set key=value[,key=value]` argument to `helm install`.

## Using Vault Operator

To deploy different Vault configurations (single node, HA, with AWS unsealing, with etcd backend, ...) see: https://github.com/banzaicloud/bank-vaults/tree/main/operator/deploy for more examples.

```bash
kubectl apply -f https://raw.githubusercontent.com/banzaicloud/bank-vaults/main/operator/deploy/rbac.yaml
kubectl apply -f https://raw.githubusercontent.com/banzaicloud/bank-vaults/main/operator/deploy/cr-raft.yaml
```

Once the Vault pods are ready (in HA setup always one is ready), it can be accessed using a `kubectl port-forward`:

```bash
$ kubectl port-forward vault-pod 8200
$ export VAULT_ADDR=https://127.0.0.1:8200
$ export VAULT_SKIP_VERIFY=true
$ vault status
```

Using as a subchart in helm v2 requires that the CRD be installed first. You can accomplish this by setting crdAnnotations as follows.

```yaml
vault-operator:
  crdAnnotations:
      "helm.sh/hook": crd-install
```

## Credits

Thanks to Cosmin Cojocar for the original Vault Operator Helm chart!
