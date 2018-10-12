# Vault Operator

This directory holds the code of the Banzai Cloud Vault Operator.

## Build

```bash
cd operator
operator-sdk build banzaicloud/vault-operator
```

## Deploying the operator

Some deployment *samples* can be found at the projects `operator/deploy` directory:

```bash
kubectl apply -f operator/deploy/rbac.yaml     # If you have an RBAC enabled cluster
kubectl apply -f operator/deploy/operator.yaml
```

This will create a Kubernetes `CustomResourceDefinition` called Vault. A documented example of this CRD can be found in operator/deploy/cr.yaml:

```bash
kubectl apply -f operator/deploy/cr.yaml
```

## HA setup with etcd

Additionally you have to deploy the [etcd-operator](https://github.com/coreos/etcd-operator) to the cluster as well:

```bash
kubectl apply -f operator/deploy/etcd-rbac.yaml
kubectl apply -f operator/deploy/etcd-operator.yaml
```

Now deploy a HA vault which connects to an etcd storage backend:

```bash
kubectl apply -f operator/deploy/cr-etcd-ha.yaml
```

From now on, if you deploy a Vault CRD into the cluster which has an [Etcd Storage Backend](https://www.vaultproject.io/docs/configuration/storage/etcd.html) defined in its configuration the Vault operator will create an EtcdCluster CRD for the Vault instance, and the etcd-operator will orchestrate the etcd cluster. After the etcd cluster is ready the Vault instance can connect to it and will start up. If the Vault CRD is deleted from the cluster the etcd cluster will be GCd as well. You have to make sure you define backup and restore for the etcd cluster to prevent data loss, this part is not handled by the Vault operator, see [this](https://github.com/coreos/etcd-operator#backup-and-restore-an-etcd-cluster) document for more details.

## Use existing etcd

If you want to use an existing etcd. You can set `etcdSize` vault to < 0. Then it won't create a new etcd.
And all config under etcd storage will not be override.
