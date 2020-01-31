# Backing up Vault

The vault-operator has support for backing up the cluster with Velero.

## Velero

First, in this example we will install [Velero](https://velero.io/) on the target cluster with Helm:

Add the Velero Helm repository:

```bash
helm repo add vmware-tanzu https://vmware-tanzu.github.io/helm-charts
```

Create a namespace for Velero:

```bash
kubectl create namespace velero
```

Install Velero with [Restic](https://restic.net/) so we get PV snapshots as well (in this example we use AWS), I have created a bucket called `bank-vaults-velero` in the Stockholm region beforehand:

```bash
BUCKET=bank-vaults-velero
REGION=eu-north-1
KMS_KEY_ID=alias/bank-vaults-velero
SECRET_FILE=~/.aws/credentials

helm upgrade --install velero --namespace velero \
          --set configuration.provider=aws \
          --set-file credentials.secretContents.cloud=${SECRET_FILE} \
          --set deployRestic=true \
          --set configuration.backupStorageLocation.name=aws \
          --set configuration.backupStorageLocation.bucket=${BUCKET} \
          --set configuration.backupStorageLocation.config.region=${REGION} \
          --set configuration.backupStorageLocation.config.kmsKeyId=${KMS_KEY_ID} \
          --set configuration.volumeSnapshotLocation.name=aws \
          --set configuration.volumeSnapshotLocation.config.region=${REGION} \
          --set "initContainers[0].name"=velero-plugin-for-aws \
          --set "initContainers[0].image"=velero/velero-plugin-for-aws:v1.0.0 \
          --set "initContainers[0].volumeMounts[0].mountPath"=/target \
          --set "initContainers[0].volumeMounts[0].name"=plugins \
          vmware-tanzu/velero
```

Install the vault-operator to the cluster:

```bash
helm upgrade --install vault-operator banzaicloud-stable/vault-operator
```

```bash
kubectl apply -f operator/deploy/rbac.yaml
kubectl apply -f operator/deploy/cr-raft.yaml
```

NOTE: The Vault CR in cr-raft.yaml has a special flag called `veleroEnabled`,
this is useful for file-based Vault storage backends (`file`, `raft`), please
see https://velero.io/docs/v1.2.0/hooks/:

```yaml
  # Add Velero fsfreeze sidecar container and supporting hook annotations to Vault Pods:
  # https://velero.io/docs/v1.2.0/hooks/
  veleroEnabled: true
```

Create a backup with the Velero CLI or with the predefined Velero Backup CR:

```bash
velero backup create --selector vault_cr=vault vault-1

# OR

kubectl apply -f docs/backup/backup.yaml
```

Check that the Velero backup got created successfully:

```bash
velero backup describe --details vault-1
```

Output:

```
Name:         vault-1
Namespace:    velero
Labels:       velero.io/backup=vault-1
              velero.io/pv=pvc-6eb4d9c1-25cd-4a28-8868-90fa9d51503a
              velero.io/storage-location=default
Annotations:  <none>

Phase:  Completed

Namespaces:
  Included:  *
  Excluded:  <none>

Resources:
  Included:        *
  Excluded:        <none>
  Cluster-scoped:  auto

Label selector:  vault_cr=vault

Storage Location:  default

Snapshot PVs:  auto

TTL:  720h0m0s

Hooks:  <none>

Backup Format Version:  1

Started:    2020-01-29 14:17:41 +0100 CET
Completed:  2020-01-29 14:17:45 +0100 CET

Expiration:  2020-02-28 14:17:41 +0100 CET
```

Remove Vault entirely from the cluster (emulate a catastrophe!):

```bash
kubectl delete vault -l vault_cr=vault
kubectl delete pvc -l vault_cr=vault
```

Now we will restore Vault from the backup

Scale down the vault-operator, so it won't reconcile during the restore process (it is advised):

```bash
kubectl scale deployment vault-operator --replicas 0
```

Now restore all Vault related resources from the backup:

```bash
velero restore create --from-backup vault-1
```

Check that the restore has finished properly:

```bash
velero restore get
NAME                    BACKUP   STATUS      WARNINGS   ERRORS   CREATED                         SELECTOR
vault1-20200129142409   vault1   Completed   0          0        2020-01-29 14:24:09 +0100 CET   <none>
```

Check that all the Vault cluster got actually restored:

```bash
kubectl get pods
NAME                                READY   STATUS    RESTARTS   AGE
vault-0                             4/4     Running   0          1m42s
vault-1                             4/4     Running   0          1m42s
vault-2                             4/4     Running   0          1m42s
vault-configurer-5499ff64cb-g75vr   1/1     Running   0          1m42s
```

Scale the operator back after the restore process:

```bash
kubectl scale deployment vault-operator --replicas 1
```

Delete the backup if you don't wish to keep it anymore:

```bash
velero backup delete vault-1
```

For a daily scheduled backup please see `docs/backup/schedule.yaml`.
