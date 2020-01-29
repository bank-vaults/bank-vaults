# Backing up Vault

## Velero

First in this example we will install [Velero](https://velero.io/) on the target cluster with Helm:

Add the Velero Helm repository:

```bash
helm repo add vmware-tanzu https://vmware-tanzu.github.io/helm-charts
```

Create a namespace for Velero:

```bash
kubectl create namespace velero
```

Install Velero (in this example we use AWS):

```bash
BUCKET=bank-vaults-velero
REGION=eu-north-1
SECRET_FILE=~/.aws/credentials

helm upgrade --install velero --namespace velero \
--set configuration.provider=aws \
--set-file credentials.secretContents.cloud=${SECRET_FILE} \
--set deployRestic=true \
--set configuration.backupStorageLocation.name=aws \
--set configuration.backupStorageLocation.bucket=${BUCKET} \
--set configuration.backupStorageLocation.config.region=${REGION} \
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

Create a backup with the Velero Backup CR or with the Velero CLI:

```bash
velero backup create vault-1 --selector vault_cr=vault

# OR

kubectl apply -f docs/backup/backup.yaml
```


kubectl delete vault -l vault_cr=vault
kubectl delete pvc -l vault_cr=vault
