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

Create a backup with the following Velero Backup CR:

```yaml
# Standard Kubernetes API Version declaration. Required.
apiVersion: velero.io/v1
# Standard Kubernetes Kind declaration. Required.
kind: Backup
# Standard Kubernetes metadata. Required.
metadata:
  # Backup name. May be any valid Kubernetes object name. Required.
  name: vault-raft-1
  # Backup namespace. Must be the namespace of the Velero server. Required.
  namespace: velero
# Parameters about the backup. Required.
spec:
  # Array of namespaces to include in the backup. If unspecified, all namespaces are included.
  # Optional.
  includedNamespaces:
  - default
  # Array of resources to include in the backup. Resources may be shortcuts (e.g. 'po' for 'pods')
  # or fully-qualified. If unspecified, all resources are included. Optional.
  includedResources:
  - pvc
  # Whether or not to include cluster-scoped resources. Valid values are true, false, and
  # null/unset. If true, all cluster-scoped resources are included (subject to included/excluded
  # resources and the label selector). If false, no cluster-scoped resources are included. If unset,
  # all cluster-scoped resources are included if and only if all namespaces are included and there are
  # no excluded namespaces. Otherwise, if there is at least one namespace specified in either
  # includedNamespaces or excludedNamespaces, then the only cluster-scoped resources that are backed
  # up are those associated with namespace-scoped resources included in the backup. For example, if a
  # PersistentVolumeClaim is included in the backup, its associated PersistentVolume (which is
  # cluster-scoped) would also be backed up.
  includeClusterResources: null
  # Individual objects must match this label selector to be included in the backup. Optional.
  labelSelector:
    matchLabels:
      app.kubernetes.io/name: vault
      vault_cr: vault
  # Whether or not to snapshot volumes. This only applies to PersistentVolumes for Azure, GCE, and
  # AWS. Valid values are true, false, and null/unset. If unset, Velero performs snapshots as long as
  # a persistent volume provider is configured for Velero.
  snapshotVolumes: true
  # Where to store the tarball and logs.
  storageLocation: default
  # The list of locations in which to store volume snapshots created for this backup.
  volumeSnapshotLocations:
    - default
  # The amount of time before this backup is eligible for garbage collection. If not specified, 
  # a default value of 30 days will be used. The default can be configured on the velero server
  # by passing the flag --default-backup-ttl. 
  ttl: 24h0m0s
  # Actions to perform at different times during a backup. The only hook currently supported is
  # executing a command in a container in a pod using the pod exec API. Optional.
  hooks:
    # Array of hooks that are applicable to specific resources. Optional.
    resources:
      -
        # Name of the hook. Will be displayed in backup log.
        name: my-hook
        # Array of namespaces to which this hook applies. If unspecified, the hook applies to all
        # namespaces. Optional.
        includedNamespaces:
        - '*'
        # Array of namespaces to which this hook does not apply. Optional.
        excludedNamespaces:
        - some-namespace
        # Array of resources to which this hook applies. The only resource supported at this time is
        # pods.
        includedResources:
        - pods
        # Array of resources to which this hook does not apply. Optional.
        excludedResources: []
        # This hook only applies to objects matching this label selector. Optional.
        labelSelector:
          matchLabels:
            app: velero
            component: server
        # An array of hooks to run before executing custom actions. Currently only "exec" hooks are supported.
        pre:
          - 
            # The type of hook. This must be "exec".
            exec:
              # The name of the container where the command will be executed. If unspecified, the
              # first container in the pod will be used. Optional.
              container: my-container
              # The command to execute, specified as an array. Required.
              command:
                - /bin/uname
                - -a
              # How to handle an error executing the command. Valid values are Fail and Continue.
              # Defaults to Fail. Optional.
              onError: Fail
              # How long to wait for the command to finish executing. Defaults to 30 seconds. Optional.
              timeout: 10s
        # An array of hooks to run after all custom actions and additional items have been
        # processed. Currently only "exec" hooks are supported.
        post:
          # Same content as pre above.
```