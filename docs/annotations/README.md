# Annotations

The Vault Operator suypport annotating most of the resources it creates using a set of fields in the Vault Specs:

## Common Vault Resources annotations
```
apiVersion: "vault.banzaicloud.com/v1alpha1"
kind: "Vault"
metadata:
  name: "vault"
	spec:
	  annotations:
		  example.com/test: "something"
```

These annotations are common to all Vault Created resources
  - Vault Statefulset
	- Vault Pods
	- Vault Configurer Deployment
	- Vault Configurer Pod
	- Vault Services
	- Vault Configurer Service
	- Vault TLS Secret


## Vault Statefulset Resources annotations
```
apiVersion: "vault.banzaicloud.com/v1alpha1"
kind: "Vault"
metadata:
  name: "vault"
	spec:
	  vaultAnnotations:
		  example.com/vault: "true"
```

These annotations are common to all Vault Statefulset Created resources
  - Vault Statefulset
	- Vault Pods
	- Vault Services
	- Vault TLS Secret

These annotations will override any annotation defined in the common set

## Vault Configurer deployment Resources annotations
```
apiVersion: "vault.banzaicloud.com/v1alpha1"
kind: "Vault"
metadata:
  name: "vault"
	spec:
	  vaultConfigurerAnnotations:
		  example.com/vaultConfigurer: "true"
```

These annotations are common to all Vault Configurer Deployment Created resources
	- Vault Configurer Deployment
	- Vault Configurer Pod
	- Vault Configurer Service

These annotations will override any annotation defined in the common set

## ETCD CRD Annotations
```
apiVersion: "vault.banzaicloud.com/v1alpha1"
kind: "Vault"
metadata:
  name: "vault"
	spec:
	  etcdAnnotations:
		  etcd.database.coreos.com/scope: clusterwide
```

These annotations are set *only* on the etcdcluster resource

## ETCD PODs Annotations
```
apiVersion: "vault.banzaicloud.com/v1alpha1"
kind: "Vault"
metadata:
  name: "vault"
	spec:
	  etcdPodAnnotations:
		  backup.velero.io/backup-volumes: "YOUR_VOLUME_NAME"
```

These annotations are set *only* on the etcd pods created by the etcd-operator

