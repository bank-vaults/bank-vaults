# Vault Secrets webhook

This chart will install a mutating admission webhook, that injects an executable to containers in a deployment/statefulset which than can request secrets from Vault through environment variable definitions.

## Installing the Chart

```bash
$ helm repo add banzaicloud-stable http://kubernetes-charts.banzaicloud.com/branch/master
$ helm repo update
```

```bash
$ helm upgrade --install <name> banzaicloud-stable/vault-secrets-webhook
```

## Configuration

The following tables lists configurable parameters of the vault-secrets-webhook chart and their default values.

|               Parameter             |                Description                  |                  Default                 |
| ----------------------------------- | ------------------------------------------- | -----------------------------------------|
|replicaCount                         |number of replicas                           |1                                         |
|logVerbosity                         |log verbosity level                          |8                                         |
|apiService.group                     |group of registered api service              |vault.banzaicloud.com                 |
|apiService.version                   |version of registered api service            |v1beta1                                   |
|apiService.resource                  |api service endpoint where hook is available |spotscheduling                            |
|image.repository                     |image repo that contains the admission server|banzaicloud/vault-secrets-webhook             |
|image.tag                            |image tag                                    |latest                                    |
|image.pullPolicy                     |image pull policy                            |IfNotPresent                              |
|service.name                         |webhook service name             |vault-secrets-webhook                               |
|service.type                         |webhook service type             |ClusterIP                                 |
|service.externalPort                 |webhook service external port    |443                                       |
|service.internalPort                 |webhook service external port    |443                                       |
|resources                            |resources to request                         |{}                                        |
|nodeSelector                         |node selector to use                         |{}                                        |
|tolerations                          |tolerations to add                           |[]                                        |
|affinity                             |affinities to use                            |{}                                        |
