# Vault Secrets webhook

This chart will install a mutating admission webhook, that injects an executable to containers in a deployment/statefulset which than can request secrets from Vault through environment variable definitions.

## Installing the Chart

```bash
$ helm repo add banzaicloud-stable http://kubernetes-charts.banzaicloud.com/branch/master
$ helm repo update
```

The chart needs to be installed into it's own namespace to overcome recursive mutation issues, that namespace is ignored by the mutating webhook.
See: https://github.com/banzaicloud/banzai-charts/issues/595#issuecomment-452223465 for more information.

```bash
$ helm upgrade --namespace vswh --install vswh banzaicloud-stable/vault-secrets-webhook
```

## Configuration

The following tables lists configurable parameters of the vault-secrets-webhook chart and their default values.

|               Parameter             |                Description                  |                  Default                 |
| ----------------------------------- | ------------------------------------------- | -----------------------------------------|
|affinity                             |affinities to use                            |{}                                        |
|debug                                |debug logs for webhook                       |false                                     |
|image.pullPolicy                     |image pull policy                            |IfNotPresent                              |
|image.repository                     |image repo that contains the admission server|banzaicloud/vault-secrets-webhook         |
|image.tag                            |image tag                                    |latest                                    |
|nodeSelector                         |node selector to use                         |{}                                        |
|replicaCount                         |number of replicas                           |1                                         |
|resources                            |resources to request                         |{}                                        |
|service.externalPort                 |webhook service external port                |443                                       |
|service.internalPort                 |webhook service external port                |443                                       |
|service.name                         |webhook service name                         |vault-secrets-webhook                     |
|service.type                         |webhook service type                         |ClusterIP                                 |
|tolerations                          |tolerations to add                           |[]                                        |
|podSecurityPolicy.enabled            |use pod security policy                      |true                                      |
