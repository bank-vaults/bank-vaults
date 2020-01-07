# Comparision of Banzai Cloud and HashiCorp mutating webhook for Vault

#### Legend:
- √ - Implemented
- O - Planned/In-progress

| Feature    | Banzai Cloud Webhook | HashiCorp Webhook |
|------------|----------------------|-------------------|
| Automated Vault and K8S setup | √ (operator) |        |
| vault-agent/consul-template sidecar injection| √ | √ |
| Direct env var injection      | √ |   |
| Injecting into K8S Secrets    | √ |   |
| Injecting into K8S ConfigMaps | √ |   |
| CSI Driver                    | O |   |
| Native Kubernetes sidecar     | O |   |
| Sidecar-less dynamic secrets  | O |   |
