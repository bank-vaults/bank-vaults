# Comparision of Banzai Cloud and HashiCorp mutating webhook for Vault

#### Legend:
- :white_check_mark: - Implemented
- :o: - Planned/In-progress

| Feature    | Banzai Cloud Webhook | HashiCorp Webhook |
|------------|----------------------|-------------------|
| Automated Vault and K8S setup | :white_check_mark: (operator) |        |
| vault-agent/consul-template sidecar injection| :white_check_mark: | :white_check_mark: |
| Direct env var injection      | :white_check_mark: |   |
| Injecting into K8S Secrets    | :white_check_mark: |   |
| Injecting into K8S ConfigMaps | :white_check_mark: |   |
| CSI Driver                    | :o: |   |
| Native Kubernetes sidecar     | :o: |   |
| Sidecar-less dynamic secrets  | :o: |   |
