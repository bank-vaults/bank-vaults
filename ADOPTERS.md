# Adopters

This is a list of production adopters of Bank-Vaults (in alphabetical order):
- [Aspect](https://www.aspect.com) is using Bank-Vaults to provision and configure Vault for the Aspect Via® Cloud Contact Centre Platform.
- [Banzai Cloud](https://banzaicloud.com) is using Bank-Vaults to provision and configure Vault for the Pipeline control plane and also the mutating webhook to injects Secrets in the provisioned user clusters. Bank-Vaults is heavily used in the supporting infrastructure of Banzai Cloud as well.
- [Tinkoff](https://www.tinkoff.ru) is using Vault Secrets Webhook to provide sensitive data to applications that don't have native integration with Vault.
- [Vonage](https://www.vonage.com/business/) is using Bank-Vaults to provision and configure Vault to provide secrets to application that are on cloud(k8s) and on premise(approle) and also as a transit engine. Uses aws kms, s3 and dynmodb and will be migrated to use raft backend.
