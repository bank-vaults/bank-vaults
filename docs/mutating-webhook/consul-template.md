# Using consul-template in the mutating webhook

This document assumes you have a working Kuberentes cluster which has a:
* Working install of Vault.
* Working install of the mutating webhook via helm or manually.
* That you have a working knowledge of Kubernetes.
* That you have the ability to apply Deployments or PodSpec's to the cluster.
* That you have the ability to change the configuration of the mutating webhook.

## Background
found [here](https://github.com/banzaicloud/bank-vaults/issues/403)

## When to use consul-template
* You have an application or tool that requires to read its configuration from a file.
* You wish to have secrets that have a TTL and expire.
* You do not wish to be limited on which vault secrets backend you use.

below features only available with 'ShareProcessNamespace' available.
* You wish to be able to expire tokens/revoke tokens i
  (to do this you need to have a ready/live probe that can send a HUP to consul-template when the current details fail).

## General concept
Based on various publications and tools ([Kubernetes Authenticator](https://github.com/sethvargo/vault-kubernetes-authenticator), [consul-template](https://github.com/hashicorp/consul-template)) released and maintained by Hashicorp and [Seth Vargo](https://github.com/sethvargo).

* Your pod starts up, the webhook will inject one init container and one container into the pods lifecycle.
* The init container is running vault, using the [vault agent](https://www.vaultproject.io/docs/agent/) that will login and retreieve a Vault token based on the configured VAULT_ROLE and Kuberentes Service Account.
* The sidecar container is running consul template which uses the already mentioned Vault token to login to Vault and write a configuration file based on a pre configured template in a configmap onto a temperary file system which your application can use.

## Pre Configuration
### ShareProcessNamespace
As of Kuberentes 1.10 you can [share](https://kubernetes.io/docs/tasks/configure-pod-container/share-process-namespace/) the process list of all containers in a pod, please check your Kuberentes API server FeatureGates configuration to find if it is on or not, it is default on in 1.12. The webhook will disable it by default in any version less than 1.12 and enable it by default for version 1.12 and above. You can override this confirguration using the `vault.security.banzaicloud.io/ct-share-process-namespace` annotation or webhook `vault_ct_share_process_namespace` environment variable.

### consul template
note, at this point in time consul-template 0.20.0 is [broken](https://github.com/hashicorp/consul-template/pull/1182#issuecomment-486047781), do not use this version.

If you wish to use Vault TTLs you need a way that you can HUP your application on configuration file change, consul template can be [configured](https://github.com/hashicorp/consul-template#configuration-file-format) with a 'command' attribute which it will run when it writes a new configuration file. You can find a basic example below (adapted from [here](https://github.com/sethvargo/vault-kubernetes-workshop/blob/master/k8s/db-sidecar.yaml#L79-L100)) which uses/requires the ShareProcessNamespace feature:

```
---
apiVersion: v1
kind: ConfigMap
metadata:
  labels:
    app: my-app
    my-app: my-app-consul-template
    branches: "true"
  name: my-app-consul-template
data:
  config.hcl: |
    vault {
      ssl {
        ca_cert = "/etc/vault/tls/ca.crt"
      }
      retry {
        backoff = "1s"
      }
    }
    template {
      contents = <<EOH
        {{- with secret "database/creds/readonly" }}
        username: {{ .Data.username }}
        password: {{ .Data.password }}
        {{ end }}
      EOH
      destination = "/etc/secrets/config"
      command     = "/bin/sh -c \"kill -HUP $(pidof vault-demo-app) || true\""
    }
```

## Configuration
There are two places to configure the Webhook, you can set some sane defaults in the environment of the mutating webhook or you can configure it via annotations in your PodSpec.

### Defaults via environment variables:
|Variable      |default     |Explanation|
|--------------|------------|------------|
|VAULT_IMAGE   |vault:latest|the vault image to use for the init container|
|VAULT_ENV_IMAGE|banzaicloud/vault-env:latest| the vault-env image to use |
|VAULT_CT_IMAGE|hashicorp/consul-template:latest| the consule template image to use|
|VAULT_ADDR    |https://127.0.0.1:8200|Kuberentes service Vault endpoint URL|
|VAULT_SKIP_VERIFY|"false"|should vault agent and consul template skip verifying TLS|
|VAULT_TLS_SECRET|""|supply a configmap with the vault TLS CA so TLS can be verified|
|VAULT_AGENT   |"true"|enable the vault agent|
|VAULT_CT_SHARE_PROCESS_NAMESPACE|Kubernetes version <1.12 default off, 1.12 or higher default on|ShareProcessNamespace override|as above|

### PodSpec annotations:
|Annotation    |default     |Explanation|
|--------------|------------|------------|
vault.security.banzaicloud.io/vault-addr|Same as VAULT_ADDR above||
vault.security.banzaicloud.io/vault-role|default|The Vault role for Vault agent to use|
vault.security.banzaicloud.io/vault-path|auth/<method type>|The mount path of the method|
vault.security.banzaicloud.io/vault-skip-verify|Same as VAULT_SKIP_VERIFY above||
vault.security.banzaicloud.io/vault-tls-secret|Same as VAULT_TLS_CONFIGMAP above||
vault.security.banzaicloud.io/vault-agent|Same as VAULT_AGENT above||
vault.security.banzaicloud.io/vault-ct-configmap|""|A configmap name which holds the consul template configuration|
vault.security.banzaicloud.io/vault-ct-image|""|Specify a custom image for consul template|
vault.security.banzaicloud.io/vault-ct-once|false|do not run consul-template in daemon mode, useful for kubernetes jobs|
vault.security.banzaicloud.io/vault-ct-pull-policy|IfNotPresent|the Pull policy for the consul template container|
vault.security.banzaicloud.io/vault-ct-share-process-namespace|Same as VAULT_CT_SHARE_PROCESS_NAMESPACE above||
vault.security.banzaicloud.io/vault-ignore-missing-secrets|"false"|When enabled will only log warnings when Vault secrets are missing|
vault.security.banzaicloud.io/vault-env-passthrough|""|Comma seprated list of `VAULT_*` related environment variables to pass through to main process. E.g.`VAULT_ADDR,VAULT_ROLE`.

### How to enable consul template in the webhook?
For the webhook to detect that it will need to mutate or change a PodSpec, it must have the annotation `vault.security.banzaicloud.io/vault-ct-configmap` otherwise the PodSpec will be ignored for configuration with Consul Template.

