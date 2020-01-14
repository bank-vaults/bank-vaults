# Using Vault Agent Templating in the mutating webhook

This document assumes you have a working Kuberentes cluster which has a:
* Working install of Vault.
* Working install of the mutating webhook via helm or manually.
* That you have a working knowledge of Kubernetes.
* That you have the ability to apply Deployments or PodSpec's to the cluster.
* That you have the ability to change the configuration of the mutating webhook.

## When to use vault-agent
* You have an application or tool that requires to read its configuration from a file.
* You wish to have secrets that have a TTL and expire.
* You do not wish to be limited on which vault secrets backend you use.

## General concept
* Your pod starts up, the webhook will inject one container into the pods lifecycle.
* The sidecar container is running Vault, using the [vault agent](https://www.vaultproject.io/docs/agent/) that accesses Vault using the configuration specified inside a configmap and writes a configuration file based on a pre configured template (written inside the same configmap) onto a temperary file system which your application can use.

## Pre Configuration
### ShareProcessNamespace
As of Kubernetes 1.10 you can [share](https://kubernetes.io/docs/tasks/configure-pod-container/share-process-namespace/) the process list of all containers in a pod, please check your Kuberentes API server FeatureGates configuration to find if it is on or not, it is default on in 1.12. The webhook will disable it by default in any version less than 1.12 and enable it by default for version 1.12 and above. You can override this confirguration using the `vault.security.banzaicloud.io/vault-agent-share-process-namespace` annotation or webhook `vault_agent_share_process_namespace` environment variable.

If you wish to use Vault TTLs you need a way that you can HUP your application on configuration file change, Vault Agent can be [configured](https://www.vaultproject.io/docs/agent/template/index.html) with a `command` attribute which it will run when it writes a new configuration file. You can find a basic example below which uses/requires the ShareProcessNamespace feature and the Kubernetes Auth:

```
---
apiVersion: v1
kind: ConfigMap
metadata:
  labels:
    app.kubernetes.io/name: my-app
    my-app.kubernetes.io/name: my-app-vault-agent
    branches: "true"
  name: my-app-vault-agent
data:
  config.hcl: |
    vault {
      retry {
        backoff = "1s"
      }
      auto_auth {
        method "kubernetes" {
          mount_path = "auth/kubernetes"
          config = {
            role = "my-role"
          }
        }
        sink "file" {
          config = {
            path = "/vault/.vault-token"
          }
        }
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
|VAULT_IMAGE|vault:latest| the vault image to use for the sidecar container|
|VAULT_IMAGE_PULL_POLICY|IfNotPresent| The pull policy for the vault agent container|
|VAULT_ADDR    |https://127.0.0.1:8200|Kubernetes service Vault endpoint URL|
|VAULT_TLS_SECRET|""|supply a secret with the vault TLS CA so TLS can be verified|
|VAULT_AGENT_SHARE_PROCESS_NAMESPACE|Kubernetes version <1.12 default off, 1.12 or higher default on|ShareProcessNamespace override|as above|

### PodSpec annotations:
|Annotation    |default     |Explanation|
|--------------|------------|------------|
vault.security.banzaicloud.io/vault-addr|Same as VAULT_ADDR above||
vault.security.banzaicloud.io/vault-tls-secret|Same as VAULT_TLS_SECRET above||
vault.security.banzaicloud.io/vault-agent-configmap|""|A configmap name which holds the vault agent configuration|
vault.security.banzaicloud.io/vault-agent-once|false|do not run vault-agent in daemon mode, useful for kubernetes jobs|
vault.security.banzaicloud.io/vault-agent-share-process-namespace|Same as VAULT_AGENT_SHARE_PROCESS_NAMESPACE above|
vault.security.banzaicloud.io/vault-agent-cpu|"100m"|Specify the vault-agent container CPU resource limit|
vault.security.banzaicloud.io/vault-agent-memory|"128Mi"|Specify the vault-agent container memory resource limit|
vault.security.banzaicloud.io/vault-configfile-path|"/vault/secrets"|Mount path of Vault Agent rendered files|

### How to enable vault agent in the webhook?
For the webhook to detect that it will need to mutate or change a PodSpec, it must have the annotation `vault.security.banzaicloud.io/vault-agent-configmap` otherwise the PodSpec will be ignored for configuration with Vault Agent.

