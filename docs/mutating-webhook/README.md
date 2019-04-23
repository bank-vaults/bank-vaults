# Mutating Webhook

The mutating admission webhook injects an executable to containers (in a very non-intrusive way) inside a Deployments/StatefulSets which than can request secrets from Vault through special environment variable definitions. The project is inspired by many, already existing projects (e.g.: `channable/vaultenv`, `hashicorp/envconsul`). The webhook checks if a container has environment variables defined in the following form, and reads the values for those variables directly from Vault during startup time:

```yaml
        env:
        - name: AWS_SECRET_ACCESS_KEY
          value: vault:secret/data/accounts/aws#AWS_SECRET_ACCESS_KEY
# or
        - name: AWS_SECRET_ACCESS_KEY
          valueFrom:
            secretKeyRef:
              name: aws-key-secret
              key: AWS_SECRET_ACCESS_KEY
# or
        - name: AWS_SECRET_ACCESS_KEY
            valueFrom:
              configMapKeyRef:
                name: aws-key-configmap
                key: AWS_SECRET_ACCESS_KEY
```

The webhook checks if a container has envFrom and parse defined configmaps and secrets:

```yaml
        envFrom:
          - secretRef:
              name: aws-key-secret
# or
          - configMapRef:
              name: aws-key-configmap
```

Secret and ConfigMap examples:
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: aws-key-secret
data:
  AWS_SECRET_ACCESS_KEY: vault:secret/data/accounts/aws#AWS_SECRET_ACCESS_KEY
type: Opaque
```

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: aws-key-configmap
data:
  AWS_SECRET_ACCESS_KEY: vault:secret/data/accounts/aws#AWS_SECRET_ACCESS_KEY
```

In this case the a init-container will be injected to the given Pod which copies a small binary, called `vault-env` into an in-memory volume and mounts that Volume to all the containers which have an environment variable definition like that. It also changes the `command` of the container to run `vault-env` instead of your application directly. `vault-env` starts up, connects to Vault with (currently with the [Kubernetes Auth method](https://www.vaultproject.io/docs/auth/kubernetes.html) checks the environment variables, and that has a reference to a value stored in Vault (`vault:secret/....`) will be replaced with that value read from the Secret backend, after this `vault-env` immediately executes (with `syscall.Exec()`) your process with the given arguments, replacing itself with that process.

**With this solution none of your Secrets stored in Vault will ever land in Kubernetes Secrets, thus in etcd.**

`vault-env` was designed to work in Kubernetes at the first place, but nothing stops you to use it outside Kubernetes as well. It can be configured with the standard Vault client's [environment variables](https://www.vaultproject.io/docs/commands/#environment-variables) (because there is a standard Go Vault client underneath).

Currently the Kubernetes Service Account based Vault authentication mechanism is used by `vault-env`, so it requests a Vault token based on the Service Account of the container it is injected into. Implementation is ongoing to use [Vault Agent's Auto-Auth](https://www.vaultproject.io/docs/agent/autoauth/index.html) to request tokens in an init-container with all the supported authentication mechanisms.

**Current limitations:**

- The command of the container has to be explicitly defined in the resource definition, the container's default `ENTRYPOINT` and `CMD` will not work (to overcome this is a work-in-progress).

## Deploying the webhook

### Helm chart

There is a Helm chart available to deploy the [Vault Secrets Webhook](https://github.com/banzaicloud/banzai-charts/tree/master/vault-secrets-webhook). 

```bash
helm init -c
helm repo add banzaicloud-stable http://kubernetes-charts.banzaicloud.com/branch/master
helm upgrade --namespace vswh --install vswh banzaicloud-stable/vault-secrets-webhook
```

For further details follow the webhook's Helm chart [repository](https://github.com/banzaicloud/banzai-charts/tree/master/vault-secrets-webhook).

## Example

Write a secret into Vault:

```bash
vault kv put secret/valami/aws AWS_SECRET_ACCESS_KEY=s3cr3t
```

This deployment will be mutated by the webhook, since it has at least one environment variable having a value which is a reference to a path in Vault:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: vault-test
spec:
  replicas: 1
  selector:
    matchLabels:
      app: vault
  template:
    metadata:
      labels:
        app: vault
      annotations:
        vault.security.banzaicloud.io/vault-addr: "https://vault:8200"
        vault.security.banzaicloud.io/vault-role: "default"
        vault.security.banzaicloud.io/vault-skip-verify: "true"
        vault.security.banzaicloud.io/vault-path: "kubernetes"
    spec:
      serviceAccountName: default
      containers:
      - name: alpine
        image: alpine
        command: ["sh", "-c", "echo $AWS_SECRET_ACCESS_KEY && echo going to sleep... && sleep 10000"]
        env:
        - name: AWS_SECRET_ACCESS_KEY
          value: vault:secret/data/valami/aws#AWS_SECRET_ACCESS_KEY
```
