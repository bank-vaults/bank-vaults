# Contributing

If you find this project useful here's how you can help:

- Send a pull request with your new features and bug fixes
- Help new users with issues they may encounter
- Support the development of this project and star this repo!


## Development environment

In your develepment environment you can use file mode for testing `bank-vaults` cli-tool:

```shell
vault server -config vault.hcl
```

**example vault.hcl:**
```
api_addr = "http://localhost:8200"

storage "file" {
  path = "/tmp/vault"
}

listener "tcp" {
  address = "0.0.0.0:8200"
  tls_disable = true
}
```

Now you have a running vault server which is unitialized and unsealed you can init and unseal it with `bank-vaults` cli-tool and unseal keys will be stored to a local file:
```shell
VAULT_ADDR=http://127.0.0.1:8200 bank-vaults unseal --init --mode file
```

The unseal keys and root token are stored your working directory:
```
vault-root
vault-unseal-0
vault-unseal-1
vault-unseal-2
vault-unseal-3
vault-unseal-4
```


## Operator

Developing the operator requires a *working Kubernetes cluster*, minikube and Docker for Mac Kubernetes will suffice.

The operator consists of two parts, the *bank-vaults sidecar* running inside a container and the *operator itself*.

You can fire up the operator on your machine, so you can debug it locally (yes you don't have to build a container from it), if your kube context points to the development cluster:

```bash
$ make operator-up
```

This installs all the necessary RBAC rules and other CRDs that you need to create a Vault instance. If you change the code of the operator you have to `CTRL + C` this `make` command and rerun it again.

Now it is time create a Vault instance for yourself, which you can work on:

```bash
$ kubectl apply -f operator/deploy/cr.yaml
```

If you change the *bank-vaults sidecar* code you have to build a new Docker image from it:

```bash
$ DOCKER_LATEST=1 make docker
```

There are at least four ways distribute this image in your Kubernetes cluster, by default `IfNotPresent` image pull policy is used:
- If you are using Docker for Mac you, you don't have to anything, the Kubernetes cluster and your host share the same Docker daemon.
- If you are using Minikube with `--vm-driver=none` (you are probably using Linux) the same applies as for Docker for Mac
- If you are using Minikube with some real `vm-driver` you have to run `eval $(minikube docker-env)` before building the Docker image with the `make` command so you build it with the minikube Docker daemon and the image will be stored there
- Build and re-tag the image and push it to the Docker registry of your choice, dont forget to change the `bankVaultsImage` attribute in the the Vault Custom Resource YAML file (`cr.yaml` in this case).

Restart the containers using the `bank-vaults` image: Vault instances and the configurer.

## WebHook

This will deploy the webhook via the Helm chart, scale it to 0, start it locally and proxy it into the cluster (somethink similar to `operator-up` but a bit more complex).

You will need Helm and `kurun` [installed](https://github.com/banzaicloud/kurun#installation) to run this:

```bash
$ make webhook-up -j
```

Now you can try out with mutating a Deployment:

```bash
$ kubectl apply -f deploy/test-deployment.yaml
```
