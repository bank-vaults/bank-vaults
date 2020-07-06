# Vault Operator

This directory holds the code of the Banzai Cloud Vault Operator.

## Build and hack on it

To compile the operator:

```bash
go build ./operator/cmd/manager
```

To start the operator locally and manage the cluster in the current-context:

```bash
make operator-up
```

If you wish to build the operator Docker image:

```bash
make docker-operator
```

If you change the Vault Go type definitions please regenerate the k8s deepcopy stubs, clientset listers and informers with the [kubernetes/code-generator](https://github.com/kubernetes/code-generator):

```bash
make generate-code
```
