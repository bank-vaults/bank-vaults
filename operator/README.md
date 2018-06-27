# Vault Operator

This directory holds the code of the Banzai Cloud Vault Operator.

## Build

```bash
cd operator
operator-sdk build banzaicloud/vault-operator
```

## Deploying the operator

```bash
kubectl apply -f operator/deploy/rbac.yaml
kubectl apply -f operator/deploy/operator.yaml
```

This will createa a Kubernetes `CustomResourceDefinition` called Vault. A documented example of this CRD can be found in deploy/cr.yaml.
