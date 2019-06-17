#!/usr/bin/env bash
set -xeo pipefail

function finish {
    echo "The last command was: $(history 1 | awk '{print $2}')"
    kubectl get pods
    kubectl logs deployment/vault-operator
    kubectl describe pod -l name=vault-operator
    kubectl describe pod vault-0 vault-1
    kubectl describe pod -l app=vault-configurator
    kubectl get services --show-labels -l vault_cr=vault
    kubectl get ep --show-labels -l vault_cr=vault
    kubectl logs deployment/vault-configurer
    kubectl logs -n vswh deployment/vault-secrets-webhook
    kubectl describe deployment/hello-secrets
    kubectl describe rs hello-secrets
    kubectl describe pod hello-secrets
    kubectl logs deployment/hello-secrets --all-containers
    kubectl get secret -n vswh -o yaml
}

trap finish EXIT

# Create a resource quota in the default namespace
kubectl create quota bank-vaults --hard=cpu=2,memory=4G,pods=10,services=10,replicationcontrollers=10,secrets=10,persistentvolumeclaims=10

# Install the operators and companion
kubectl apply -f operator/deploy/etcd-rbac.yaml
kubectl apply -f operator/deploy/etcd-operator.yaml
kubectl wait --for=condition=available deployment/etcd-operator --timeout=120s
sleep 5

kubectl apply -f operator/deploy/operator-rbac.yaml
kubectl apply -f operator/deploy/operator.yaml
kubectl wait --for=condition=available deployment/vault-operator --timeout=120s

kubectl apply -f operator/deploy/rbac.yaml

# First test: single node cluster
kubectl apply -f operator/deploy/cr.yaml
kubectl 10
kubectl wait --for=condition=ready pod/vault-0 --timeout=120s
kubectl delete --wait=true -f operator/deploy/cr.yaml


# Second test: HA setup with etcd
kubectl apply -f operator/deploy/cr-etcd-ha.yaml
sleep 5

kubectl wait --for=condition=available etcdclusters.etcd.database.coreos.com/etcd-cluster --timeout=120s
sleep 30

# piggyback on initial leader change of the current HA setup
kubectl wait --for=condition=ready pod/vault-0 --timeout=120s

# Run a client test

# Give bank-vaults some time to let the Kubernetes auth backend configuration happen
sleep 20

# Run an internal client which tries to read from Vault with the configured Kubernetes auth backend
go get -v github.com/banzaicloud/kurun
git checkout -- go.mod go.sum
export PATH=${PATH}:${GOPATH}/bin
kurun cmd/examples/main.go


# Run the webhook test, the hello-secrets deployment should be successfully mutated
helm install banzaicloud-stable/vault-secrets-webhook \
    --name vault-secrets-webhook \
    --set image.tag=latest \
    --set image.pullPolicy=IfNotPresent \
    --set env.VAULT_ENV_IMAGE=banzaicloud/vault-env:latest \
    --namespace vswh \
    --wait

kubectl apply -f deploy/test-secret.yaml
test `kubectl get secrets sample-secret -o jsonpath='{.data.\.dockerconfigjson}' | base64 --decode | jq -r '.auths[].username'` = "dockerrepouser"
test `kubectl get secrets sample-secret -o jsonpath='{.data.\.dockerconfigjson}' | base64 --decode | jq -r '.auths[].password'` = "dockerrepopassword"

kubectl apply -f deploy/test-deployment.yaml
kubectl wait --for=condition=available deployment/hello-secrets --timeout=120s
