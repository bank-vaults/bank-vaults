#!/usr/bin/env bash
set -xeo pipefail

function waitfor {
    WAIT_MAX=0
    until $@ &> /dev/null || [ $WAIT_MAX -eq 30 ]; do
        sleep 1
        (( WAIT_MAX = WAIT_MAX + 1 ))
    done
}

function finish {
    echo "The last command was: $(history 1 | awk '{print $2}')"
    kubectl get pods
    kubectl logs deployment/vault-operator
    kubectl describe pod -l name=vault-operator
    kubectl describe pod -l app=vault
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

kubectl apply -f operator/deploy/operator-rbac.yaml
kubectl apply -f operator/deploy/operator.yaml
kubectl wait --for=condition=available deployment/vault-operator --timeout=120s

# Install common RBAC setup for CRs
kubectl apply -f operator/deploy/rbac.yaml

# First test: HA setup with etcd
kubectl apply -f operator/deploy/cr-etcd-ha.yaml
waitfor kubectl get etcdclusters.etcd.database.coreos.com/etcd-cluster
kubectl wait --for=condition=available etcdclusters.etcd.database.coreos.com/etcd-cluster --timeout=120s
waitfor kubectl get pod/vault-0
waitfor kubectl get pod/vault-1
kubectl wait --for=condition=ready pod/vault-0 --timeout=120s
kubectl delete -f operator/deploy/cr-etcd-ha.yaml

# Second test: single node cluster with defined PriorityClass via vaultPodSpec and vaultConfigurerPodSpec
kubectl apply -f operator/deploy/priorityclass.yaml
kubectl apply -f operator/deploy/cr-priority.yaml
waitfor kubectl get pod/vault-0
kubectl wait --for=condition=ready pod/vault-0 --timeout=120s

# Run a client test

# Give bank-vaults some time to let the Kubernetes auth backend configuration happen
sleep 20

# Run an internal client which tries to read from Vault with the configured Kubernetes auth backend
go get github.com/banzaicloud/kurun
git checkout -- go.mod go.sum
export PATH=${PATH}:${GOPATH}/bin
kurun run cmd/examples/main.go


# Run the webhook test, the hello-secrets deployment should be successfully mutated
helm install ./charts/vault-secrets-webhook \
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
