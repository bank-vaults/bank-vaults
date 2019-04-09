#!/usr/bin/env bash
set -xeo pipefail

function finish {
    kubectl get pods
    kubectl logs deployment/vault-operator
    kubectl describe pod -l name=vault-operator
    kubectl describe pod vault-0 vault-1
    kubectl describe pod -l app=vault-configurator
    kubectl get services --show-labels -l vault_cr=vault
    kubectl get ep --show-labels -l vault_cr=vault
    kubectl logs deployment/vault-configurer
}

trap finish EXIT

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
sleep 5
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

go get -v github.com/banzaicloud/kurun
export PATH=${PATH}:${GOPATH}/bin
kurun cmd/examples/main.go
