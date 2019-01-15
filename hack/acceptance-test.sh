#!/usr/bin/env bash
set -xeo pipefail

function finish {
    kubectl get pods
    kubectl logs deployment/vault-operator
    kubectl describe pod vault-0 vault-1
}

trap finish EXIT

kubectl apply -f operator/deploy/etcd-rbac.yaml
kubectl apply -f operator/deploy/etcd-operator.yaml
kubectl wait --for=condition=available deployment/etcd-operator --timeout=120s
sleep 5

kubectl apply -f operator/deploy/rbac.yaml
kubectl apply -f operator/deploy/operator.yaml
kubectl wait --for=condition=available deployment/vault-operator --timeout=120s

kubectl apply -f operator/deploy/cr.yaml
sleep 5
kubectl wait --for=condition=ready pod/vault-0 --timeout=120s
kubectl delete --wait=true vaults.vault.banzaicloud.com vault

kubectl apply -f operator/deploy/cr-etcd-ha.yaml
sleep 5

kubectl wait --for=condition=available etcdclusters.etcd.database.coreos.com/etcd-cluster --timeout=120s
sleep 30

# piggyback on initial leader change of the current HA setup
kubectl wait --for=condition=ready pod/vault-0 --timeout=120s


# Run a simple client test
go get -v github.com/banzaicloud/kurun
export PATH=${PATH}:${GOPATH}/bin
kurun cmd/examples/main.go
