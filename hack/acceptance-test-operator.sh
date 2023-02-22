#!/usr/bin/env bash
set -xeo pipefail

function waitfor {
    WAIT_MAX=0
    until sh -c "$*" &> /dev/null || [ $WAIT_MAX -eq 45 ]; do
        sleep 1
        (( WAIT_MAX = WAIT_MAX + 1 ))
    done
}

function finish {
    echo "The last command was: $(history 1 | awk '{print $2}')"
    kubectl get pods -A
    kubectl describe pods -A
    kubectl describe services -A
    kubectl logs deployment/vault-operator
    kubectl logs deployment/vault-configurer
    kubectl logs --all-containers statefulset/vault
    kubectl get secret -n vswh -o yaml
}

trap finish EXIT

# Create a resource quota in the default namespace
kubectl create quota bank-vaults --hard=cpu=4,memory=8G,pods=10,services=10,replicationcontrollers=10,secrets=15,persistentvolumeclaims=10

# Install the operators and companion
helm dependency build ./charts/vault-operator
helm upgrade --install vault-operator ./charts/vault-operator \
    --set image.tag=latest \
    --set image.bankVaultsTag=latest \
    --set image.pullPolicy=IfNotPresent \
    --wait

# Install common RBAC setup for CRs
kubectl apply -f operator/deploy/rbac.yaml

# Wait for operator
kubectl wait --for=condition=ready --timeout=150s pods -l app.kubernetes.io/name=vault-operator

# 0. test: KVv2 options
kubectl apply -f operator/deploy/cr-kvv2.yaml
kubectl wait --for=condition=healthy --timeout=180s vault/vault
kubectl delete -f operator/deploy/cr-kvv2.yaml
kubectl delete secret vault-unseal-keys

# 0. test: explicit statsd options
kubectl apply -f operator/deploy/cr-statsd.yaml
kubectl wait --for=condition=healthy --timeout=180s vault/vault
kubectl delete -f operator/deploy/cr-statsd.yaml
kubectl delete secret vault-unseal-keys

# 1. test: test the external secrets watcher work and match as expected
kubectl apply -f deploy/test-external-secrets-watch-deployment.yaml
kubectl wait --for=condition=healthy --timeout=180s vault/vault
test "$(kubectl get pod vault-0 -o jsonpath='{.metadata.annotations.vault\.banzaicloud\.io/watched-secrets-sum}')" = ""
kubectl delete -f deploy/test-external-secrets-watch-deployment.yaml
kubectl delete secret vault-unseal-keys

kubectl apply -f deploy/test-external-secrets-watch-secrets.yaml
kubectl apply -f deploy/test-external-secrets-watch-deployment.yaml
kubectl wait --for=condition=healthy --timeout=120s vault/vault
test "$(kubectl get pod vault-0 -o jsonpath='{.metadata.annotations.vault\.banzaicloud\.io/watched-secrets-sum}')" = "bac8dfa8bdf03009f89303c8eb4a6c8f2fd80eb03fa658f53d6d65eec14666d4"
kubectl delete -f deploy/test-external-secrets-watch-deployment.yaml
kubectl delete -f deploy/test-external-secrets-watch-secrets.yaml
kubectl delete secret vault-unseal-keys

# 2. test: Raft HA setup
kubectl apply -f operator/deploy/cr-raft.yaml
kubectl wait --for=condition=healthy --timeout=150s vault/vault
kubectl delete -f operator/deploy/cr-raft.yaml
kubectl delete secret vault-unseal-keys
kubectl delete pvc --all

# 3. test: HSM setup with SoftHSM
kubectl apply -f operator/deploy/cr-hsm-softhsm.yaml
kubectl wait --for=condition=healthy --timeout=120s vault/vault
kubectl delete -f operator/deploy/cr-hsm-softhsm.yaml
kubectl delete secret vault-unseal-keys
kubectl delete pvc --all

# 4. test: disabled root token storage
kubectl apply -f operator/deploy/cr-disabled-root-token-storage.yaml
kubectl wait --for=condition=healthy --timeout=120s vault/vault
test "$(kubectl get secret vault-root -o json --ignore-not-found | wc -l)" -eq 0
kubectl delete -f operator/deploy/cr-disabled-root-token-storage.yaml
kubectl delete secret vault-unseal-keys
kubectl delete pvc --all

# 5. test: single node cluster with defined PriorityClass via vaultPodSpec and vaultConfigurerPodSpec
kubectl apply -f operator/deploy/priorityclass.yaml
kubectl apply -f operator/deploy/cr-priority.yaml
kubectl wait --for=condition=healthy --timeout=120s vault/vault

# Leave this instance for further tests

# Run a client tests

# Give bank-vaults some time to let the Kubernetes auth backend configuration happen
sleep 30

# Run an internal client which tries to read from Vault with the configured Kubernetes auth backend
kurun run cmd/examples/main.go

kubectl delete -f operator/deploy/cr-priority.yaml
kubectl delete -f operator/deploy/priorityclass.yaml
kubectl delete secret vault-unseal-keys
kubectl delete pvc --all

# 6. test: Run the OIDC authenticated client test
kubectl create namespace vswh # create the namespace beforehand, because we need the CA cert here as well
kubectl apply -f operator/deploy/cr-oidc.yaml
kubectl wait --for=condition=healthy --timeout=120s vault/vault

kurun apply -f hack/oidc-pod.yaml
waitfor "kubectl get pod/oidc -o json | jq -e '.status.phase == \"Succeeded\"'"

echo "Test has finished"
