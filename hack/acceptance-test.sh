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
    kubectl get pods
    kubectl describe pods
    kubectl describe services
    kubectl logs deployment/vault-operator
    kubectl logs --all-containers statefulset/vault
    kubectl logs -n vswh deployment/vault-secrets-webhook
    kubectl describe deployment/hello-secrets
    kubectl describe rs hello-secrets
    kubectl describe pod hello-secrets
    kubectl logs deployment/hello-secrets --all-containers
    kubectl get secret -n vswh -o yaml
}

function check_webhook_seccontext {
    kubectl describe deployment/hello-secrets-seccontext
    kubectl describe rs hello-secrets-seccontext
    kubectl describe pod hello-secrets-seccontext
    kubectl logs deployment/hello-secrets-seccontext --all-containers
}

trap finish EXIT

# Smoke test the pure Vault Helm chart first
helm upgrade --install --wait vault ./charts/vault --set unsealer.image.tag=latest
helm delete vault
kubectl delete secret bank-vaults

# Create a resource quota in the default namespace
kubectl create quota bank-vaults --hard=cpu=4,memory=8G,pods=10,services=10,replicationcontrollers=10,secrets=15,persistentvolumeclaims=10

# Install the operators and companion
helm dependency build ./charts/vault-operator
helm upgrade --install vault-operator ./charts/vault-operator \
    --set image.tag=latest \
    --set image.pullPolicy=IfNotPresent \
    --set etcd-operator.enabled=true \
    --set etcd-operator.deployments.backupOperator=false \
    --set etcd-operator.deployments.restoreOperator=false \
    --wait

# Install common RBAC setup for CRs
kubectl apply -f operator/deploy/rbac.yaml

# First test: HA setup with etcd
kubectl apply -f operator/deploy/cr-etcd-ha.yaml
waitfor kubectl get etcdclusters.etcd.database.coreos.com/etcd-cluster
kubectl wait --for=condition=available --timeout=120s etcdclusters.etcd.database.coreos.com/etcd-cluster
kubectl wait --for=condition=healthy --timeout=180s vault/vault
kubectl delete -f operator/deploy/cr-etcd-ha.yaml
kubectl delete secret vault-unseal-keys
kubectl delete pvc --all
kubectl delete deployment vault-operator-etcd-operator-etcd-operator # the etcd operator is also unused from this point

# Second test: test the external secrets watcher work and match as expected
kubectl apply -f deploy/test-external-secrets-watch-deployment.yaml
kubectl wait --for=condition=healthy --timeout=120s vault/vault
test x`kubectl get pod vault-0 -o jsonpath='{.metadata.annotations.vault\.banzaicloud\.io/watched-secrets-sum}'` = "x"
kubectl delete -f deploy/test-external-secrets-watch-deployment.yaml
kubectl delete secret vault-unseal-keys

kubectl apply -f deploy/test-external-secrets-watch-secrets.yaml
kubectl apply -f deploy/test-external-secrets-watch-deployment.yaml
kubectl wait --for=condition=healthy --timeout=120s vault/vault
test x`kubectl get pod vault-0 -o jsonpath='{.metadata.annotations.vault\.banzaicloud\.io/watched-secrets-sum}'` = "xbac8dfa8bdf03009f89303c8eb4a6c8f2fd80eb03fa658f53d6d65eec14666d4"
kubectl delete -f deploy/test-external-secrets-watch-deployment.yaml
kubectl delete -f deploy/test-external-secrets-watch-secrets.yaml
kubectl delete secret vault-unseal-keys

# Third test: Raft HA setup
kubectl apply -f operator/deploy/cr-raft.yaml
kubectl wait --for=condition=healthy --timeout=150s vault/vault
kubectl delete -f operator/deploy/cr-raft.yaml
kubectl delete secret vault-unseal-keys
kubectl delete pvc --all

# Fourth test: HSM setup with SoftHSM
kubectl apply -f operator/deploy/cr-hsm-softhsm.yaml
kubectl wait --for=condition=healthy --timeout=120s vault/vault
kubectl delete -f operator/deploy/cr-hsm-softhsm.yaml
kubectl delete secret vault-unseal-keys
kubectl delete pvc --all

# Fifth test: single node cluster with defined PriorityClass via vaultPodSpec and vaultConfigurerPodSpec
kubectl create clusterrolebinding oidc-reviewer --clusterrole=system:service-account-issuer-discovery --group=system:unauthenticated
kubectl apply -f operator/deploy/priorityclass.yaml
kubectl apply -f operator/deploy/cr-priority.yaml
kubectl wait --for=condition=healthy --timeout=120s vault/vault

# Leave this instance for further tests

# Run a client tests

# Give bank-vaults some time to let the Kubernetes auth backend configuration happen
sleep 20

# Run an internal client which tries to read from Vault with the configured Kubernetes auth backend
kurun run cmd/examples/main.go

# Only kind is configured to be able to run this test
kubectl delete -f operator/deploy/cr-priority.yaml
kubectl delete -f operator/deploy/priorityclass.yaml
kubectl delete secret vault-unseal-keys
kubectl delete pvc --all

# Sixth test: Run the OIDC authenticated client test
kubectl create namespace vswh # create the namespace beforehand, because we need the CA cert here as well
kubectl apply -f operator/deploy/cr-oidc.yaml
kubectl wait --for=condition=healthy --timeout=120s vault/vault

kurun apply -f hack/oidc-pod.yaml
waitfor "kubectl get pod/oidc -o json | jq -e '.status.phase == \"Succeeded\"'"

# Run the webhook test, the hello-secrets deployment should be successfully mutated
helm upgrade --install vault-secrets-webhook ./charts/vault-secrets-webhook \
    --set image.tag=latest \
    --set image.pullPolicy=IfNotPresent \
    --set configMapMutation=true \
    --set configmapFailurePolicy=Fail \
    --set podsFailurePolicy=Fail \
    --set secretsFailurePolicy=Fail \
    --set env.VAULT_ENV_IMAGE=ghcr.io/banzaicloud/vault-env:latest \
    --namespace vswh \
    --wait

kubectl apply -f deploy/test-secret.yaml
test "$(kubectl get secrets sample-secret -o jsonpath='{.data.\.dockerconfigjson}' | base64 --decode | jq -r '.auths[].username')" = "dockerrepouser"
test "$(kubectl get secrets sample-secret -o jsonpath='{.data.\.dockerconfigjson}' | base64 --decode | jq -r '.auths[].password')" = "dockerrepopassword"
test "$(kubectl get secrets sample-secret -o jsonpath='{.data.inline}' | base64 --decode)" = "Inline: secretId AWS_ACCESS_KEY_ID"

kubectl apply -f deploy/test-configmap.yaml
test "$(kubectl get cm sample-configmap -o jsonpath='{.data.aws-access-key-id}')" = "secretId"
test "$(kubectl get cm sample-configmap -o jsonpath='{.data.aws-access-key-id-formatted}')" = "AWS key in base64: c2VjcmV0SWQ="
test "$(kubectl get cm sample-configmap -o jsonpath='{.binaryData.aws-access-key-id-binary}')" = "secretId"
test "$(kubectl get cm sample-configmap -o jsonpath='{.data.aws-access-key-id-inline}')" = "AWS_ACCESS_KEY_ID: secretId AWS_SECRET_ACCESS_KEY: s3cr3t"

kubectl apply -f deploy/test-deployment-seccontext.yaml
kubectl wait --for=condition=available deployment/hello-secrets-seccontext --timeout=120s
check_webhook_seccontext
kubectl delete -f deploy/test-deployment-seccontext.yaml

kubectl apply -f deploy/test-deployment.yaml
kubectl wait --for=condition=available deployment/hello-secrets --timeout=120s
