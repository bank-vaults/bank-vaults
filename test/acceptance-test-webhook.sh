#!/usr/bin/env bash
set -xeo pipefail

function finish {
    echo "The last command was: $(history 1 | awk '{print $2}')"
    kubectl get pods -A
    kubectl describe pods -A
    kubectl describe services -A
    kubectl logs deployment/vault-operator
    kubectl logs deployment/vault-configurer
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

kubectl create namespace vswh --dry-run=client -o yaml | kubectl apply -f -

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

kubectl apply -f operator/deploy/cr-raft-1.yaml
kubectl wait --for=condition=healthy --timeout=150s vault/vault

# Run the webhook test, the hello-secrets deployment should be successfully mutated
helm upgrade --install vault-secrets-webhook ./charts/vault-secrets-webhook \
    --set image.tag=latest \
    --set image.pullPolicy=IfNotPresent \
    --set configMapMutation=true \
    --set configmapFailurePolicy=Fail \
    --set podsFailurePolicy=Fail \
    --set secretsFailurePolicy=Fail \
    --set vaultEnv.tag=latest \
    --namespace vswh \
    --wait

kubectl wait --namespace vswh --for=condition=ready --timeout=150s pods -l app.kubernetes.io/name=vault-secrets-webhook

kubectl apply -f deploy/test-secret.yaml
test "$(kubectl get secrets sample-secret -o jsonpath='{.data.\.dockerconfigjson}' | base64 --decode | jq -r '.auths[].username')" = "dockerrepouser"
test "$(kubectl get secrets sample-secret -o jsonpath='{.data.\.dockerconfigjson}' | base64 --decode | jq -r '.auths[].password')" = "dockerrepopassword"
test "$(kubectl get secrets sample-secret -o jsonpath='{.data.inline}' | base64 --decode)" = "Inline: secretId AWS_ACCESS_KEY_ID"

kubectl apply -f deploy/test-configmap.yaml
test "$(kubectl get cm sample-configmap -o jsonpath='{.data.aws-access-key-id}')" = "secretId"
test "$(kubectl get cm sample-configmap -o jsonpath='{.data.aws-access-key-id-formatted}')" = "AWS key in base64: c2VjcmV0SWQ="
test "$(kubectl get cm sample-configmap -o jsonpath='{.binaryData.aws-access-key-id-binary}')" = "secretId"
test "$(kubectl get cm sample-configmap -o jsonpath='{.data.aws-access-key-id-inline}')" = "AWS_ACCESS_KEY_ID: secretId AWS_SECRET_ACCESS_KEY: s3cr3t"

# Make sure file templating works
kubectl apply -f deploy/test-deploy-templating.yaml
sleep 10
kubectl wait pod -l app.kubernetes.io/name=test-templating --for=condition=ready --timeout=120s -A
test "$(kubectl exec -it "$(kubectl get pods --selector=app.kubernetes.io/name=test-templating -o=jsonpath='{.items[0].metadata.name}')" -c alpine -- cat /vault/secrets/config.yaml | jq '.id' | xargs )" = "secretId"

kubectl apply -f deploy/test-deployment-seccontext.yaml
kubectl wait --for=condition=available deployment/hello-secrets-seccontext --timeout=120s
check_webhook_seccontext
kubectl delete -f deploy/test-deployment-seccontext.yaml

kubectl apply -f deploy/test-deployment.yaml
kubectl wait --for=condition=available deployment/hello-secrets --timeout=120s

echo "Test has finished"
