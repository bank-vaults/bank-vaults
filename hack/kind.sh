#!/bin/sh
set -o errexit

# create registry container unless it already exists
reg_name='kind-registry'
reg_port='5000'
running="$(docker inspect -f '{{.State.Running}}' "${reg_name}" 2>/dev/null || true)"
if [ "${running}" != 'true' ]; then
  docker run \
    -d --restart=always -p "127.0.0.1:${reg_port}:5000" --name "${reg_name}" \
    registry:2
fi

# create a cluster with the local registry enabled in containerd
cat <<EOF | kind create cluster --config=-
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
containerdConfigPatches:
- |-
  [plugins."io.containerd.grpc.v1.cri".registry.mirrors."localhost:${reg_port}"]
    endpoint = ["http://${reg_name}:5000"]
EOF

# connect the registry to the cluster network
# (the network may already be connected)
docker network connect "kind" "${reg_name}" || true

# Document the local registry
# https://github.com/kubernetes/enhancements/tree/issue-1531-fix/keps/sig-cluster-lifecycle/generic/1755-communicating-a-local-registry
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: ConfigMap
metadata:
  name: local-registry-hosting
  namespace: kube-public
data:
  localRegistryHosting.v1: |
    host: "localhost:${reg_port}"
    help: "https://kind.sigs.k8s.io/docs/user/local-registry/"
EOF

docker tag ghcr.io/banzaicloud/vault-operator:issue-1531-fix localhost:5000/vault-operator:issue-1531-fix
docker push localhost:5000/vault-operator:issue-1531-fix
docker tag ghcr.io/banzaicloud/bank-vaults:issue-1531-fix localhost:5000/bank-vaults:issue-1531-fix
docker push localhost:5000/bank-vaults:issue-1531-fix
docker tag ghcr.io/banzaicloud/vault-secrets-webhook:issue-1531-fix localhost:5000/vault-secrets-webhook:issue-1531-fix
docker push localhost:5000/vault-secrets-webhook:issue-1531-fix
#helm upgrade --install vault-operator charts/vault-operator --set=image.repository=localhost:5000/vault-operator --set=image.tag=issue-1531-fix
#kubectl apply -f https://raw.githubusercontent.com/banzaicloud/bank-vaults/issue-1531-fix/operator/deploy/rbac.yaml
#kubectl apply -f https://raw.githubusercontent.com/banzaicloud/bank-vaults/issue-1531-fix/operator/deploy/cr.yaml
#kubectl apply -f cr.yaml
