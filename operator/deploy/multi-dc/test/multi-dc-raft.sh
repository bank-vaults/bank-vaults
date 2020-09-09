#!/bin/bash

set -euo pipefail

# REQUIREMENTS:
# - kubectl
# - helm3
# - https://github.com/subfuzion/envtpl
# - jq
#
# - 3 Kubernetes clusters
#

# Install:
# ./mult-dc-raft.sh install primary-kubeconfig.yaml secondary-kubeconfig.yaml tertiary-kubeconfig.yaml

# Check the Raft leader:
# ./mult-dc-raft.sh status primary-kubeconfig.yaml

# Uninstall
# ./mult-dc-raft.sh uninstall primary-kubeconfig.yaml secondary-kubeconfig.yaml tertiary-kubeconfig.yaml

if [ $# = 0 ]; then
    echo "The Bank-Vaults Multi-DC CLI"
    echo
    echo "Usage:"
    echo "  $0 [command]"
    echo
    echo "Available Commands:"
    echo "  install    Installs a Vault cluster to one or more Kubernetes clusters"
    echo "  uninstall  Uninstalls a Vault cluster from one or more Kubernetes clusters"
    echo "  status     Displays the status a cluster to one or more Kubernetes clusters"
    exit 0
fi

COMMAND=$1

export KIND_EXPERIMENTAL_DOCKER_NETWORK=bridge

function waitfor {
    WAIT_MAX=0
    until $@ &> /dev/null || [ $WAIT_MAX -eq 45 ]; do
        sleep 1
        (( WAIT_MAX = WAIT_MAX + 1 ))
    done
}

function metallb_setup {
    export METALLB_ADDRESS_RANGE=$1
    kubectl apply -f https://raw.githubusercontent.com/metallb/metallb/v0.9.3/manifests/namespace.yaml
    kubectl apply -f https://raw.githubusercontent.com/metallb/metallb/v0.9.3/manifests/metallb.yaml
    cat operator/deploy/multi-dc/test/metallb-config.yaml | envtpl | kubectl apply -f -
}

function infra_setup {
    kind create cluster --name primary
    metallb_setup 172.17.1.1-172.17.1.10

    kind create cluster --name secondary
    metallb_setup 172.17.1.11-172.17.1.20

    kind create cluster --name tertiary
    metallb_setup 172.17.1.21-172.17.1.30

    docker run -d --rm --network kind -e VAULT_DEV_ROOT_TOKEN_ID=227e1cce-6bf7-30bb-2d2a-acc854318caf --name central-vault vault
    export CENTRAL_VAULT_ADDRESS=$(docker inspect central-vault --format '{{.NetworkSettings.Networks.kind.IPAddress}}')
}

function install_instance {
    local INSTANCE=$1

    helm upgrade --install vault-operator charts/vault-operator --wait --set image.tag=master --set image.pullPolicy=Always

    kubectl apply -f operator/deploy/rbac.yaml
    cat operator/deploy/multi-dc/test/cr-${INSTANCE}.yaml | envtpl | kubectl apply -f -

    echo "Waiting for for ${INSTANCE} vault instance..."
    waitfor kubectl get pod/vault-${INSTANCE}-0

    kubectl wait --for=condition=ready pod/vault-${INSTANCE}-0 --timeout=120s
}

if [ $COMMAND = "install" ]; then

    infra_setup

    export CENTRAL_VAULT_ADDRESS=$(docker inspect central-vault --format '{{.NetworkSettings.Networks.kind.IPAddress}}')

    ## Primary
    kubectl config use-context kind-primary

    install_instance primary

    export RAFT_LEADER_ADDRESS=$(kubectl get service vault-primary -o jsonpath='{.status.loadBalancer.ingress[0].ip}')

    kubectl get secrets vault-primary-tls -o json | jq 'del(.metadata.ownerReferences)' | jq 'del(.metadata.resourceVersion)' | jq 'del(.metadata.uid)' > vault-primary-tls.json

    ## Secondary
    kubectl config use-context kind-secondary

    kubectl apply -f vault-primary-tls.json

    install_instance secondary

    ## Tertiary
    kubectl config use-context kind-tertiary

    kubectl apply -f vault-primary-tls.json

    install_instance tertiary

    ## Cleanup

    rm vault-primary-tls.json

    echo -e "\nMulti-DC Vault cluster setup completed."

elif [ $COMMAND = "status" ]; then

    PRIMARY_KUBECONFIG=$2
    export KUBECONFIG=$PRIMARY_KUBECONFIG

    BUCKET=bank-vaults
    REGION=eu-west-1

    aws s3api get-object --bucket ${BUCKET} --key raft-vault-root raft-vault-root > /dev/null
    export VAULT_TOKEN=$(aws --region $REGION kms decrypt --ciphertext-blob fileb://raft-vault-root --query Plaintext --output text --encryption-context Tool=bank-vaults | base64 -D)
    
    rm raft-vault-root

    export VAULT_SKIP_VERIFY="true"

    export VAULT_ADDR=https://$(get_elb_dns):8200
    
    vault operator raft list-peers -format json | jq

elif [ $COMMAND = "uninstall" ]; then

    PRIMARY_KUBECONFIG=$2
    SECONDARY_KUBECONFIG=$3
    TERTIARY_KUBECONFIG=$4

    function delete_instance {
        local KUBECONFIG=$1
        export KUBECONFIG=$KUBECONFIG
        helm delete vault-operator
        kubectl delete vault --all
        kubectl delete pvc --all
        kubectl delete secret aws
    }

    delete_instance $PRIMARY_KUBECONFIG
    delete_instance $SECONDARY_KUBECONFIG
    delete_instance $TERTIARY_KUBECONFIG

    aws s3 rm s3://bank-vaults --recursive
    aws s3 rm s3://bank-vaults-0 --recursive

else

    echo "unknown command: $COMMAND"

fi
