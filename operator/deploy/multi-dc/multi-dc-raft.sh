#!/bin/bash

set -euo pipefail

# REQUIREMENTS:
# - kubectl
# - helm3
# - https://github.com/arschles/envtpl
# - jq
#
# - 3 Kubernetes clusters

# GET the root token:
# aws s3api get-object --bucket bank-vaults --key raft-vault-root raft-vault-root
# aws kms decrypt --ciphertext-blob fileb://raft-vault-root --query Plaintext --output text --encryption-context Tool=bank-vaults | base64 -D

# Check the Raft leader:
# curl -H "X-Vault-Token: $VAULT_TOKEN" -v -k https://a81d3cae9150211ea9ca606a2178004f-612493827.eu-west-3.elb.amazonaws.com:8200/v1/sys/storage/raft/configuration | jq

# Usage:
# ./mult-dc-raft.sh install primary-kubeconfig.yaml secondary-kubeconfig.yaml tertiary-kubeconfig.yaml

if [ $# = 0 ]; then
    echo "The Bank-Vaults Multi-DC CLI"
    echo
    echo "Usage:"
    echo "  $0 [command]"
    echo
    echo "Available Commands:"
    echo "  install    Installs a Vault cluster to one or more Kubernetes clusters"
    echo "  delete     Removes a Vault cluster from one or more Kubernetes clusters"
    echo "  status     Displays the status a cluster to one or more Kubernetes clusters"
    exit 0
fi

COMMAND=$1

function waitfor {
    WAIT_MAX=0
    until $@ &> /dev/null || [ $WAIT_MAX -eq 45 ]; do
        sleep 1
        (( WAIT_MAX = WAIT_MAX + 1 ))
    done
}

function get_elb_dns {
    local INSTANCE=$1
    kubectl get service $INSTANCE -o jsonpath='{.status.loadBalancer.ingress[0].hostname}'
}

function get_region {
    kubectl get nodes -o json | jq -r '.items[0].metadata.labels["failure-domain.beta.kubernetes.io/region"]'
}

if [ $COMMAND = "install" ]; then

    PRIMARY_KUBECONFIG=$2
    SECONDARY_KUBECONFIG=$3
    TERTIARY_KUBECONFIG=$4

    function create_aws_secret {
        kubectl get secret aws 2> /dev/null || kubectl create secret generic aws \
            --from-literal=AWS_ACCESS_KEY_ID=$AWS_ACCESS_KEY_ID \
            --from-literal=AWS_SECRET_ACCESS_KEY=$AWS_SECRET_ACCESS_KEY
    }

    function fix_elb_healthcheck {
        local INSTANCE=$1
        local REGION=$2
        ELB_DNS=$(kubectl get service $INSTANCE -o jsonpath='{.status.loadBalancer.ingress[0].hostname}')
        local ELB_NODE_PORT=$(kubectl get service $INSTANCE -o jsonpath='{.spec.ports[0].nodePort}')
        local ELB_NAME=$(echo $ELB_DNS | cut -f1 -d-)

        echo "Fixing AWS ELB healthcheck..."

        aws elb configure-health-check --region $REGION --load-balancer-name $ELB_NAME --health-check Target=SSL:${ELB_NODE_PORT},Interval=10,UnhealthyThreshold=6,HealthyThreshold=2,Timeout=5 > /dev/null
    }

    function install_instance {
        local INSTANCE=$1
        local KUBECONFIG=$2

        export KUBECONFIG=$KUBECONFIG

        local REGION=$(get_region)

        helm upgrade --install vault-operator banzaicloud-stable/vault-operator --set image.tag=multi-dc --wait

        create_aws_secret

        kubectl apply -f operator/deploy/rbac.yaml
        cat operator/deploy/multi-dc/cr-${INSTANCE}.yaml | envtpl | kubectl apply -f -

        echo "Waiting for for ${INSTANCE} vault instance..."
        waitfor waitfor kubectl get pod/vault-${INSTANCE}-0
        kubectl wait --for=condition=ready pod/vault-${INSTANCE}-0 --timeout=120s

        fix_elb_healthcheck vault-${INSTANCE} $REGION
    }


    ## Primary

    install_instance primary $PRIMARY_KUBECONFIG

    export RAFT_LEADER_ADDRESS=$ELB_DNS

    KUBECONFIG=$PRIMARY_KUBECONFIG kubectl get secrets vault-primary-tls -o json | jq 'del(.metadata.ownerReferences)' | jq 'del(.metadata.resourceVersion)' | jq 'del(.metadata.uid)' > vault-primary-tls.json

    ## Secondary

    KUBECONFIG=$SECONDARY_KUBECONFIG kubectl apply -f vault-primary-tls.json

    install_instance secondary $SECONDARY_KUBECONFIG

    ## Tertiary

    KUBECONFIG=$TERTIARY_KUBECONFIG kubectl apply -f vault-primary-tls.json

    install_instance tertiary $TERTIARY_KUBECONFIG

    ## Cleanup

    rm vault-primary-tls.json

    echo -e "\nMulti-DC Vault cluster setup completed."

elif [ $COMMAND = "status" ]; then

    PRIMARY_KUBECONFIG=$2
    export KUBECONFIG=$PRIMARY_KUBECONFIG

    REGION=$(get_region)

    aws s3api get-object --bucket bank-vaults-0 --key raft-vault-root raft-vault-root > /dev/null
    export VAULT_TOKEN=$(aws --region $REGION kms decrypt --ciphertext-blob fileb://raft-vault-root --query Plaintext --output text --encryption-context Tool=bank-vaults | base64 -D)
    
    rm raft-vault-root

    export VAULT_SKIP_VERIFY="true"

    export VAULT_ADDR=https://`get_elb_dns "vault-primary"`:8200
    
    vault operator raft configuration -format json | jq

elif [ $COMMAND = "remove" ]; then

    PRIMARY_KUBECONFIG=$2
    SECONDARY_KUBECONFIG=$3
    TERTIARY_KUBECONFIG=$4

    function delete_instance {
        local KUBECONFIG=$1
        export KUBECONFIG=$KUBECONFIG
        helm delete vault-operator
        kubectl delete pvc --all
        kubectl delete secret aws
    }

    delete_instance $PRIMARY_KUBECONFIG
    delete_instance $SECONDARY_KUBECONFIG
    delete_instance $TERTIARY_KUBECONFIG

    aws s3 rm s3://bank-vaults-0 --recursive
    aws s3 rm s3://bank-vaults-1 --recursive

else

    echo "unknown command: $COMMAND"

fi