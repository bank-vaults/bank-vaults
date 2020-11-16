#!/bin/bash

set -euo pipefail

# REQUIREMENTS:
# - kubectl
# - helm3
# - https://github.com/subfuzion/envtpl
# - jq
# - aws
#
# - 3 Kubernetes clusters
# - AWS credentials in:
#   - AWS_ACCESS_KEY_ID
#   - AWS_SECRET_ACCESS_KEY

# GET the root token:
# aws s3api get-object --bucket bank-vaults --key raft-vault-root raft-vault-root
# aws kms decrypt --ciphertext-blob fileb://raft-vault-root --query Plaintext --output text --encryption-context Tool=bank-vaults | base64 -D

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

function waitfor {
    WAIT_MAX=0
    until $@ &> /dev/null || [ $WAIT_MAX -eq 45 ]; do
        sleep 1
        (( WAIT_MAX = WAIT_MAX + 1 ))
    done
}

function get_elb_dns {
    kubectl get service -l app.kubernetes.io/name=vault -o jsonpath='{.items[0].status.loadBalancer.ingress[0].hostname}'
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

        helm upgrade --install vault-operator charts/vault-operator --wait --set image.tag=latest --set image.pullPolicy=Always

        create_aws_secret

        kubectl apply -f operator/deploy/rbac.yaml
        cat operator/deploy/multi-dc/aws/cr-${INSTANCE}.yaml | envtpl | kubectl apply -f -

        echo "Waiting for for ${INSTANCE} vault instance..."
        waitfor kubectl get pod/vault-${INSTANCE}-0

        fix_elb_healthcheck vault-${INSTANCE} $REGION

        kubectl wait --for=condition=ready pod/vault-${INSTANCE}-0 --timeout=120s
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
