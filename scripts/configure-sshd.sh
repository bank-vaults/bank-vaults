#!/bin/bash

# This script configures your sshd daemon with the SSH certificats from Vault.
# It assumes that it is running in automation on a VM with Vault AppRole, thus needs:
#  - VAULT_ROLE_ID: the AppRole's RoleID
#  - VAULT_SECRET_ID: the AppRole's SecretID
#  - TRUSTED_USER_CA_URL: The Vault URL where the public certificates are exposed

set -euo pipefail

VAULT_VERSION=0.10.0

if [[ ! -z "${TRUSTED_USER_CA_URL}" ]]; then
  curl ${TRUSTED_USER_CA_URL} > /etc/ssh/trusted-user-ca-keys.pem
  echo -e "\nTrustedUserCAKeys /etc/ssh/trusted-user-ca-keys.pem" >> /etc/ssh/sshd_config
  if [[ ! -z "${VAULT_ROLE_ID}" && ! -z "${VAULT_SECRET_ID}" ]]; then
    curl -O https://releases.hashicorp.com/vault/${VAULT_VERSION}/vault_${VAULT_VERSION}_linux_amd64.zip
    unzip vault_${VAULT_VERSION}_linux_amd64.zip -d /usr/bin/
    rm vault_${VAULT_VERSION}_linux_amd64.zip
    export VAULT_ADDR=${TRUSTED_USER_CA_URL%/v1*}
    export VAULT_TOKEN=$(vault write -field token auth/approle/login role_id=${VAULT_ROLE_ID} secret_id=${VAULT_SECRET_ID})
    vault write -field=signed_key ssh-host-signer/sign/hostrole cert_type=host public_key=@/etc/ssh/ssh_host_rsa_key.pub > /etc/ssh/ssh_host_rsa_key-cert.pub
    echo -e "\nHostCertificate /etc/ssh/ssh_host_rsa_key-cert.pub" >> /etc/ssh/sshd_config
  fi
  service ssh restart
fi
