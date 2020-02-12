# Unseal Keys

Vault data and the unseal keys live together, if you delete a Vault instance installed by the operator or the Helm chart all your data and the unseal keys to that initialized state should remain untouched. Read more about it in the [official documentaion](https://www.vaultproject.io/docs/concepts/seal/).

The keys that will be stored by Bank-Vaults are:

- `vault-root`, which is the Vault's root token
- `vault-unseal-N`, where `N` is a number, starting at 0 up to the maximum defined minus 1, e.g. 5 unseal keys will be `vault-unseal-0` up to including `vault-unseal-4`

HashiCorp [recommends to revoke root tokens](https://www.vaultproject.io/docs/concepts/tokens.html#root-tokens) after the initial set up of Vault has been completed.
To unseal Vault the `vault-root` token is not needed and can be removed from the storage if it was put there via the `--init` call to `bank-vaults`.

## Decrypting root token

### AWS

To use the KMS-encrypted root token with Vault CLI:

Required CLI tools:
  - aws

Steps:

1. Download and decrypt the root token (and the unseal keys, but that is not mandatory) into a file on your local file system:
    ```bash
    BUCKET=bank-vaults-0
    REGION=eu-central-1

    for key in "vault-root" "vault-unseal-0" "vault-unseal-1" "vault-unseal-2" "vault-unseal-3" "vault-unseal-4"
    do
        aws s3 cp s3://${BUCKET}/${key} .

        aws kms decrypt \
            --region ${REGION} \
            --ciphertext-blob fileb://${key} \
            --encryption-context Tool=bank-vaults \
            --output text \
            --query Plaintext | base64 -d > ${key}.txt

        rm ${key}
    done
    ```

1. Save it as an environment variable:
    ```bash
    export VAULT_TOKEN="$(cat vault-root.txt)"
    ```

### Google Cloud

To use the KMS-encrypted root token with vault CLI:

Required CLI tools:
- `gcloud`
- `gsutil`

```bash
GOOGLE_PROJECT="my-project"
GOOGLE_REGION="us-central1"
BUCKET="bank-vaults-bucket"
KEYRING="beta"
KEY="beta"

export VAULT_TOKEN=$(gsutil cat gs://${BUCKET}/vault-root | gcloud kms decrypt \
                     --project ${GOOGLE_PROJECT} \
                     --location ${GOOGLE_REGION} \
                     --keyring ${KEYRING} \
                     --key ${KEY} \
                     --ciphertext-file - \
                     --plaintext-file -)
```

### Kubernetes

There is a Kubernetes Secret backed unseal storage in Bank-Vaults, you should be aware of that Kubernetes Secrets are base64 encoded only if you are not using a [EncryptionConfiguration](https://kubernetes.io/docs/tasks/administer-cluster/encrypt-data/) in your Kubernetes cluster.

```bash
VAULT_NAME="vault"

export VAULT_TOKEN=$(kubectl get secrets ${VAULT_NAME}-unseal-keys -o jsonpath={.data.vault-root} | base64 -d)
```

## Moving unseal keys to be managed by Bank-Vaults or migrating between cloud providers

If you need to move your Vault instance from one provider or an external managed Vault, you will have to store those the unseal keys and a root token in the Bank-Vaults format.

All examples assume that you have created files holding the root-token and the 5 unseal keys in plaintext:
- vault-root.txt
- vault-unseal-0.txt
- vault-unseal-1.txt
- vault-unseal-2.txt
- vault-unseal-3.txt
- vault-unseal-4.txt

For migrating the Vault storage data you will have to use [official migration command](https://www.vaultproject.io/docs/commands/operator/migrate/) provided by Vault.

### AWS

Moving the above mentioned files to an AWS bucket and encrypt them with KMS before:

```bash
REGION=eu-central-1
KMS_KEY_ID=02a2ba49-42ce-487f-b006-34c64f4b760e
BUCKET=bank-vaults-1

for key in "vault-root" "vault-unseal-0" "vault-unseal-1" "vault-unseal-2" "vault-unseal-3" "vault-unseal-4"
do
    aws kms encrypt \
        --region ${REGION} --key-id ${KMS_KEY_ID} \
        --plaintext fileb://${key}.txt \
        --encryption-context Tool=bank-vaults \
        --output text \
        --query CiphertextBlob | base64 -d > ${key}

    aws s3 cp ./${key} s3://${BUCKET}/

    rm ${key} ${key}.txt
done
```
