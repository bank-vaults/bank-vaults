# Unseal Keys

The keys that will be stored are:

- `vault-root`, which is the Vault's root token
- `vault-unseal-N`, where `N` is a number, starting at 0 up to the maximum defined minus 1, e.g. 5 unseal keys will be `vault-unseal-0` up to including `vault-unseal-4`

HashiCorp [recommends to revoke root tokens](https://www.vaultproject.io/docs/concepts/tokens.html#root-tokens) after the initial set up of Vault has been completed.
To unseal Vault the `vault-root` token is not needed and can be removed from the storage if it was put there via the `--init` call to `bank-vaults`.

## Decrypting root token

### AWS

To use the KMS-encrypted root token with Vault CLI:

Required CLI tools:
- aws

1. Download root token file to your local file system
1. Decrypt the token and save it as an environment variable
    ```bash
    export VAULT_TOKEN="$(aws kms decrypt --ciphertext-blob fileb://<encrypted token file> --encryption-context Tool=bank-vaults --query Plaintext --output text | base64 --decode)"
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
