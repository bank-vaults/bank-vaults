# Cloud permissions

The `bank-vaults` CLI command needs certain cloud permissions to function properly (init, unseal, configuration).

## Google Cloud

The Service Account in which the Pod is running has to have the following IAM Roles:

- Cloud KMS Admin
- Cloud KMS CryptoKey Encrypter/Decrypter
- Storage Admin

A CLI example how to run bank-vaults based Vault configuration on Google Cloud:

```bash
bank-vaults configure --google-cloud-kms-key-ring vault --google-cloud-kms-crypto-key bank-vaults --google-cloud-kms-location global --google-cloud-storage-bucket vault-ha --google-cloud-kms-project continual-flow-276578
```

## Azure

The Access Policy in which the Pod is running has to have the following IAM Roles:

- Key Vault All Key permissions
- Key Vault All Secret permissions

## AWS

### Enable IAM OIDC provider for cluster

To allow Vault pods to assume IAM roles in order to access AWS services the IAM OIDC provider needs to be enabled on the cluster.

```bash
cluster_name="mycluster"

# Enable OIDC provider
eksctl utils associate-iam-oidc-provider \
    --name $cluster_name \
    --approve

# Create IAM policy to allow Vault to read/write and encrypt unseal keys in an S3 bucket
policy_name="vault-operator"

# Create a KMS key and S3 bucket and enter details here
kms_key_arn="kms key ARN here"
s3_bucket_name="name of S3 bucket to store keys in"

cat > /tmp/operator-policy.json <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "s3:PutObject",
                "s3:GetObject",
                "kms:Decrypt",
                "kms:Encrypt"
            ],
            "Resource": [
                "$kms_key_arn",
                "arn:aws:s3:::$s3_bucket_name/*"
            ]
        },
        {
            "Effect": "Allow",
            "Action": "s3:ListBucket",
            "Resource": "arn:aws:s3:::$s3_bucket_name"
        }
    ]
}
EOF
policy_arn=$(aws iam create-policy \
    --policy-name $policy_name \
    --policy-document file:///tmp/operator-policy.json \
    | jq -r '.Policy.Arn')

# Cleanup
rm /tmp/operator-policy.json

# Kubernetes service account and IAM role setup
eksctl create iamserviceaccount \
    --name "vault-operator" \
    --namespace "vault-operator" \
    --cluster $cluster_name \
    --attach-policy-arn $policy_arn \
    --approve
```

### Getting the root token

After the Vault is successfully deployed, you will need to get the root token for first access.

```bash
# Fetch Vault root token, check bucket for actual name based on unsealConfig.aws.s3Prefix
aws s3 cp s3://$s3_bucket_name/vault-root /tmp/vault-root

export VAULT_TOKEN="$(aws kms decrypt \
  --ciphertext-blob fileb:///tmp/vault-root \
  --encryption-context Tool=bank-vaults \
  --query Plaintext --output text | base64 --decode)"
```


The Instance profile in which the Pod is running has to have the following IAM Policies:

- KMS: `kms:Encrypt, kms:Decrypt`
- S3:  `s3:GetObject, s3:PutObject` on object level and `s3:ListBucket` on bucket level

An example command how to init and unseal Vault on AWS:

```bash
bank-vaults unseal --init --mode aws-kms-s3 --aws-kms-key-id 9f054126-2a98-470c-9f10-9b3b0cad94a1 --aws-s3-region eu-west-1 --aws-kms-region eu-west-1 --aws-s3-bucket bank-vaults
```

When using existing unseal keys, you need to make sure to kms encrypt these with the proper `EncryptionContext`.
If this is not done, the invocation of `bank-vaults` will trigger an `InvalidCiphertextException` from AWS KMS.
An example how to encrypt the keys (specify `--profile` and `--region` accordingly):

```bash
aws kms encrypt --key-id "alias/kms-key-alias" --encryption-context "Tool=bank-vaults"  --plaintext fileb://vault-unseal-0.txt --output text --query CiphertextBlob | base64 -D > vault-unseal-0
```

From this point on copy the encrypted files to the appropriate S3 bucket.
As an additional security measure make sure to turn on encryption of the S3 bucket before uploading the files.

## Alibaba Cloud

A CLI example how to run bank-vaults based Vault unsealing on Alibaba Cloud:

```bash
bank-vaults unseal --mode alibaba-kms-oss --alibaba-access-key-id ${ALIBABA_ACCESS_KEY_ID} --alibaba-access-key-secret ${ALIBABA_ACCESS_KEY_SECRET} --alibaba-kms-region eu-central-1 --alibaba-kms-key-id ${ALIBABA_KMS_KEY_UUID} --alibaba-oss-endpoint oss-eu-central-1.aliyuncs.com --alibaba-oss-bucket bank-vaults
```

## Kubernetes

The Service Account in which the bank-vaults Pod is running has to have the following Roles rules:

```yaml
rules:
- apiGroups: [""]
  resources: ["secrets"]
  verbs:     ["get", "create", "update"]
```
