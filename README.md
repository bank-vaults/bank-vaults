[![Docker Automated build](https://img.shields.io/docker/automated/banzaicloud/bank-vaults.svg)](https://hub.docker.com/r/banzaicloud/bank-vaults/)
[![GoDoc](https://godoc.org/github.com/banzaicloud/bank-vaults?status.svg)](https://godoc.org/github.com/banzaicloud/bank-vaults)
[![CircleCI](https://circleci.com/gh/banzaicloud/bank-vaults/tree/master.svg?style=shield)](https://circleci.com/gh/banzaicloud/bank-vaults/tree/master)
[![Go Report Card](https://goreportcard.com/badge/github.com/banzaicloud/bank-vaults)](https://goreportcard.com/report/github.com/banzaicloud/bank-vaults)

*Bank Vaults is a thick, tricky, shifty right with a fast and intense tube for experienced surfers only, located on Mentawai. Think heavy steel doors, secret unlocking combinations and burly guards with smack-down attitude. Watch out for clean-up sets.*

*Bank Vaults is an umbrella project which provides various tools for Vault to make using and operating Hashicorp Vault easier. Its a wrapper for the official Vault client with automatic token renewal and built in Kubernetes support, dynamic database credential provider for Golang SQL based clients. It has a CLI tool to automatically initialize, unseal and configure Vault. It also provides a Kubernetes operator for provisioning, and a mutating webhook for injecting secrets.*

---

**Bank Vaults** is a core building block of the **[Banzai Cloud Pipeline](https://github.com/banzaicloud/pipeline)** platform. Some of the usage patterns are highlighted through these blog posts:

**Securing Kubernetes deployments with Vault:**

- [Authentication and authorization of Pipeline users with OAuth2 and Vault](https://banzaicloud.com/blog/oauth2-vault/)
- [Dynamic credentials with Vault using Kubernetes Service Accounts](https://banzaicloud.com/blog/vault-dynamic-secrets/)
- [Dynamic SSH with Vault and Pipeline](https://banzaicloud.com/blog/vault-dynamic-ssh/)
- [Secure Kubernetes Deployments with Vault and Pipeline](https://banzaicloud.com/blog/hashicorp-guest-post/)
- [Vault Operator](https://banzaicloud.com/blog/vault-operator/)
- [Vault unseal flow with KMS](https://banzaicloud.com/blog/vault-unsealing/)
- [Monitoring Vault on Kubernetes using Cloud Native technologies](https://banzaicloud.com/blog/monitoring-vault-grafana/)
- [Inject secrets directly into pods from Vault](https://banzaicloud.com/blog/inject-secrets-into-pods-vault/)

We use Vault across our large Kubernetes deployments and all the projects were `reinventing` the wheel. We have externalized all the codebase into this project and removed all the [Pipeline](https://github.com/banzaicloud/pipeline) and [Hollowtrees](https://github.com/banzaicloud/hollowtrees) dependencies thus this project can be used independently as a CLI tool to manage Vault, a Golang library to build upon (OAuth2 tokens, K8s auth, Vault operator, dynamic secrets, cloud credential storage, etc), Helm chart for a HA cluster, operator, mutating webhook and a collection of scripts to support some advanced features (dynamic SSH, etc).

>We take bank-vaults' security and our users' trust very seriously. If you believe you have found a security issue in bank-vaults, please contact us at security@banzaicloud.com.

## Table of Contents

- [The CLI tool](#the-cli-tool)
- [The Go library](#the-go-library)
- [Helm Chart](#helm-chart)
- [Operator](#operator)
- [Mutating Webhook](#mutating-webhook)
- [Unseal Keys](#unseal-keys)
- [Examples](#examples)
- [Getting and Installing](#getting-and-installing)
- [Monitoring](#monitoring)
- [Contributing](#contributing)
- [Credits](#credits)

## The CLI tool

The `bank-vaults` CLI tool is to help automate the setup and management of HashiCorp Vault.

Features:

- Initializes Vault and stores the root token and unseal keys in one of the followings:
  - AWS KMS keyring (backed by S3)
  - Azure Key Vault
  - Google Cloud KMS keyring (backed by GCS)
  - Alibaba Cloud KMS (backed by OSS)
  - Kubernetes Secrets (should be used only for development purposes)
  - Dev Mode (useful for `vault server -dev` dev mode Vault servers)
  - Files (backed by files, should be used only for development purposes)
- Automatically unseals Vault with these keys
- Continuously configures Vault with a YAML/JSON based external configuration (besides the [standard Vault configuration](https://www.vaultproject.io/docs/configuration/index.html))
  - If the configuration is updated Vault will be reconfigured
  - It supports configuring Vault secret engines, plugins, auth methods, and policies

### Example external Vault configuration

```yaml
# Allows creating policies in Vault which can be used later on in roles
# for the Kubernetes based authentication.
# See https://www.vaultproject.io/docs/concepts/policies.html for more information.
policies:
  - name: allow_secrets
    rules: path "secret/*" {
             capabilities = ["create", "read", "update", "delete", "list"]
           }
  - name: readonly_secrets
    rules: path "secret/*" {
             capabilities = ["read", "list"]
           }

# Allows configuring Auth Methods in Vault (Kubernetes and GitHub is supported now).
# See https://www.vaultproject.io/docs/auth/index.html for more information.
auth:
  - type: kubernetes
    # If you want to configure with specific kubernets service account instead of default service account
    # https://www.vaultproject.io/docs/auth/kubernetes.html
    # config:
    #  token_reviewer_jwt: your_service_account_jwt
    #  kubernetes_ca_cert: -----BEGIN CERTIFICATE-----.....-----END CERTIFICATE-----
    #  kubernetes_host: https://192.168.99.100:8443
    # Allows creating roles in Vault which can be used later on for the Kubernetes based
    # authentication.
    #  See https://www.vaultproject.io/docs/auth/kubernetes.html#creating-a-role for
    # more information.
    roles:
      # Allow every pod in the default namespace to use the secret kv store
      - name: default
        bound_service_account_names: default
        bound_service_account_namespaces: default
        policies: allow_secrets
        ttl: 1h

  # Allows creating team mappings in Vault which can be used later on for the GitHub
  # based authentication.
  # See https://www.vaultproject.io/docs/auth/github.html#configuration for
  # more information.
  - type: github
    config:
      organization: banzaicloud
    map:
      # Map the banzaicloud dev team on GitHub to the dev policy in Vault
      teams:
        dev: dev
      # Map myself to the root policy in Vault
      users:
        bonifaido: allow_secrets

  # Allows creating roles in Vault which can be used later on for AWS
  # IAM based authentication.
  # See https://www.vaultproject.io/docs/auth/aws.html for
  # more information.
  - type: aws
    config:
      access_key: VKIAJBRHKH6EVTTNXDHA
      secret_key: vCtSM8ZUEQ3mOFVlYPBQkf2sO6F/W7a5TVzrl3Oj
      iam_server_id_header_value: vault-dev.example.com # consider setting this to the Vault server's DNS name
    crossaccountrole:
    # Add cross account number and role to assume in the cross account
    # https://www.vaultproject.io/api/auth/aws/index.html#create-sts-role
    - sts_account: 12345671234
      sts_role_arn: arn:aws:iam::12345671234:role/crossaccountrole
    roles:
    # Add roles for AWS instances or principals
    # See https://www.vaultproject.io/api/auth/aws/index.html#create-role
    - name: dev-role-iam
      bound_iam_principal_arn: arn:aws:iam::123456789012:role/dev-vault
      policies: allow_secrets
      period: 1h
    - name: cross-account-role
      bound_iam_principal_arn: arn:aws:iam::12345671234:role/crossaccountrole
      policies: allow_secrets
      period: 1h

  # Allows creating roles in Vault which can be used later on for GCP
  # IAM based authentication.
  # See https://www.vaultproject.io/docs/auth/gcp.html for
  # more information.
  - type: gcp
    config:
      # Credentials context is service account's key. Can download when you create a key for service account. 
      # No need to manually create it. Just paste the json context as multiline yaml.
      credentials: |
        {
          "type": "service_account",
          "project_id": "PROJECT_ID",
          "private_key_id": "KEY_ID",
          "private_key": "-----BEGIN PRIVATE KEY-----.....-----END PRIVATE KEY-----\n",
          "client_email": "SERVICE_ACCOUNT@PROJECT_ID.iam.gserviceaccount.com",
          "client_id": "CLIENT_ID",
          "auth_uri": "https://accounts.google.com/o/oauth2/auth",
          "token_uri": "https://oauth2.googleapis.com/token",
          "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
          "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/SERVICE_ACCOUNT%40PROJECT_ID.iam.gserviceaccount.com"
        }
    roles:
    # Add roles for gcp service account
    # See https://www.vaultproject.io/api/auth/gcp/index.html#create-role
    - name: user-role
      type: iam
      project_id: PROJECT_ID
      policies: "readonly_secrets"
      bound_service_accounts: "USER_SERVICE_ACCOUNT@PROJECT_ID.iam.gserviceaccount.com"
    - name: admin-role
      type: iam
      project_id: PROJECT_ID
      policies: "allow_secrets"
      bound_service_accounts: "ADMIN_SERVICE_ACCOUNT@PROJECT_ID.iam.gserviceaccount.com"

  # Allows creating group mappings in Vault which can be used later on for the LDAP
  # based authentication.
  # See https://www.vaultproject.io/docs/auth/ldap.html#configuration for
  # more information.
  # Start an LDAP testing server: docker run -it --rm -p 389:389 -e LDAP_TLS=false --name ldap osixia/openldap
  # Start an LDAP admin server: docker run -it --rm -p 6443:443 --link ldap:ldap -e PHPLDAPADMIN_LDAP_HOSTS=ldap -e PHPLDAPADMIN_LDAP_CLIENT_TLS=false osixia/phpldapadmin
  - type: ldap
    description: LDAP directory auth.
    config:
      url: ldap://localhost
      binddn: "cn=admin,dc=example,dc=org"
      bindpass: "admin"
      userattr: uid
      userdn: "ou=users,dc=example,dc=org"
      groupdn: "ou=groups,dc=example,dc=org"
    groups:
      # Map the banzaicloud dev team on GitHub to the dev policy in Vault
      developers:
        policies: allow_secrets
    # Map myself to the allow_secrets policy in Vault
    users:
      bonifaido:
        groups: developers
        policies: allow_secrets
  # Allows machines/apps to authenticate with Vault-defined roles.
  # See https://www.vaultproject.io/docs/auth/approle.html for more information
  - type: approle
    roles:
    - name: default
      policies: allow_secrets
      secret_id_ttl: 10m
      token_num_uses: 10
      token_ttl: 20m
      token_max_ttl: 30m
      secret_id_num_uses: 40

# Add environment variables. Please reference below `my-mysql` part for usage.
# This is a list of K8S env. You can reference K8S document for detail
# https://kubernetes.io/docs/tasks/inject-data-application/define-environment-variable-container/
# https://kubernetes.io/docs/concepts/configuration/secret/#using-secrets-as-environment-variables
envsConfig:
  - name: ROOT_USERNAME
    valueFrom:
      secretKeyRef:
        name: mysql-login
        key: user
  - name: ROOT_PASSWORD
    valueFrom:
      secretKeyRef:
        name: mysql-login
        key: password

# Allows configuring Secrets Engines in Vault (KV, Database and SSH is tested,
# but the config is free form so probably more is supported).
# See https://www.vaultproject.io/docs/secrets/index.html for more information.
secrets:
  # This plugin stores arbitrary secrets within the configured physical storage for Vault.
  # See https://www.vaultproject.io/docs/secrets/kv/index.html for
  # more information.
  - path: secret
    type: kv
    description: General secrets.
    options:
      version: 2
  # Mounts non-default plugin's path
  - path: ethereum-gateway
    type: plugin
    plugin_name: ethereum-plugin
    description: Immutability's Ethereum Wallet

  # This plugin stores database credentials dynamically based on configured roles for
  # the MySQL database.
  # See https://www.vaultproject.io/docs/secrets/databases/mysql-maria.html for
  # more information.
  - type: database
    description: MySQL Database secret engine.
    configuration:
      config:
        - name: my-mysql
          plugin_name: "mysql-database-plugin"
          connection_url: "{{username}}:{{password}}@tcp(127.0.0.1:3306)/"
          allowed_roles: [pipeline]
          username: "${env `ROOT_USERNAME`}" # Example how to read environment variables
          password: "${env `ROOT_PASSWORD`}"
      roles:
        - name: pipeline
          db_name: my-mysql
          creation_statements: "GRANT ALL ON *.* TO '{{name}}'@'%' IDENTIFIED BY '{{password}}';"
          default_ttl: "10m"
          max_ttl: "24h"

  # Create a named Vault role for signing SSH client keys.
  # See https://www.vaultproject.io/docs/secrets/ssh/signed-ssh-certificates.html#client-key-signing for
  # more information.
  - type: ssh
    path: ssh-client-signer
    description: SSH Client Key Signing.
    configuration:
      config:
        - name: ca
          generate_signing_key: "true"
      roles:
        - name: my-role
          allow_user_certificates: "true"
          allowed_users: "*"
          key_type: "ca"
          default_user: "ubuntu"
          ttl: "24h"

  # The RabbitMQ secrets engine generates user credentials dynamically based on configured permissions and virtual hosts.
  # See https://www.vaultproject.io/docs/secrets/rabbitmq/index.html
  # Start a RabbitMQ testing server: docker run -it --rm -p 15672:15672 rabbitmq:3.7-management-alpine
  - type: rabbitmq
    description: local-rabbit
    configuration:
      config:
        - name: connection
          connection_uri: "http://localhost:15672"
          username: guest
          password: guest
      roles:
        - name: prod_role
          vhosts: '{"/web":{"write": "production_.*", "read": "production_.*"}}'

  # The PKI secrets engine generates X.509 certificates
  # See https://www.vaultproject.io/docs/secrets/pki/index.html for more information
  - type: pki
    description: Vault PKI Backend
    options:
      default_ttl: 168h
      max_ttl: 720h
    configuration:
      config:
      - name: urls
        issuing_certificates: https://vault.default:8200/v1/pki/ca
        crl_distribution_points: https://vault.default:8200/v1/pki/crl
      root/generate:
      - name: internal
        common_name: vault.default
      roles:
      - name: default
        allowed_domains: localhost,pod,svc,default
        allow_subdomains: true
        generate_lease: true
        ttl: 30m

# Registers a new plugin in Vault's plugin catalog. "plugin_directory" setting should be set it Vault server configuration
# and plugin binary should be present in plugin directory. Also, for some plugins readOnlyRootFilesystem Pod Security Policy
# should be disabled to allow RPC communication between plugin and Vault server via Unix socket
# See https://www.vaultproject.io/api/system/plugins-catalog.html and
#     https://github.com/hashicorp/go-plugin/blob/master/docs/internals.md for details.
plugins:
  - plugin_name: ethereum-plugin
    command: ethereum-vault-plugin --ca-cert=/vault/tls/client/ca.crt --client-cert=/vault/tls/server/server.crt --client-key=/vault/tls/server/server.key
    sha256: 62fb461a8743f2a0af31d998074b58bb1a589ec1d28da3a2a5e8e5820d2c6e0a
    type: secret
```

## The Go library

This repository contains several Go packages for interacting with Vault:

- `pkg/auth`

    A GitHub OAuth2 based authentication system as a Gin Middleware, stores JWT bearer tokens in Vault.

    ![authn](docs/images/authn-vault-flow.png)

- `pkg/vault`

    A wrapper for the official Vault client with automatic token renewal, and Kubernetes support.

    ![token](docs/images/token-request-vault-flow.png)

- `pkg/db`

    A helper for creating database source strings (MySQL/PostgreSQL) with database credentials dynamically based on configured Vault roles (instead of `username:password`).

    ![token](docs/images/vault-mySQL.gif)

- `pkg/tls`

    A simple package to generate self-signed TLS certificates. Useful for bootstrapping situations, when you can't use Vault's [PKI secret engine](https://www.vaultproject.io/docs/secrets/pki/index.html).

## Helm Charts

We have some fully fledged, production ready Helm charts for deploying [Vault](https://github.com/banzaicloud/banzai-charts/tree/master/vault) using `bank-vaults` and the [Vault Operator](https://github.com/banzaicloud/banzai-charts/tree/master/vault-operator). With the help of this chart you can run a HA Vault instance with automatic initialization, unsealing and external configuration which used to be a tedious manual operation. This chart can be used easily for development purposes as well.

## Operator

We have a Vault operator built on bank-vaults features as:

- external, API based configuration (secret engines, auth methods, policies) to automatically re/configure a Vault cluster
- automatic unsealing (AWS, GCE, Azure, Alibaba, Kubernetes Secrets (for dev purposes), Oracle)
- TLS support

The operator flow is the following:

![operator](docs/images/vaultoperator.png)

The source code can be found inside the [operator](operator/) directory.

### Deploying the operator

There are two ways to deploy the operator:

#### K8s deployment

```bash
kubectl apply -f operator/deploy/rbac.yaml
kubectl apply -f operator/deploy/operator.yaml
```

This will create a Kubernetes [CustomResourceDefinition](https://kubernetes.io/docs/tasks/access-kubernetes-api/extend-api-custom-resource-definitions/) called `Vault`.

A documented example of this CRD can be found in [operator/deploy/cr.yaml](operator/deploy/cr.yaml).

#### Helm chart

There is a Helm chart available to deploy the [Vault Operator](https://github.com/banzaicloud/banzai-charts/tree/master/vault-operator). 

```bash
helm init -c
helm repo add banzaicloud-stable http://kubernetes-charts.banzaicloud.com/branch/master
helm install banzaicloud-stable/vault-operator
```

For further details follow the operator's Helm chart [repository](https://github.com/banzaicloud/banzai-charts/tree/master/vault-operator).

## Mutating Webhook

The mutating admission webhook injects an executable to containers (in a very non-intrusive way) inside a Deployments/StatefulSets which than can request secrets from Vault through special environment variable definitions. The project is inspired by many, already existing projects (e.g.: `channable/vaultenv`, `hashicorp/envconsul`). The webhook checks if a container has environment variables defined in the following form, and reads the values for those variables directly from Vault during startup time:

```yaml
        env:
        - name: AWS_SECRET_ACCESS_KEY
          value: vault:secret/data/accounts/aws#AWS_SECRET_ACCESS_KEY
```

In this case the a init-container will be injected to the given Pod which copies a small binary, called `vault-env` into an in-memory volume and mounts that Volume to all the containers which have an environment variable definition like that. It also changes the `command` of the container to run `vault-env` instead of your application directly. `vault-env` starts up, connects to Vault with (currently with the [Kubernetes Auth method](https://www.vaultproject.io/docs/auth/kubernetes.html) checks the environment variables, and that has a reference to a value stored in Vault (`vault:secret/....`) will be replaced with that value read from the Secret backend, after this `vault-env` immediately executes (with `syscall.Exec()`) your process with the given arguments, replacing itself with that process.

**With this solution none of your Secrets stored in Vault will ever land in Kubernetes Secrets, thus in etcd.**

`vault-env` was designed to work in Kubernetes at the first place, but nothing stops you to use it outside Kubernetes as well. It can be configured with the standard Vault client's [environment variables](https://www.vaultproject.io/docs/commands/#environment-variables) (because there is a standard Go Vault client underneath).

Currently the Kubernetes Service Account based Vault authentication mechanism is used by `vault-env`, so it requests a Vault token based on the Service Account of the container it is injected into. Implementation is ongoing to use [Vault Agent's Auto-Auth](https://www.vaultproject.io/docs/agent/autoauth/index.html) to request tokens in an init-container with all the supported authentication mechanisms.

**Current limitations:**

- Only Vault KV 2 is supported right now.
- The command of the container has to be explicitly defined in the resource definition, the container's default `ENTRYPOINT` and `CMD` will not work (to overcome this is a work-in-progress).

### Deploying the webhook

#### Helm chart

There is a Helm chart available to deploy the [Vault Secrets Webhook](https://github.com/banzaicloud/banzai-charts/tree/master/vault-secrets-webhook). 

```bash
helm init -c
helm repo add banzaicloud-stable http://kubernetes-charts.banzaicloud.com/branch/master
helm install banzaicloud-stable/vault-secrets-webhook
```

For further details follow the webhook's Helm chart [repository](https://github.com/banzaicloud/banzai-charts/tree/master/vault-secrets-webhook).

### Example

Write a secret into Vault:

```bash
vault kv put secret/valami/aws AWS_SECRET_ACCESS_KEY=s3cr3t
```

This deployment will be mutated by the webhook, since it has at least one environment variable having a value which is a reference to a path in Vault:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: vault-test
  annotations:
    vault.security.banzaicloud.io/vault-addr: "https://vault:8200"
    vault.security.banzaicloud.io/vault-role: "default"
    vault.security.banzaicloud.io/vault-skip-verify: "true"
spec:
  replicas: 1
  selector:
    matchLabels:
      app: vault
  template:
    metadata:
      labels:
        app: vault
    spec:
      serviceAccountName: default
      containers:
      - name: alpine
        image: alpine
        command: ["sh", "-c", "echo $AWS_SECRET_ACCESS_KEY && echo going to sleep... && sleep 10000"]
        env:
        - name: AWS_SECRET_ACCESS_KEY
          value: vault:secret/data/valami/aws#AWS_SECRET_ACCESS_KEY
```

## Unseal Keys

The keys that will be stored are:

- `vault-root`, which is the Vault's root token
- `vault-unseal-N`, where `N` is a number, starting at 0 up to the maximum defined minus 1, e.g. 5 unseal keys will be `vault-unseal-0` up to including `vault-unseal-4`

HashiCorp [recommends to revoke root tokens](https://www.vaultproject.io/docs/concepts/tokens.html#root-tokens) after the initial set up of Vault has been completed.
To unseal Vault the `vault-root` token is not needed and can be removed from the storage if it was put there via the `--init` call to `bank-vaults`.

## Examples for using the library part

Some examples are in `cmd/examples/main.go`

- [Vault client example](https://github.com/banzaicloud/bank-vaults/blob/master/cmd/examples/main.go#L17)
- [Dynamic secrets for MySQL example with Gorm](https://github.com/banzaicloud/bank-vaults/blob/master/cmd/examples/main.go#L45)
- [JWTAuth tokens example with a Gin middleware](https://github.com/banzaicloud/bank-vaults/blob/master/cmd/examples/main.go#L53)

## Getting and Installing

```bash
go get github.com/banzaicloud/bank-vaults/cmd/bank-vaults
go get github.com/banzaicloud/bank-vaults/cmd/vault-env
```

or

```bash
docker pull banzaicloud/bank-vaults
docker pull banzaicloud/vault-operator
docker pull banzaicloud/vault-env
```

## Monitoring

At Banzai Cloud we prefer Prometheus for monitoring and use it also for Vault. If you configure, Vault can expose metrics through [statsd](https://www.vaultproject.io/docs/configuration/telemetry.html#statsd). Both the [Helm chart](https://github.com/banzaicloud/banzai-charts/tree/master/vault) and the Vault Operator installs the [Prometheus StatsD exporter](https://github.com/prometheus/statsd_exporter) and annotates the pods correctly with Prometheus annotations so Prometheus can discover and scrape them. All you have to do is to put the telemetry stanza into your Vault configuration:

```yaml
    telemetry:
      statsd_address: localhost:9125
```

## Cloud permissions

The `bank-vaults` CLI command needs certain cloud permissions to function properly (init, unseal, configuration).

### Google Cloud

The Service Account in which the Pod is running has to have the following IAM Roles:

- Cloud KMS Admin
- Cloud KMS CryptoKey Encrypter/Decrypter
- Storage Admin

A CLI example how to run bank-vaults based Vault configuration on Google Cloud:

```bash
bank-vaults configure --google-cloud-kms-key-ring vault --google-cloud-kms-crypto-key bank-vaults --google-cloud-kms-location global --google-cloud-storage-bucket vault-ha --google-cloud-kms-project continual-flow-276578
```

### Azure

The Access Policy in which the Pod is running has to have the following IAM Roles:

- Key Vault All Key permissions
- Key Vault All Secret permissions

### AWS

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

### Alibaba Cloud

A CLI example how to run bank-vaults based Vault unsealing on Alibaba Cloud:

```bash
bank-vaults unseal --mode alibaba-kms-oss --alibaba-access-key-id ${ALIBABA_ACCESS_KEY_ID} --alibaba-access-key-secret ${ALIBABA_ACCESS_KEY_SECRET} --alibaba-kms-region eu-central-1 --alibaba-kms-key-id ${ALIBABA_KMS_KEY_UUID} --alibaba-oss-endpoint oss-eu-central-1.aliyuncs.com --alibaba-oss-bucket bank-vaults
```

### Kubernetes

The Service Account in which the bank-vaults Pod is running has to have the following Roles rules:

```yaml
rules:
- apiGroups: [""]
  resources: ["secrets"]
  verbs:     ["get", "create", "update"]
```

### Contributing

If you find this project useful here's how you can help:

- Send a pull request with your new features and bug fixes
- Help new users with issues they may encounter
- Support the development of this project and star this repo!

## Credits

Kudos to HashiCorp for open sourcing Vault and making secret management easier and more secure.

## License

Copyright (c) 2017-2018 [Banzai Cloud, Inc.](https://banzaicloud.com)

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

[http://www.apache.org/licenses/LICENSE-2.0](http://www.apache.org/licenses/LICENSE-2.0)

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
