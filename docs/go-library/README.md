# The Go library

This repository contains several Go packages for interacting with Vault:

- `pkg/auth`

    A GitHub OAuth2 based authentication system as a Gin Middleware, stores JWT bearer tokens in Vault.

    ![authn](images/authn-vault-flow.png)

- `pkg/vault`

    A wrapper for the official Vault client with automatic token renewal, and Kubernetes support.

    ![token](images/token-request-vault-flow.png)

- `pkg/db`

    A helper for creating database source strings (MySQL/PostgreSQL) with database credentials dynamically based on configured Vault roles (instead of `username:password`).

    ![token](images/vault-mySQL.gif)

- `pkg/tls`

    A simple package to generate self-signed TLS certificates. Useful for bootstrapping situations, when you can't use Vault's [PKI secret engine](https://www.vaultproject.io/docs/secrets/pki/index.html).

## Examples for using the library part

Some examples are in `cmd/examples/main.go`

- [Vault client example](https://github.com/banzaicloud/bank-vaults/blob/master/cmd/examples/main.go#L17)
- [Dynamic secrets for MySQL example with Gorm](https://github.com/banzaicloud/bank-vaults/blob/master/cmd/examples/main.go#L45)
- [JWTAuth tokens example with a Gin middleware](https://github.com/banzaicloud/bank-vaults/blob/master/cmd/examples/main.go#L53)
