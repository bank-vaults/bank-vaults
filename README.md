*Bank Vaults is a thick, tricky, shifty right with a fast and intense tube for experienced surfers only, located on Mentawai. Think heavy steel doors, secret unlocking combinations and burly guards with smack-down attitude. Watch out for clean-up sets.*

*Bank Vaults is a wrapper for the official Vault client with automatic token renewal, built in Kubernetes support, dynamic database credential management and more.*

**Bank Vaults** is a core building block of the [Pipeline](https://github.com/banzaicloud/pipeline) PaaS. Some of the usage patterns are highlighted through these blog posts:

[Authentication and authorization of Pipeline users with OAuth2 and Vault](https://banzaicloud.com/blog/oauth2-vault/)</br>
[Dynamic credentials with Vault using Kubernetes Service Accounts](https://banzaicloud.com/blog/vault-dynamic-secrets/)</br>
[Dynamic SSH with Vault and Pipeline](https://banzaicloud.com/blog/vault-dynamic-ssh/)</br>

We are working on an improved documentation and code examples, please watch this [issue](https://github.com/banzaicloud/bank-vaults/issues/9).

---

This repository contains several Go packages for interacting with Vault:

- Vault
    
    A wrapper for the official Vault client with automatic token renewal, and Kubernetes support.

- Database
    
    A helper for creating database source strings (MySQL/PostgreSQL) with database credentials dynamically based on configured Vault roles (instead of `username:password`).

## Examples

Some examples are in `main.go`
