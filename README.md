*Bank Vaults is a thick, tricky, shifty right with a fast and intense tube for experienced surfers only, located on Mentawai. Think heavy steel doors, secret unlocking combinations and burly guards with smack-down attitude. Watch out for clean-up sets.*

*Bank Vaults is a wrapper for the official Vault client with automatic token renewal, built in Kubernetes support, dynamic database credential management and more.*

**Bank Vaults** is a core building block of the [Pipeline](https://github.com/banzaicloud/pipeline) PaaS.

This repository contains several Go packages for interacting with Vault:

- Vault
    
    A wrapper for the official Vault client with automatic token renewal, and Kubernetes support.

- Database
    
    A helper for creating database source strings (MySQL/PostgreSQL) with database credentials dynamically based on configured Vault roles (instead of `username:password`).

## Examples

Some examples are in `main.go`
