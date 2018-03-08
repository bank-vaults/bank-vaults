# vault-dogsbody

This repository contains several Go packages for interacting with Hashicorp Vault:

- vault
    
    A wrapper for the official Vault client with automatic token renewal, and Kubernetes support.

- database
    
    A helper for creating database source strings (MySQL/PostgreSQL) with database credentials dynamically based on configured Vault roles (instead of `username:password`).

## Examples

Some examples are in `main.go`
