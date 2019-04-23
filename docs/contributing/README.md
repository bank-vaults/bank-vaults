# Contributing

If you find this project useful here's how you can help:

- Send a pull request with your new features and bug fixes
- Help new users with issues they may encounter
- Support the development of this project and star this repo!


## Development environment

In your develepment environment you can use file mode for testing `bank-vaults` cli-tool:

```shell
vault server -config vault.hcl
```

**example vault.hcl:**
```
api_addr = "http://localhost:8200"

storage "file" {
  path = "/tmp/vault"
}

listener "tcp" {
  address = "0.0.0.0:8200"
  tls_disable = true
}
```

Now you have a running vault server which is unitialized and unsealed you can init and unseal it with `bank-vaults` cli-tool and unseal keys will be stored to a local file:
```shell
VAULT_ADDR=http://127.0.0.1:8200 bank-vaults unseal --init --mode file
```

The unseal keys and root token are stored your working directory:
```
vault-root
vault-unseal-0
vault-unseal-1
vault-unseal-2
vault-unseal-3
vault-unseal-4
```
