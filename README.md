<p align="center">
  <a href="https://bank-vaults.dev">
    <img src="resources/logo.png" width="300" alt="Bank-Vaults logo" />
  </a>

  <h1 align="center">
    Bank-Vaults
  </h1>
</p>

Bank-Vaults is now a [CNCF Sandbox](https://www.cncf.io/sandbox-projects/) project.

[![Open in Gitpod](https://gitpod.io/button/open-in-gitpod.svg)](https://gitpod.io/#https://github.com/bank-vaults/bank-vaults)
<br>
[![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/bank-vaults/bank-vaults/ci.yaml?branch=main&style=flat-square)](https://github.com/bank-vaults/bank-vaults/actions/workflows/ci.yaml?query=workflow%3ACI)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/bank-vaults/bank-vaults/badge?style=flat-square)](https://api.securityscorecards.dev/projects/github.com/bank-vaults/bank-vaults)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/7871/badge)](https://www.bestpractices.dev/projects/7871)

*Bank Vaults is a thick, tricky, shifty right with a fast and intense tube for experienced surfers only, located on Mentawai.
Think heavy steel doors, secret unlocking combinations and burly guards with smack-down attitude. Watch out for clean-up sets.*

---

Bank-Vaults is an umbrella project which provides various tools for Cloud Native secret management, including:

- Bank-Vaults CLI to make configuring Hashicorp Vault easier
- [Vault Operator](https://github.com/bank-vaults/vault-operator/) to make operating Hashicorp Vault on top of Kubernetes easier
- [Secrets Webhook](https://github.com/bank-vaults/secrets-webhook) to inject secrets directly into Kubernetes pods
- [Vault SDK](https://github.com/bank-vaults/vault-sdk) to make working with Vault easier in Go
- and others

## Usage

Some of the usage patterns are highlighted through these blog posts:

- [Authentication and authorization of Pipeline users with OAuth2 and Vault](https://banzaicloud.com/blog/oauth2-vault/)
- [Dynamic credentials with Vault using Kubernetes Service Accounts](https://banzaicloud.com/blog/vault-dynamic-secrets/)
- [Dynamic SSH with Vault and Pipeline](https://banzaicloud.com/blog/vault-dynamic-ssh/)
- [Secure Kubernetes Deployments with Vault and Pipeline](https://banzaicloud.com/blog/hashicorp-guest-post/)
- [Vault Operator](https://banzaicloud.com/blog/vault-operator/)
- [Vault unseal flow with KMS](https://banzaicloud.com/blog/vault-unsealing/)
- [Monitoring Vault on Kubernetes using Cloud Native technologies](https://banzaicloud.com/blog/monitoring-vault-grafana/)
- [Inject secrets directly into pods from Vault](https://banzaicloud.com/blog/inject-secrets-into-pods-vault-revisited/)
- [Backing up Vault with Velero](https://banzaicloud.com/blog/vault-backup-velero/)
- [Vault replication across multiple datacenters on Kubernetes](https://banzaicloud.com/blog/vault-multi-datacenter/)
- [More blog posts about Bank-Vaults](https://banzaicloud.com/tags/bank-vaults/)
- [Bank Vaults Configuration Helm Chart](https://github.com/rljohnsn/bank-vault-config/tree/main)

## Documentation

The official documentation is available at [https://bank-vaults.dev](https://bank-vaults.dev/).

## Development

**For an optimal developer experience, it is recommended to install [Nix](https://nixos.org/download.html) and [direnv](https://direnv.net/docs/installation.html).**

_Alternatively, install [Go](https://go.dev/dl/) on your computer then run `make deps` to install the rest of the dependencies._

Make sure Docker is installed with Compose and Buildx.

Fetch required tools:

```shell
make deps
```

Run project dependencies:

```shell
make up
```

Run the test suite:

```shell
make test
make test-integration
```

Run linters:

```shell
make lint # pass -j option to run them in parallel
```

Some linter violations can automatically be fixed:

```shell
make fmt
```

Build artifacts locally:

```shell
make artifacts
```

Once you are done either stop or tear down dependencies:

```shell
make stop

# OR

make down
```

## Credits

Kudos to HashiCorp for open sourcing Vault and making secret management easier and more secure.

## License

The project is licensed under the [Apache 2.0 License](LICENSE).
