# Watching External Secrets 

In some setup it might be needed to restart the Vault Statefulset when secrets, external to the operator control, are changed. 

Some Examples include:

* Cert-Manager managing a public Certificate for vault using let's Encrypt 
* Cloud IAM Credentials created with an external tool ( like terraform ) to allow vault to interact with the cloud services

The Operator can watch a set of secrets in the namespace of the Vault resource using a list of labels selector and update the statefulset , triggering a rolling restart, when the content of any of those secrets change

How to configure labels selectors
```

  watchedSecretsLabels:
    - certmanager.k8s.io/certificate-name: vault-letsencrypt-cert
    - test.com/scope: gcp
      test.com/credentials: vault

```

in the example above a restart would be trigger if 
* secret with label _certmanager.k8s.io/certificate-name: vault-letsencrypt-cert_ change in contents
* secret with label _test.com/scope: gcp_ AND _test.com/credentials: vault_ change in contents

The operator will control the restart of the statefulset by adding an _annotation_ to the _spec.template_ of the vault resource
```

kubectl get -n vault statefulset vault -o json | jq .spec.template.metadata.annotations
{
  "prometheus.io/path": "/metrics",
  "prometheus.io/port": "9102",
  "prometheus.io/scrape": "true",
  "vault.security.banzaicloud.io/watched-secrets-sum": "ff1f1c79a31f76c68097975977746be9b85878f4737b8ee5a9d6ee3c5169b0ba"
}

```
