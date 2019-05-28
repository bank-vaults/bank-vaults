# Running Vault with external end to end encryption

This document assumes you have a working Kuberentes cluster which has a:
* Working install of Vault.
* That you have a working knowledge of Kubernetes.
* A working install of helm
* A working knowledge of Kubernetes ingress
* A valid external (www.example.com) SSL certificate, verified by your provider as a Kubernetes secret.

## Background

The bank-vaults operator takes care of creating and maintaining internal cluster communications but if you wish to use your vault install
outside of your Kubernetes cluster what is the best way to maintain a secure state. Creating a standard Ingress object will reverse proxy
these requests to your vault instance but this is a hand off between the external SSL connection and the internal one and not acceptable
for some circumstances and if you have to adhere to scrict security standards.

## Workflow
Here we will create a separate TCP listner for vault using a custom SSL certificate on an external domain of your choosing. We will then
install a unique ingress-nginx controller allowing SSL pass through. SSL Pass through comes with a performance hit, so you would not use this
on a production website or ingress-controller that has a lot of traffic.

## Install
### ingress-nginx
### vaules.yaml
```
controller:
  electionID: vault-ingress-controller-leader
  ingressClass: nginx-vault
  extraArgs:
    enable-ssl-passthrough:
  publishService:
    enabled: true
  scope:
    enabled: true
  replicaCount: 2
  affinity:
    podAntiAffinity:
      requiredDuringSchedulingIgnoredDuringExecution:
      - labelSelector:
          matchExpressions:
          - key: release
            operator: In
            values: ["vault-ingress"]
        topologyKey: kubernetes.io/hostname
```
### Install nginx-ingress via helm
```
helm install nginx-stable/nginx-ingress --name my-release -f vaules.yaml
```

## Configuration
### SSL Secret example:
```
apiVersion: v1
data:
  tls.crt: LS0tLS1......=
  tls.key: LS0tLS.......==
kind: Secret
metadata:
  labels:
    ssl: "true"
    tls: "true"
  name: wildcard.example.com
type: Opaque
```

### CR Vault Config:
```
---
apiVersion: "vault.banzaicloud.com/v1alpha1"
kind: "Vault"
metadata:
  name: "vault"
  namespace: secrets
spec:
  size: 2
  image: vault:1.1.2
  bankVaultsImage: banzaicloud/bank-vaults:0.4.16

  # A YAML representation of a final vault config file.
  # See https://www.vaultproject.io/docs/configuration/ for more information.
  config:
    listener:
      - tcp:
          address: "0.0.0.0:8200"
          tls_cert_file: /vault/tls/server.crt
          tls_key_file: /vault/tls/server.key
      - tcp:
          address: "0.0.0.0:8300"
          tls_cert_file: /etc/ingress-tls/tls.crt
          tls_key_file: /etc/ingress-tls/tls.key
    api_addr: https://vault:8200
    cluster_addr: https://vault:8201
    ui: true
```
### CR Service:
```
  # Specify the Service's type where the Vault Service is exposed
  serviceType: ClusterIP
  servicePorts:
    api-port: 8200
    cluster-port: 8201
    ext-api-port: 8300
    ext-clu-port: 8301
```
### Mount the secret into your vault pod
```
  volumes:
    - name: wildcard-ssl
      secret:
        defaultMode: 420
        secretName: wildcard.examlpe.com

  volumeMounts:
    - name: wildcard-ssl
      mountPath: /etc/ingress-tls
```

### CR Ingress:
```
  # Request an Ingress controller with the default configuration
  ingress:
    annotations:
      kubernetes.io/ingress.allow-http: "false"
      kubernetes.io/ingress.class: "nginx-vault"
      nginx.ingress.kubernetes.io/force-ssl-redirect: "true"
      nginx.ingress.kubernetes.io/ssl-passthrough: "true"
      nginx.ingress.kubernetes.io/backend-protocol: "HTTPS"
      nginx.ingress.kubernetes.io/whitelist-source-range: "127.0.0.1"

    spec:
      rules:
        - host: vault.example.com
          http:
            paths:
              - path: /
                backend:
                  serviceName: vault
                  servicePort: 8300
```
