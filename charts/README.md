## Bank-Vaults Charts

The official way to deploy the Bank-Vaults is via Helm.

All charts are deployed to the central Banzai Cloud repository:

```shell
helm repo add banzaicloud-stable https://kubernetes-charts.banzaicloud.com
```

We have three different charts for the 3 main application:

```shell
$ helm search banzaicloud-stable/vault
NAME                                    	CHART VERSION	APP VERSION	DESCRIPTION                                                 
banzaicloud-stable/vault                	0.7.0        	1.1.5      	A Helm chart for Vault, a tool for managing secrets         
banzaicloud-stable/vault-operator       	0.2.17       	0.4.18     	A Helm chart for banzaicloud/bank-vaults operator           
banzaicloud-stable/vault-secrets-webhook	0.3.23       	0.4.18     	A Helm chart that deploys a mutating admission webhook th...
```
