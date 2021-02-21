# Developing on MicroK8s

MicroK8s is super simple to setup and has minimal overhead. Once you install it make
sure to enable the storage addon, so that persistent volumes and persistent volume
claims can be served.
```bash
microk8s.addon storage enabled
```

# Deploying the operator

Create a branch, make whatever changes you want and then do the following:
```bash
make docker docker-operator docker-webhook
```
Then you need to import the images into the microk8s containerd process:
```bash
docker save ghcr.io/banzaicloud/<some_image>:<your_branch_name> | microk8s.ctr --namespace k8s.io images import -
```
If you do:
```bash
microk8s.ctr -n k8s.io images list
```
you should be able to see your image now.

Finally, you can deploy the operator using:
```bash
helm upgrade --install vault-operator charts/vault-operator --set=image.repository=ghcr.io/banzaicloud/vault-operator --set=image.tag=<your_branch_name>
```
