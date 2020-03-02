# HSM Support

On OSX where you run Docker in VMs you need to do some extra steps before developing to mount your HSM device to Kubernetes.

## NitroKey HSM

[Nitrokey HSM](https://www.nitrokey.com/) is a USB HSM device. We are using NitroKey to develop HSM support for Bank-Vaults. The following steps are needed to mount it into Kubernetes.

```bash
# You need to the Oracle VM VirtualBox Extension Pack for USB 2.0 support, make sure it is installed
VBoxManage list extpacks

# Create a minikube cluster with the virtualbox driver and stop it (we need to modify the VM)
minikube start --vm-driver virtualbox
minikube stop

# Enable USB 2.0 support for the minikube VM
VBoxManage modifyvm minikube --usbehci on

# Find the vendorid and productid for your Nitrokey HSM device
VBoxManage list usbhost

# Create a filter for it
VBoxManage usbfilter add 1 --target minikube --name "Nitrokey HSM" --vendorid 0x20a0 --productid 0x4230

# Restart the minikube VM
minikube start --vm-driver virtualbox
```


## Kubernetes node setup

Since the HSM is a hardware device connected to a node Bank-Vaults has to find its way to that node. We can create a HSM extended resource on the Kubernetes node for which the device is plugged in.

Patch the minikube node to contain the HSM as a resource: https://kubernetes.io/docs/tasks/administer-cluster/extended-resource-node/

```bash
kubectl proxy &

curl --header "Content-Type: application/json-patch+json" \
     --request PATCH \
     --data '[{"op": "add", "path": "/status/capacity/nitrokey.com~1hsm", "value": "2"}]' \
     http://localhost:8001/api/v1/nodes/minikube/status
```

This resource can be requested from now on in the PodSpec:

```yaml
    resources:
      requests:
        nitrokey.com/hsm: 1
      limits:
        nitrokey.com/hsm: 1
```
