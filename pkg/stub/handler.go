package stub

import (
	"fmt"
	"reflect"

	"github.com/banzaicloud/bank-vaults/pkg/apis/vault/v1alpha1"

	"github.com/operator-framework/operator-sdk/pkg/sdk/action"
	"github.com/operator-framework/operator-sdk/pkg/sdk/handler"
	"github.com/operator-framework/operator-sdk/pkg/sdk/query"
	"github.com/operator-framework/operator-sdk/pkg/sdk/types"
	appsv1 "k8s.io/api/apps/v1"
	"k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

func NewHandler() handler.Handler {
	return &Handler{}
}

type Handler struct {
}

func (h *Handler) Handle(ctx types.Context, event types.Event) error {
	switch o := event.Object.(type) {
	case *v1alpha1.Vault:
		vault := o

		// Ignore the delete event since the garbage collector will clean up all secondary resources for the CR
		// All secondary resources must have the CR set as their OwnerReference for this to be the case
		if event.Deleted {
			return nil
		}

		// Create the deployment if it doesn't exist
		dep := deploymentForVault(vault)
		err := action.Create(dep)
		if err != nil && !apierrors.IsAlreadyExists(err) {
			return fmt.Errorf("failed to create deployment: %v", err)
		}

		// Ensure the deployment size is the same as the spec
		err = query.Get(dep)
		if err != nil {
			return fmt.Errorf("failed to get deployment: %v", err)
		}
		size := vault.Spec.Size
		if *dep.Spec.Replicas != size {
			dep.Spec.Replicas = &size
			err = action.Update(dep)
			if err != nil {
				return fmt.Errorf("failed to update deployment: %v", err)
			}
		}

		// Update the Vault status with the pod names
		podList := podList()
		labelSelector := labels.SelectorFromSet(labelsForVault(vault.Name)).String()
		listOps := &metav1.ListOptions{LabelSelector: labelSelector}
		err = query.List(vault.Namespace, podList, query.WithListOptions(listOps))
		if err != nil {
			return fmt.Errorf("failed to list pods: %v", err)
		}
		podNames := getPodNames(podList.Items)
		if !reflect.DeepEqual(podNames, vault.Status.Nodes) {
			vault.Status.Nodes = podNames
			err := action.Update(vault)
			if err != nil {
				return fmt.Errorf("failed to update vault status: %v", err)
			}
		}

		// Create the service if it doesn't exist
		ser := serviceForVault(vault)
		err = action.Create(ser)
		if err != nil && !apierrors.IsAlreadyExists(err) {
			return fmt.Errorf("failed to create service: %v", err)
		}
	}
	return nil
}

// deploymentForVault returns a vault Deployment object
func deploymentForVault(v *v1alpha1.Vault) *appsv1.Deployment {
	ls := labelsForVault(v.Name)
	replicas := v.Spec.Size
	config := v.Spec.ConfigJSON()

	dep := &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "apps/v1",
			Kind:       "Deployment",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      v.Name,
			Namespace: v.Namespace,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: ls,
			},
			Template: v1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: ls,
				},
				Spec: v1.PodSpec{
					Containers: []v1.Container{
						{
							Image: "vault:0.10.1",
							Name:  "vault",
							Args:  []string{"server"},
							Ports: []v1.ContainerPort{{
								ContainerPort: 8200,
								Name:          "vault",
							}},
							Env: []v1.EnvVar{{
								Name:  "VAULT_LOCAL_CONFIG",
								Value: config,
							}},
							SecurityContext: &v1.SecurityContext{
								Capabilities: &v1.Capabilities{
									Add: []v1.Capability{"IPC_LOCK"},
								},
							},
						},
						{
							Image:   "banzaicloud/bank-vaults:master",
							Name:    "vault-unsealer",
							Command: []string{"bank-vaults", "unseal"},
							Args: []string{
								"--init",
								"--mode",
								"k8s", // TODO This should be dependant on the Vault configuration later on
								"--k8s-secret-namespace",
								v.Namespace,
								"--k8s-secret-name",
								v.Name + "-unseal-keys",
							},
							Env: []v1.EnvVar{{
								Name:  "VAULT_ADDR",
								Value: "http://localhost:8200",
							}},
						},
					},
				},
			},
		},
	}
	addOwnerRefToObject(dep, asOwner(v))
	return dep
}

func serviceForVault(v *v1alpha1.Vault) *v1.Service {
	ls := labelsForVault(v.Name)
	service := &v1.Service{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "Service",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      v.Name,
			Namespace: v.Namespace,
		},
		Spec: v1.ServiceSpec{
			Type:     v1.ServiceTypeNodePort,
			Selector: ls,
			Ports: []v1.ServicePort{
				{
					Name: "vault",
					Port: 8200,
				},
			},
		},
	}
	addOwnerRefToObject(service, asOwner(v))
	return service
}

// labelsForVault returns the labels for selecting the resources
// belonging to the given vault CR name.
func labelsForVault(name string) map[string]string {
	return map[string]string{"app": "vault", "vault_cr": name}
}

// addOwnerRefToObject appends the desired OwnerReference to the object
func addOwnerRefToObject(obj metav1.Object, ownerRef metav1.OwnerReference) {
	obj.SetOwnerReferences(append(obj.GetOwnerReferences(), ownerRef))
}

// asOwner returns an OwnerReference set as the vault CR
func asOwner(v *v1alpha1.Vault) metav1.OwnerReference {
	trueVar := true
	return metav1.OwnerReference{
		APIVersion: v.APIVersion,
		Kind:       v.Kind,
		Name:       v.Name,
		UID:        v.UID,
		Controller: &trueVar,
	}
}

// podList returns a v1.PodList object
func podList() *v1.PodList {
	return &v1.PodList{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Pod",
			APIVersion: "v1",
		},
	}
}

// getPodNames returns the pod names of the array of pods passed in
func getPodNames(pods []v1.Pod) []string {
	var podNames []string
	for _, pod := range pods {
		podNames = append(podNames, pod.Name)
	}
	return podNames
}
