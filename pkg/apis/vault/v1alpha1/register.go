package v1alpha1

import (
	sdkK8sutil "github.com/operator-framework/operator-sdk/pkg/util/k8sutil"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

const (
	version   = "v1alpha1"
	groupName = "vault.banzaicloud.com"
)

var (
	// SchemeBuilder is the SchemeBuilder for the Vault Operator
	SchemeBuilder = runtime.NewSchemeBuilder(addKnownTypes)
	// AddToScheme is the AddToScheme function of the SchemeBuilder for the Vault Operator
	AddToScheme = SchemeBuilder.AddToScheme
	// SchemeGroupVersion is the group version used to register these objects.
	SchemeGroupVersion = schema.GroupVersion{Group: groupName, Version: version}
)

func init() {
	sdkK8sutil.AddToSDKScheme(AddToScheme)
}

// addKnownTypes adds the set of types defined in this package to the supplied scheme.
func addKnownTypes(scheme *runtime.Scheme) error {
	scheme.AddKnownTypes(SchemeGroupVersion,
		&Vault{},
		&VaultList{},
	)
	metav1.AddToGroupVersion(scheme, SchemeGroupVersion)
	return nil
}
