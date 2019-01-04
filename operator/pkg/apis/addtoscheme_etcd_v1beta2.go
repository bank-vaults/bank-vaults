package apis

import (
	"github.com/coreos/etcd-operator/pkg/apis/etcd/v1beta2"
)

func init() {
	// Register the types with the Scheme so the components can map objects to GroupVersionKinds and back
	AddToSchemes = append(AddToSchemes, v1beta2.SchemeBuilder.AddToScheme)
}
