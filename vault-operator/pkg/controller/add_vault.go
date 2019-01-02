package controller

import (
	"github.com/banzaicloud/bank-vaults/vault-operator/pkg/controller/vault"
)

func init() {
	// AddToManagerFuncs is a list of functions to create controllers and add them to a manager.
	AddToManagerFuncs = append(AddToManagerFuncs, vault.Add)
}
