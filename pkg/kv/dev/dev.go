package dev

import (
	"fmt"
	"io/ioutil"
	"os"

	"github.com/banzaicloud/bank-vaults/pkg/kv"
)

type dev struct {
	rootToken []byte
}

func New() (service kv.Service, err error) {
	rootToken, err := ioutil.ReadFile(os.Getenv("HOME") + "/.vault-token")

	if err != nil {
		return nil, fmt.Errorf("error creating dev client: %s", err.Error())
	}

	service = &dev{rootToken}

	return
}

func (d *dev) Set(key string, val []byte) error {
	return nil
}

func (d *dev) Get(key string) ([]byte, error) {

	if key == "vault-root" {
		return d.rootToken, nil
	}

	return nil, kv.NewNotFoundError("key '%s' is not present in secret: %s", key)
}

func (d *dev) Test(key string) error {
	return nil
}
