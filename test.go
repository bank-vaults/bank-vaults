package main

import (
	"fmt"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

func main() {
	ref, err := name.ParseReference("gcr.io/etcd-development/etcd:v3.2.5")
	if err != nil {
		panic(err)
	}

	println(ref.Identifier())

	auth, err := authn.DefaultKeychain.Resolve(ref.Context().Registry)
	if err != nil {
		panic(err)
	}

	descriptor, err := remote.Get(ref, remote.WithAuth(auth))
	if err != nil {
		panic(err)
	}

	image, err := descriptor.Image()
	if err != nil {
		panic(err)
	}

	configFile, err := image.ConfigFile()
	if err != nil {
		panic(err)
	}

	fmt.Println(configFile.Config)
}
