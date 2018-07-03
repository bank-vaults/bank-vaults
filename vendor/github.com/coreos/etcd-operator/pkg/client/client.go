// Copyright 2017 The etcd-operator Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package client

import (
	"github.com/coreos/etcd-operator/pkg/generated/clientset/versioned"
	"github.com/coreos/etcd-operator/pkg/util/k8sutil"

	"k8s.io/client-go/rest"
)

func MustNewInCluster() versioned.Interface {
	cfg, err := k8sutil.InClusterConfig()
	if err != nil {
		panic(err)
	}
	return MustNew(cfg)
}

func MustNew(cfg *rest.Config) versioned.Interface {
	cli, err := versioned.NewForConfig(cfg)
	if err != nil {
		panic(err)
	}
	return cli
}
