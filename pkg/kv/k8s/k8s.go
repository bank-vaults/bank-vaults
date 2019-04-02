// Copyright © 2018 Banzai Cloud
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

package k8s

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/banzaicloud/bank-vaults/pkg/kv"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// EnvK8SOwnerReference holds the environment variable name for passing in K8S owner refs
const EnvK8SOwnerReference = "K8S_OWNER_REFERENCE"

type k8sStorage struct {
	cl             *kubernetes.Clientset
	namespace      string
	secret         string
	ownerReference *metav1.OwnerReference
}

// New creates a new kv.Service backed by K8S Secrets
func New(namespace, secret string) (service kv.Service, err error) {
	kubeconfig := os.Getenv(clientcmd.RecommendedConfigPathEnvVar)
	var config *rest.Config

	if kubeconfig != "" {
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
	} else {
		config, err = rest.InClusterConfig()
	}

	if err != nil {
		return nil, fmt.Errorf("error creating k8s config: %s", err.Error())
	}

	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("error creating k8s client: %s", err.Error())
	}

	var ownerReference *metav1.OwnerReference
	ownerReferenceJSON := os.Getenv(EnvK8SOwnerReference)
	if ownerReferenceJSON != "" {
		ownerReference = &metav1.OwnerReference{}
		err := json.Unmarshal([]byte(ownerReferenceJSON), ownerReference)
		if err != nil {
			return nil, fmt.Errorf("error unmarhsaling OwnerReference: %s", err.Error())
		}
	}

	service = &k8sStorage{client, namespace, secret, ownerReference}

	return
}

func (k *k8sStorage) Set(key string, val []byte) error {
	secret, err := k.cl.CoreV1().Secrets(k.namespace).Get(k.secret, metav1.GetOptions{})

	if errors.IsNotFound(err) {
		secret := &v1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: k.namespace,
				Name:      k.secret,
			},
			Data: map[string][]byte{key: val},
		}
		if k.ownerReference != nil {
			secret.ObjectMeta.SetOwnerReferences([]metav1.OwnerReference{*k.ownerReference})
		}
		secret, err = k.cl.CoreV1().Secrets(k.namespace).Create(secret)
	} else if err == nil {
		secret.Data[key] = val
		secret, err = k.cl.CoreV1().Secrets(k.namespace).Update(secret)
		//reflect.DeepEqual()
	} else {
		return fmt.Errorf("error checking if '%s' secret exists: '%s'", k.secret, err.Error())
	}

	if err != nil {
		return fmt.Errorf("error writing secret key '%s' into secret '%s': '%s'", key, k.secret, err.Error())
	}
	return nil
}

func (k *k8sStorage) Get(key string) ([]byte, error) {
	secret, err := k.cl.CoreV1().Secrets(k.namespace).Get(k.secret, metav1.GetOptions{})

	if err != nil {
		if errors.IsNotFound(err) {
			return nil, kv.NewNotFoundError("error getting secret for key '%s': %s", key, err.Error())
		}
		return nil, fmt.Errorf("error getting secret for key '%s': %s", key, err.Error())
	}

	val := secret.Data[key]
	if val == nil {
		return nil, kv.NewNotFoundError("key '%s' is not present in secret: %s", key, secret.GetName())
	}

	return val, nil
}
