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
	"context"
	"encoding/json"
	"os"

	"emperror.dev/errors"
	v1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/banzaicloud/bank-vaults/pkg/kv"
)

// EnvK8SOwnerReference holds the environment variable name for passing in K8S owner refs
// TODO: remove this in the next release.
const EnvK8SOwnerReference = "K8S_OWNER_REFERENCE"

type k8sStorage struct {
	client         *kubernetes.Clientset
	namespace      string
	secret         string
	labels         map[string]string
	ownerReference *metav1.OwnerReference
}

// New creates a new kv.Service backed by K8S Secrets
func New(namespace, secret string, labels map[string]string) (kv.Service, error) {
	kubeconfig := os.Getenv(clientcmd.RecommendedConfigPathEnvVar)
	var config *rest.Config

	var err error
	if kubeconfig != "" {
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
	} else {
		config, err = rest.InClusterConfig()
	}

	if err != nil {
		return nil, errors.Wrap(err, "error creating k8s config")
	}

	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, errors.Wrap(err, "error creating k8s client")
	}

	var ownerReference *metav1.OwnerReference
	ownerReferenceJSON := os.Getenv(EnvK8SOwnerReference)
	if ownerReferenceJSON != "" {
		ownerReference = &metav1.OwnerReference{}
		err := json.Unmarshal([]byte(ownerReferenceJSON), ownerReference)
		if err != nil {
			return nil, errors.Wrap(err, "error unmarhsaling OwnerReference")
		}
	}

	return &k8sStorage{
		client:         client,
		namespace:      namespace,
		secret:         secret,
		labels:         labels,
		ownerReference: ownerReference,
	}, nil
}

func (k *k8sStorage) Set(key string, val []byte) error {
	secret, err := k.client.CoreV1().Secrets(k.namespace).Get(context.Background(), k.secret, metav1.GetOptions{})

	if k8serrors.IsNotFound(err) {
		secret := &v1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: k.namespace,
				Name:      k.secret,
				Labels:    k.labels,
			},
			Data: map[string][]byte{key: val},
		}
		if k.ownerReference != nil {
			secret.ObjectMeta.SetOwnerReferences([]metav1.OwnerReference{*k.ownerReference})
		}
		_, err = k.client.CoreV1().Secrets(k.namespace).Create(context.Background(), secret, metav1.CreateOptions{})
	} else if err == nil {
		secret.Data[key] = val
		_, err = k.client.CoreV1().Secrets(k.namespace).Update(context.Background(), secret, metav1.UpdateOptions{})
	} else {
		return errors.Wrapf(err, "error checking if '%s' secret exists", k.secret)
	}

	if err != nil {
		return errors.Wrapf(err, "error writing secret key '%s' into secret '%s'", key, k.secret)
	}

	return nil
}

func (k *k8sStorage) Get(key string) ([]byte, error) {
	secret, err := k.client.CoreV1().Secrets(k.namespace).Get(context.Background(), k.secret, metav1.GetOptions{})
	if err != nil {
		if k8serrors.IsNotFound(err) {
			return nil, kv.NewNotFoundError("error getting secret for key '%s': %s", key, err.Error())
		}

		return nil, errors.Wrapf(err, "error getting secret for key '%s'", key)
	}

	val := secret.Data[key]
	if val == nil {
		return nil, kv.NewNotFoundError("key '%s' is not present in secret: %s", key, secret.GetName())
	}

	return val, nil
}
