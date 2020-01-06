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

package k8srestapi

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/banzaicloud/bank-vaults/pkg/kv"
	"io/ioutil"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"net/http"
	"os"
)

// EnvK8SOwnerReference holds the environment variable name for passing in K8S owner refs
const EnvK8SOwnerReference = "K8S_OWNER_REFERENCE"

type k8srestapiStore struct {
	cl             *kubernetes.Clientset
	namespace      string
	secret         string
	keyidName      string
	encryptionUrl  string
	decryptionUrl  string
	ownerReference *metav1.OwnerReference
}

// New Structs were created for passing the json payload to rest Api call and receiving the return json payload
type plaintext_payload struct {
	Application  string `json:"application"`
	PlaintextB64 string `json:"plaintextB64"`
}

type encrypted_payload struct {
	Application  string `json:"application"`
	EncryptedB64 string `json:"encryptedB64"`
}

// New creates a new kv.Service backed by K8S Secrets
func New(namespace, secret, keyidName, encryptionUrl, decryptionUrl string) (service kv.Service, err error) {
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

	service = &k8srestapiStore{client, namespace, secret, keyidName, encryptionUrl, decryptionUrl, ownerReference}

	return
}

func (k *k8srestapiStore) encrypt(plainText []byte) []byte {

	var ep encrypted_payload
	jsonData := &plaintext_payload{
		Application:  k.keyidName,
		PlaintextB64: base64.StdEncoding.EncodeToString(plainText),
	}
	jsonValue, _ := json.Marshal(jsonData)
	request, _ := http.NewRequest("POST", k.encryptionUrl, bytes.NewBuffer(jsonValue))
	request.Header.Set("Content-Type", "application/json")
	client := &http.Client{}
	response, err := client.Do(request)
	if err != nil {
		fmt.Printf("The http request failed %s\n", err)
	} else {
		cipherTextTemp, _ := ioutil.ReadAll(response.Body)
		err := json.Unmarshal(cipherTextTemp, &ep)
		if err != nil {
			panic(err)
		}
	}
	return ([]byte(ep.EncryptedB64))
}

func (k *k8srestapiStore) decrypt(cipherText []byte) []byte {

	var pp plaintext_payload
	jsonData := &encrypted_payload{
		Application:  k.keyidName,
		EncryptedB64: string(cipherText),
	}
	jsonValue, _ := json.Marshal(jsonData)
	request, _ := http.NewRequest("POST", k.decryptionUrl, bytes.NewBuffer(jsonValue))
	request.Header.Set("Content-Type", "application/json")
	client := &http.Client{}
	response, err := client.Do(request)
	if err != nil {
		fmt.Printf("The http request failed %s\n", err)
	} else {
		plainTextTemp, _ := ioutil.ReadAll(response.Body)
		err := json.Unmarshal(plainTextTemp, &pp)
		if err != nil {
			panic(err)
		}
	}
	decoded, err := base64.StdEncoding.DecodeString(pp.PlaintextB64)
	if err != nil {
		panic(err)
	}
	return decoded
}

func (k *k8srestapiStore) Set(key string, val []byte) error {

	secret, err := k.cl.CoreV1().Secrets(k.namespace).Get(k.secret, metav1.GetOptions{})

	cipherText := k.encrypt(val)
	if errors.IsNotFound(err) {
		secret := &v1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: k.namespace,
				Name:      k.secret,
			},
			Data: map[string][]byte{key: cipherText},
		}
		if k.ownerReference != nil {
			secret.ObjectMeta.SetOwnerReferences([]metav1.OwnerReference{*k.ownerReference})
		}
		secret, err = k.cl.CoreV1().Secrets(k.namespace).Create(secret)

	} else if err == nil {
		secret.Data[key] = cipherText
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

func (k *k8srestapiStore) Get(key string) ([]byte, error) {
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

	plainText := k.decrypt(val)
	return plainText, nil
}
