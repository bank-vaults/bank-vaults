// Copyright © 2019 Banzai Cloud
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

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"reflect"

	dockerTypes "github.com/docker/docker/api/types"
	"go.uber.org/zap"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// K8s structure keeps information retrieved from POD definition
type K8s struct {
	clientset        *kubernetes.Clientset
	Namespace        string
	ImagePullSecrets string
	RegistryAddress  string
	RegistryName     string
	RegistryUsername string
	RegistryPassword string
	Image            string
}

type dockerCreds struct {
	Auths map[string]dockerTypes.AuthConfig `json:"auths"`
}

func (k *K8s) newClientSet() error {
	kubeConfig, err := rest.InClusterConfig()
	if err != nil {
		return err
	}

	k.clientset, err = kubernetes.NewForConfig(kubeConfig)
	if err != nil {
		return err
	}
	return nil
}

func (k *K8s) readDockerSecret(secretName string) (map[string][]byte, error) {
	secret, err := k.clientset.CoreV1().Secrets(k.Namespace).Get(secretName, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	return secret.Data, nil
}

func (k *K8s) getNamespace() {
	k.Namespace = os.Getenv("NAMESPACE")
}

func (k *K8s) getPod(podName string) (*v1.Pod, error) {
	pod, err := k.clientset.CoreV1().Pods(k.Namespace).Get(podName, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	return pod, nil
}

func (k *K8s) parseDockerConfig(dockerCreds dockerCreds) {
	k.RegistryName = reflect.ValueOf(dockerCreds.Auths).MapKeys()[0].String()
	k.RegistryAddress = fmt.Sprintf("https://%s", k.RegistryName)

	auths := dockerCreds.Auths
	k.RegistryUsername = auths[k.RegistryName].Username
	k.RegistryPassword = auths[k.RegistryName].Password
}

// Load reads information from k8s and load them into the structure
func (k *K8s) Load() {
	k.getNamespace()
	k.newClientSet()

	podName := os.Getenv("MY_POD_NAME")
	if podName == "" {
		logger.Fatal("Cannot find MY_POD_NAME environment variable")
	}

	pod, err := k.getPod(podName)
	if err != nil {
		logger.Fatal("Cannot get pod definition", zap.Error(err))
	}

	for _, container := range pod.Spec.Containers {
		k.Image = container.Image

		containerName := os.Getenv("CONTAINER_NAME")
		if containerName == container.Name && containerName != "" {
			break
		}
	}

	if len(pod.Spec.ImagePullSecrets) >= 1 {
		k.ImagePullSecrets = pod.Spec.ImagePullSecrets[0].Name

		if k.ImagePullSecrets != "" {
			data, err := k.readDockerSecret(k.ImagePullSecrets)
			if err != nil {
				logger.Fatal("Cannot read imagePullSecrets", zap.Error(err))
			}
			dockerConfig := data[v1.DockerConfigJsonKey]
			//parse config
			var dockerCreds dockerCreds
			err = json.Unmarshal(dockerConfig, &dockerCreds)
			if err != nil {
				logger.Fatal("Cannot unmarshal docker configuration from imagePullSecrets", zap.Error(err))
			}
			k.parseDockerConfig(dockerCreds)
		}
	}
}
