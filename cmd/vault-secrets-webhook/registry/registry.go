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

package registry

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"sync"

	dockerTypes "github.com/docker/docker/api/types"
	"github.com/heroku/docker-registry-client/registry"
	imagev1 "github.com/opencontainers/image-spec/specs-go/v1"
	log "github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

var logger log.FieldLogger

var imageCache ImageCache

func init() {
	logger = log.New()
	imageCache = NewInMemoryImageCache()
}

type ImageCache interface {
	Get(image string) *imagev1.ImageConfig
	Put(image string, imageConfig *imagev1.ImageConfig)
}

type InMemoryImageCache struct {
	mutex sync.Mutex
	cache map[string]imagev1.ImageConfig
}

func NewInMemoryImageCache() ImageCache {
	return &InMemoryImageCache{cache: map[string]imagev1.ImageConfig{}}
}

func (c *InMemoryImageCache) Get(image string) *imagev1.ImageConfig {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	if imageConfig, ok := c.cache[image]; ok {
		return &imageConfig
	}
	return nil
}

func (c *InMemoryImageCache) Put(image string, imageConfig *imagev1.ImageConfig) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.cache[image] = *imageConfig
}

type DockerCreds struct {
	Auths map[string]dockerTypes.AuthConfig `json:"auths"`
}

// GetImageConfig returns entrypoint and command of container
func GetImageConfig(
	clientset *kubernetes.Clientset,
	namespace string,
	container *corev1.Container,
	podSpec *corev1.PodSpec) (*imagev1.ImageConfig, error) {

	if imageConfig := imageCache.Get(container.Image); imageConfig != nil {
		logger.Infof("found image %s in cache", container.Image)
		return imageConfig, nil
	}

	containerInfo := ContainerInfo{Namespace: namespace, clientset: clientset}

	err := containerInfo.Collect(container, podSpec)
	if err != nil {
		return nil, err
	}

	logger.Infoln("I'm using registry", containerInfo.RegistryAddress)

	imageConfig, err := getImageBlob(containerInfo)
	if imageConfig != nil {
		imageCache.Put(container.Image, imageConfig)
	}

	return imageConfig, err
}

// GetImageBlob download image blob from registry
func getImageBlob(container ContainerInfo) (*imagev1.ImageConfig, error) {
	imageName, tag := parseContainerImage(container.Image)

	registrySkipVerify := os.Getenv("REGISTRY_SKIP_VERIFY")

	var hub *registry.Registry
	var err error

	if registrySkipVerify == "true" {
		hub, err = registry.NewInsecure(container.RegistryAddress, container.RegistryUsername, container.RegistryPassword)
	} else {
		hub, err = registry.New(container.RegistryAddress, container.RegistryUsername, container.RegistryPassword)
	}
	if err != nil {
		return nil, fmt.Errorf("cannot create client for registry: %s", err.Error())
	}

	manifest, err := hub.ManifestV2(imageName, tag)
	if err != nil {
		return nil, fmt.Errorf("cannot download manifest for image: %s", err.Error())
	}

	reader, err := hub.DownloadBlob(imageName, manifest.Config.Digest)
	if reader != nil {
		defer reader.Close()
	}
	if err != nil {
		return nil, fmt.Errorf("cannot download blob: %s", err.Error())
	}

	b, err := ioutil.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("cannot read blob: %s", err.Error())
	}

	var imageMetadata imagev1.Image
	err = json.Unmarshal(b, &imageMetadata)
	if err != nil {
		return nil, fmt.Errorf("cannot unmarshal BlobResponse JSON: %s", err.Error())
	}

	return &imageMetadata.Config, nil
}

// parseContainerImage returns image and tag
func parseContainerImage(image string) (string, string) {
	split := strings.SplitN(image, ":", 2)

	imageName := split[0]
	tag := "latest"

	if len(split) > 1 {
		tag = split[1]
	}

	return imageName, tag
}

// K8s structure keeps information retrieved from POD definition
type ContainerInfo struct {
	clientset        *kubernetes.Clientset
	Namespace        string
	ImagePullSecrets string
	RegistryAddress  string
	RegistryName     string
	RegistryUsername string
	RegistryPassword string
	Image            string
}

func (k *ContainerInfo) readDockerSecret(namespace, secretName string) (map[string][]byte, error) {
	secret, err := k.clientset.CoreV1().Secrets(namespace).Get(secretName, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	return secret.Data, nil
}

func (k *ContainerInfo) parseDockerConfig(dockerCreds DockerCreds) (bool, error) {
	for registryName, registryAuth := range dockerCreds.Auths {
		if strings.HasPrefix(registryName, "https://") {
			registryName = strings.TrimPrefix(registryName, "https://")
		}

		registryName = strings.TrimSuffix(registryName, "/")

		if strings.HasPrefix(k.Image, registryName) {
			k.RegistryName = registryName
			if registryAuth.ServerAddress != "" {
				k.RegistryAddress = registryAuth.ServerAddress
			} else {
				k.RegistryAddress = fmt.Sprintf("https://%s", registryName)
			}
			k.RegistryUsername = registryAuth.Username
			k.RegistryPassword = registryAuth.Password
			return true, nil
		}
	}

	return false, nil
}

func (k *ContainerInfo) fixDockerHubImage(image string) string {
	slash := strings.Index(image, "/")
	if slash == -1 { // Is it a DockerHub library repository?
		image = "index.docker.io/library/" + image
	} else if !strings.Contains(image[:slash], ".") { // DockerHub organization names can't contain '.'
		image = "index.docker.io/" + image
	} else {
		return image
	}

	// if in the end there is no RegistryAddress defined it should be a public DockerHub repository
	k.RegistryAddress = "https://index.docker.io"
	k.RegistryName = "index.docker.io"

	return image
}

// Collect reads information from k8s and load them into the structure
func (k *ContainerInfo) Collect(container *corev1.Container, podSpec *corev1.PodSpec) error {

	k.Image = k.fixDockerHubImage(container.Image)

	// k.clientset.Core().ServiceAccounts(k.Namespace).Get(podSpec.ServiceAccountName)

	// TODO read ServiceAccount's imagePullSecrets as well
	for _, imagePullSecret := range podSpec.ImagePullSecrets {
		data, err := k.readDockerSecret(k.Namespace, imagePullSecret.Name)
		if err != nil {
			return fmt.Errorf("cannot read imagePullSecrets '%s': %s", imagePullSecret.Name, err.Error())
		}

		var dockerCreds DockerCreds

		err = json.Unmarshal(data[corev1.DockerConfigJsonKey], &dockerCreds)
		if err != nil {
			return fmt.Errorf("cannot unmarshal docker configuration from imagePullSecrets: %s", err.Error())
		}

		found, err := k.parseDockerConfig(dockerCreds)
		if err != nil {
			return nil
		}

		if found {
			break
		}
	}

	// In case of other public docker registry
	if k.RegistryName == "" && k.RegistryAddress == "" {
		registryName := container.Image
		if strings.HasPrefix(registryName, "https://") {
			registryName = strings.TrimPrefix(registryName, "https://")
		}

		registryName = strings.Split(registryName, "/")[0]
		k.RegistryName = registryName
		k.RegistryAddress = fmt.Sprintf("https://%s", registryName)
	}

	// Clean registry from image
	k.Image = strings.TrimPrefix(k.Image, fmt.Sprintf("%s/", k.RegistryName))

	return nil
}
