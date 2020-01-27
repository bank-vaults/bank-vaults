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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ecr"
	dockerTypes "github.com/docker/docker/api/types"
	"github.com/heroku/docker-registry-client/registry"
	imagev1 "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/patrickmn/go-cache"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const ecrCredentialsKey = "AWS_ECR_CREDENTIALS"

var logger *log.Logger
var ecrHostPattern *regexp.Regexp

func init() {
	logger = log.New()
	if viper.GetBool("enable_json_log") {
		logger.SetFormatter(&log.JSONFormatter{})
	}

	// Adapted from https://github.com/awslabs/amazon-ecr-credential-helper/blob/master/ecr-login/api/client.go#L34
	ecrHostPattern = regexp.MustCompile(`([a-zA-Z0-9][a-zA-Z0-9-_]*)\.dkr\.ecr(\-fips)?\.([a-zA-Z0-9][a-zA-Z0-9-_]*)\.amazonaws\.com(\.cn)?`)
}

// ImageRegistry is a docker registry
type ImageRegistry interface {
	GetImageConfig(
		clientset kubernetes.Interface,
		namespace string,
		container *corev1.Container,
		podSpec *corev1.PodSpec) (*imagev1.ImageConfig, error)
}

// Registry impl
type Registry struct {
	imageCache       *cache.Cache
	credentialsCache *cache.Cache
}

// NewRegistry creates and initializes registry
func NewRegistry() ImageRegistry {
	return &Registry{
		imageCache:       cache.New(cache.NoExpiration, cache.NoExpiration),
		credentialsCache: cache.New(12*time.Hour, 12*time.Hour),
	}
}

type DockerCreds struct {
	Auths map[string]dockerTypes.AuthConfig `json:"auths"`
}

// IsAllowedToCache checks that information about Docker image can be cached
// base on image name and container PullPolicy
func IsAllowedToCache(container *corev1.Container) bool {
	if container.ImagePullPolicy == corev1.PullAlways {
		return false
	}
	_, reference := parseContainerImage(container.Image)

	return reference != "latest"
}

// GetImageConfig returns entrypoint and command of container
func (r *Registry) GetImageConfig(
	clientset kubernetes.Interface,
	namespace string,
	container *corev1.Container,
	podSpec *corev1.PodSpec) (*imagev1.ImageConfig, error) {
	allowToCache := IsAllowedToCache(container)
	if allowToCache {
		if imageConfig, cacheHit := r.imageCache.Get(container.Image); cacheHit {
			logger.Infof("found image %s in cache", container.Image)
			return imageConfig.(*imagev1.ImageConfig), nil
		}
	}

	containerInfo := ContainerInfo{Namespace: namespace, clientset: clientset}

	err := containerInfo.Collect(container, podSpec, r.credentialsCache)
	if err != nil {
		return nil, err
	}

	logger.Infoln("I'm using registry", containerInfo.RegistryAddress)

	imageConfig, err := getImageBlob(containerInfo)
	if imageConfig != nil && allowToCache {
		r.imageCache.Set(container.Image, imageConfig, cache.DefaultExpiration)
	}

	return imageConfig, err
}

// GetImageBlob download image blob from registry
func getImageBlob(container ContainerInfo) (*imagev1.ImageConfig, error) {
	imageName, reference := parseContainerImage(container.Image)

	registrySkipVerify := viper.GetBool("registry_skip_verify")

	var hub *registry.Registry
	var err error

	if registrySkipVerify {
		hub, err = registry.NewInsecure(container.RegistryAddress, container.RegistryUsername, container.RegistryPassword)
	} else {
		hub, err = registry.New(container.RegistryAddress, container.RegistryUsername, container.RegistryPassword)
	}
	if err != nil {
		return nil, fmt.Errorf("cannot create client for registry: %s", err.Error())
	}

	manifest, err := hub.ManifestV2(imageName, reference)
	if err != nil {
		return nil, fmt.Errorf("cannot download manifest for image: %s", err.Error())
	}

	reader, err := hub.DownloadBlob(imageName, manifest.Config.Digest)
	if err != nil {
		return nil, fmt.Errorf("cannot download blob: %s", err.Error())
	}

	defer reader.Close()

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

// parseContainerImage returns image and reference
func parseContainerImage(image string) (string, string) {
	var split []string

	if strings.Contains(image, "@") {
		split = strings.SplitN(image, "@", 2)
	} else {
		split = strings.SplitN(image, ":", 2)
	}

	imageName := split[0]
	reference := "latest"

	if len(split) > 1 {
		reference = split[1]
	}

	return imageName, reference
}

// K8s structure keeps information retrieved from POD definition
type ContainerInfo struct {
	clientset        kubernetes.Interface
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

		// kubectl create secret docker-registry for DockerHub creates
		// registry credentials with API version suffixes, trim it!
		if strings.HasSuffix(registryName, "/v1/") {
			registryName = strings.TrimSuffix(registryName, "/v1/")
		} else if strings.HasSuffix(registryName, "/v2/") {
			registryName = strings.TrimSuffix(registryName, "/v2/")
		}

		registryName = strings.TrimSuffix(registryName, "/")

		if strings.HasPrefix(k.Image, registryName) {
			k.RegistryName = registryName
			if registryAuth.ServerAddress != "" {
				k.RegistryAddress = registryAuth.ServerAddress
			} else {
				k.RegistryAddress = fmt.Sprintf("https://%s", registryName)
			}
			if len(registryAuth.Username) > 0 && len(registryAuth.Password) > 0 {
				// auths.<registry>.username and auths.<registry>.username are present
				// in the config.json, use them
				k.RegistryUsername = registryAuth.Username
				k.RegistryPassword = registryAuth.Password
			} else if len(registryAuth.Auth) > 0 {
				// auths.<registry>.username and auths.<registry>.username are not present
				// in the config.json, fall back to the base64 encoded auths.<registry>.auth field
				// The registry.Auth field contains a base64 encoded string of the format <username>:<password>
				decodedAuth, err := base64.StdEncoding.DecodeString(registryAuth.Auth)
				if err != nil {
					return false, fmt.Errorf("failed to decode auth field for registry %s: %s", registryName, err.Error())
				}
				auth := strings.Split(string(decodedAuth), ":")
				if len(auth) != 2 {
					return false, fmt.Errorf("unexpected number of elements in auth field for registry %s: %d (expected 2)", registryName, len(auth))
				}
				// decodedAuth is something like ":xxx"
				if len(auth[0]) <= 0 {
					return false, fmt.Errorf("username element of auth field for registry %s missing", registryName)
				}
				// decodedAuth is something like "xxx:"
				if len(auth[1]) <= 0 {
					return false, fmt.Errorf("password element of auth field for registry %s missing", registryName)
				}
				k.RegistryUsername = auth[0]
				k.RegistryPassword = auth[1]
			} else {
				// the auths section has an entry for the registry, but it neither contains
				// username/password fields nor an auth field, fail
				return false, fmt.Errorf("found %s in imagePullSecrets but it contains no usable credentials; either username/password fields or an auth field are required", registryName)
			}

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
	} else if strings.HasPrefix(image, "docker.io/") {
		image = "index." + image
	} else {
		return image
	}

	// if in the end there is no RegistryAddress defined it should be a public DockerHub repository
	k.RegistryAddress = "https://index.docker.io"
	k.RegistryName = "index.docker.io"

	return image
}

func (k *ContainerInfo) checkImagePullSecret(namespace string, secret string) (bool, error) {
	data, err := k.readDockerSecret(namespace, secret)
	if err != nil {
		return false, fmt.Errorf("cannot read imagePullSecret '%s' in namespace '%s': %s", secret, namespace, err.Error())
	}

	var dockerCreds DockerCreds

	dockerConfigJSONKey := viper.GetString("default_image_pull_docker_config_json_key")
	err = json.Unmarshal(data[dockerConfigJSONKey], &dockerCreds)
	if err != nil {
		return false, fmt.Errorf("cannot unmarshal docker configuration from imagePullSecret: %s", err.Error())
	}

	found, err := k.parseDockerConfig(dockerCreds)
	return found, err
}

// Collect reads information from k8s and load them into the structure
func (k *ContainerInfo) Collect(container *corev1.Container, podSpec *corev1.PodSpec, credentialsCache *cache.Cache) error {
	k.Image = k.fixDockerHubImage(container.Image)

	var err error
	found := false
	// Check for registry credentials in imagePullSecrets attached to the pod
	// ImagePullSecrets attached to ServiceAccounts do not have to be considered
	// explicitly as ServiceAccount ImagePullSecrets are automatically attached
	// to a pod.
	for _, imagePullSecret := range podSpec.ImagePullSecrets {
		found, err = k.checkImagePullSecret(k.Namespace, imagePullSecret.Name)
		if err != nil {
			return err
		}

		if found {
			logger.Infof("found credentials for registry %s in pod imagePullSecret: %s/%s", k.RegistryName, k.Namespace, imagePullSecret.Name)
			break
		}
	}

	// The pod imagePullSecrets did not contained matching credentials.
	// Try to find matching registry credentials in the default imagePullSecret if one was provided.
	if !found {
		defaultImagePullSecret := viper.GetString("default_image_pull_secret")
		defaultImagePullSecretNamespace := viper.GetString("default_image_pull_secret_namespace")
		if len(defaultImagePullSecret) > 0 && len(defaultImagePullSecretNamespace) > 0 {
			found, err = k.checkImagePullSecret(defaultImagePullSecretNamespace, defaultImagePullSecret)
			if err != nil {
				return err
			}

			if found {
				logger.Infof("found credentials for registry %s in default imagePullSecret: %s/%s", k.RegistryName, defaultImagePullSecretNamespace, defaultImagePullSecret)
			}
		}
	}

	// In case of other docker registry
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

	if !found {
		// if still no credentials and it is an ECR image, try to get credentials through an EC2 instance role
		if ecrRegistryID, region := getECRRegistryIDAndRegion(k.RegistryAddress); ecrRegistryID != "" {
			logger.Infof("trying to request AWS credentials for ECR registry %s", k.RegistryAddress)

			var data string
			cacheKey := ecrCredentialsKey + k.RegistryAddress
			cachedToken, usingCache := credentialsCache.Get(cacheKey)
			if usingCache {
				data = cachedToken.(string)
				logger.Infof("Using cached AWS ECR Token for registry %s", k.RegistryAddress)
			} else {
				sess, err := session.NewSession()
				if err != nil {
					logger.Info("Failed to create AWS session, trying with no credentials")
					return nil
				}
				svc := ecr.New(sess, aws.NewConfig().WithRegion(region))

				req := ecr.GetAuthorizationTokenInput{
					RegistryIds: []*string{aws.String(ecrRegistryID)},
				}

				resp, err := svc.GetAuthorizationToken(&req)
				if err != nil {
					logger.Infof("Failed to get AWS ECR Token, trying with no credentials")
					return nil
				}

				// We requested only one entry
				authData := resp.AuthorizationData[0]

				decodedData, err := base64.StdEncoding.DecodeString(aws.StringValue(authData.AuthorizationToken))
				data = string(decodedData)
				if err != nil {
					return err
				}

				expiration := authData.ExpiresAt.Sub(time.Now().Add(5 * time.Minute))
				credentialsCache.Set(cacheKey, data, expiration)
				logger.Infof("Caching ECR token with expiration in %+v", expiration)
			}

			token := strings.SplitN(data, ":", 2)

			k.RegistryUsername = token[0]
			k.RegistryPassword = token[1]

			logger.Infof("got AWS credentials for ecr registry %s", k.RegistryAddress)
		} else {
			logger.Infof("found no credentials for registry %s, assuming it is public", k.RegistryAddress)
		}
	}

	return nil
}

func getECRRegistryIDAndRegion(registryAddr string) (string, string) {
	matches := ecrHostPattern.FindStringSubmatch(registryAddr)
	if len(matches) < 3 {
		return "", ""
	}
	return matches[1], matches[3]
}
