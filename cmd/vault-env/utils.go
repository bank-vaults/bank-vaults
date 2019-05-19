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
	"io/ioutil"
	"os"
	"strings"

	"go.uber.org/zap"

	"github.com/heroku/docker-registry-client/registry"
)

// GetImageBlob download image blob from registry
func GetImageBlob(url, username, password, image, registryName string) ([]string, []string) {
	imageName, tag := ParseContainerImage(image)

	registrySkipVerify := os.Getenv("REGISTRY_SKIP_VERIFY")

	var hub *registry.Registry
	var err error

	if registrySkipVerify == "true" {
		hub, err = registry.NewInsecure(url, username, password)
	} else {
		hub, err = registry.New(url, username, password)
	}
	if err != nil {
		logger.Fatal("Cannot create client for registry", zap.Error(err))
	}

	manifest, err := hub.ManifestV2(imageName, tag)
	if err != nil {
		logger.Fatal("Cannot download manifest for image", zap.Error(err))
	}

	reader, err := hub.DownloadBlob(imageName, manifest.Config.Digest)
	if reader != nil {
		defer reader.Close()
	}
	if err != nil {
		logger.Fatal("Cannot download blob", zap.Error(err))
	}

	b, err := ioutil.ReadAll(reader)
	if err != nil {
		logger.Fatal("Cannot read blob", zap.Error(err))
	}

	var msg BlobResponse
	err = json.Unmarshal(b, &msg)
	if err != nil {
		logger.Fatal("Cannot unmarshal JSON", zap.Error(err))
	}

	return msg.Config.Entrypoint, msg.Config.Cmd
}

// ParseContainerImage returns image and tag
func ParseContainerImage(image string) (string, string) {
	split := strings.SplitN(image, ":", 2)

	if len(split) <= 1 {
		logger.Fatal("Cannot find tag for image", zap.String("image", image))
	}

	imageName := split[0]
	tag := split[1]

	return imageName, tag
}
