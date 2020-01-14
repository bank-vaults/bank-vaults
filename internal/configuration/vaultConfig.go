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

package configuration

import (
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
)

// VaultConfig represents vault options
type VaultConfig struct {
	Addr                        string
	Role                        string
	Path                        string
	SkipVerify                  string
	TLSSecret                   string
	UseAgent                    bool
	TransitKeyID                string
	TransitPath                 string
	CtConfigMap                 string
	CtImage                     string
	CtOnce                      bool
	CtImagePullPolicy           corev1.PullPolicy
	CtShareProcess              bool
	CtShareProcessDefault       string
	CtCPU                       resource.Quantity
	CtMemory                    resource.Quantity
	PspAllowPrivilegeEscalation bool
	IgnoreMissingSecrets        string
	VaultEnvPassThrough         string
	ConfigfilePath              string
	MutateConfigMap             bool
	EnableJSONLog               string
	AgentConfigMap              string
	AgentOnce                   bool
	AgentShareProcess           bool
	AgentShareProcessDefault    string
	AgentCPU                    resource.Quantity
	AgentMemory                 resource.Quantity
	AgentImage                  string
	AgentImagePullPolicy        corev1.PullPolicy
}
