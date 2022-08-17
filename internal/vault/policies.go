// Copyright © 2021 Banzai Cloud
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

package vault

import (
	"fmt"
	"strings"

	"emperror.dev/errors"
	"github.com/hashicorp/hcl"
	hclPrinter "github.com/hashicorp/hcl/hcl/printer"
	"github.com/hashicorp/vault/api"
	"github.com/sirupsen/logrus"
)

type policy struct {
	Name           string `mapstructure:"name"`
	Rules          string `mapstructure:"rules"`
	RulesFormatted string
}

func initPoliciesConfig(policiesConfig []policy, mounts map[string]*api.MountOutput) ([]policy, error) {
	for index, policy := range policiesConfig {
		for k, v := range mounts {
			policy.Rules = strings.Replace(policy.Rules, fmt.Sprintf("__accessor__%s", strings.TrimRight(k, "/")), v.Accessor, -1)
		}
		//
		// Format HCL polices.
		rulesFormatted, err := hclPrinter.Format([]byte(policy.Rules))
		if err != nil {
			// Check if rules parse (HCL or JSON).
			if _, err := hcl.Parse(policy.Rules); err != nil {
				return nil, errors.Wrapf(err, "error parsing %s policy rules", policy.Name)
			}

			// Policies are parsable but couldn't be HCL formatted (most likely JSON).
			rulesFormatted = []byte(policy.Rules)
			logrus.Debugf("error HCL-formatting %s policy rules (ignore if rules are JSON-formatted): %s",
				policy.Name, err.Error())
		}
		policiesConfig[index].RulesFormatted = string(rulesFormatted)
	}

	return policiesConfig, nil
}

func (v *vault) addManagedPolicies(managedPolicies []policy) error {
	for _, policy := range managedPolicies {
		logrus.Infof("adding policy %s", policy.Name)
		if err := v.cl.Sys().PutPolicy(policy.Name, policy.RulesFormatted); err != nil {
			return errors.Wrapf(err, "error putting %s policy into vault", policy.Name)
		}
	}

	return nil
}

// getExistingPolicies gets all policies that are already in Vault.
// The existing policies are in a map to make it easy to delete easily from it with "O(n)" complexity.
func (v *vault) getExistingPolicies() (map[string]bool, error) {
	existingPolicies := make(map[string]bool)

	existingPoliciesList, err := v.cl.Sys().ListPolicies()
	if err != nil {
		return nil, errors.Wrapf(err, "unable to list existing policies")
	}

	for _, existingPolicy := range existingPoliciesList {
		existingPolicies[existingPolicy] = true
	}

	return existingPolicies, nil
}

// getUnmanagedPolicies gets unmanaged policies by comparing what's already in Vault and what's in the externalConfig.
func (v *vault) getUnmanagedPolicies(managedPolicies []policy) map[string]bool {
	unmanagedPolicies, _ := v.getExistingPolicies()

	// Vault doesn't allow to remove default or root policies.
	delete(unmanagedPolicies, "root")
	delete(unmanagedPolicies, "default")

	// Remove managed polices form the items since the reset will be removed.
	for _, managedPolicy := range managedPolicies {
		delete(unmanagedPolicies, managedPolicy.Name)
	}

	return unmanagedPolicies
}

func (v *vault) removeUnmanagedPolicies(managedPolicies []policy) error {
	if !extConfig.PurgeUnmanagedConfig.Enabled || extConfig.PurgeUnmanagedConfig.Exclude.Policies {
		logrus.Debugf("purge config is disabled, no unmanaged policies will be removed")
		return nil
	}

	unmanagedPolicies := v.getUnmanagedPolicies(managedPolicies)
	for policyName := range unmanagedPolicies {
		logrus.Infof("removing policy %s", policyName)
		if err := v.cl.Sys().DeletePolicy(policyName); err != nil {
			return errors.Wrapf(err, "error deleting %s policy from vault", policyName)
		}
	}
	return nil
}

func (v *vault) configurePolicies() error {
	auths, err := v.cl.Sys().ListAuth()
	if err != nil {
		return errors.Wrap(err, "error while getting list of auth engines")
	}
	managedPolicies, err := initPoliciesConfig(extConfig.Policies, auths)
	if err != nil {
		return errors.Wrap(err, "error while initializing policies config")
	}

	if err := v.addManagedPolicies(managedPolicies); err != nil {
		return errors.Wrap(err, "error while adding policies")
	}

	if err := v.removeUnmanagedPolicies(managedPolicies); err != nil {
		return errors.Wrap(err, "error while removing policies")
	}

	return nil
}
