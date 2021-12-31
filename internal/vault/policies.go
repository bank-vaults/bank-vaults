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
	"emperror.dev/errors"
	"github.com/hashicorp/hcl"
	hclPrinter "github.com/hashicorp/hcl/hcl/printer"
	"github.com/sirupsen/logrus"
)

type policy struct {
	Name           string `json:"name"`
	Rules          string `json:"rules"`
	RulesFormatted string
}

func (p *policy) format() error {
	// Try to format rules (HCL only)
	policyRules, err := hclPrinter.Format([]byte(p.Rules))
	if err != nil {
		// Check if rules parse (HCL or JSON)
		_, parseErr := hcl.Parse(p.Rules)
		if parseErr != nil {
			return errors.Wrapf(err, "error parsing %s policy rules", p.Name)
		}

		// Policies are parsable but couldn't be HCL formatted (most likely JSON)
		policyRules = []byte(p.Rules)
		logrus.Debugf("error HCL-formatting %s policy rules (ignore if rules are JSON-formatted): %s", p.Name, err.Error())
	}

	p.RulesFormatted = string(policyRules)

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
	for _, mangedPolicy := range managedPolicies {
		delete(unmanagedPolicies, mangedPolicy.Name)
	}

	return unmanagedPolicies
}

func (v *vault) configurePolicies() error {
	// Add managed policies.
	managedPolicies := extConfig.Policies
	logrus.Debugf("add manged policies %v", managedPolicies)
	for _, policy := range managedPolicies {
		if err := policy.format(); err != nil {
			return errors.Wrapf(err, "error formatting %s policy", policy.Name)
		}
		if err := v.cl.Sys().PutPolicy(policy.Name, policy.RulesFormatted); err != nil {
			return errors.Wrapf(err, "error putting %s policy into vault", policy.Name)
		}
	}

	// Remove unmanaged policies.
	if extConfig.PurgeUnmanagedConfig.Enabled && !extConfig.PurgeUnmanagedConfig.Exclude.Policies {
		unmanagedPolicies := v.getUnmanagedPolicies(managedPolicies)
		logrus.Debugf("remove unmanged policies %v", unmanagedPolicies)
		for policyName := range unmanagedPolicies {
			if err := v.cl.Sys().DeletePolicy(policyName); err != nil {
				return errors.Wrapf(err, "error deleting %s policy from vault", policyName)
			}
		}
	}

	return nil
}
