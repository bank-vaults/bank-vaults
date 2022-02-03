// Copyright © 2022 Banzai Cloud
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
	"strings"

	"emperror.dev/errors"
	"github.com/hashicorp/vault/api"
	"github.com/mitchellh/mapstructure"
	"github.com/sirupsen/logrus"
)

type audit struct {
	Type        string                 `json:"type"`
	Path        string                 `json:"path"`
	Description string                 `json:"description"`
	Options     map[string]interface{} `json:"options"`
}

func (a *audit) setDefaults() {
	if a.Path == "" {
		a.Path = a.Type
	}
}

func (a *audit) setPath() {
	a.setDefaults()
	a.Path = strings.Trim(a.Path, "/")
}

// getExistingAudits gets all audits that are already in Vault.
func (v *vault) getExistingAudits() (map[string]bool, error) {
	existingAudits := make(map[string]bool)

	existingAuditsList, err := v.cl.Sys().ListAudit()
	if err != nil {
		return nil, errors.Wrapf(err, "unable to list existing audits")
	}

	logrus.Infof("already existing audit devices: %#v", existingAuditsList)

	for existingAuditPath := range existingAuditsList {
		existingAudits[strings.Trim(existingAuditPath, "/")] = true
	}

	return existingAudits, nil
}

func (v *vault) getUnmanagedAudits(managedAudits []audit) map[string]bool {
	unmanagedAudits, _ := v.getExistingAudits()

	// Remove managed audits form the items since the reset will be removed.
	for _, managedAudit := range managedAudits {
		managedAudit.setPath()
		delete(unmanagedAudits, managedAudit.Type)
	}

	return unmanagedAudits
}

func (v *vault) addManagedAudits(managedAudits []audit, existingAudits map[string]bool) error {
	for _, auditDevice := range managedAudits {
		if existingAudits[auditDevice.Type] {
			logrus.Infof("audit device is already mounted: %s/", auditDevice.Path)
		} else {
			var options api.EnableAuditOptions
			err := mapstructure.Decode(auditDevice, &options)
			if err != nil {
				return errors.Wrap(err, "error parsing audit options")
			}

			logrus.Infof("enabling audit device with options: %#v", options)
			err = v.cl.Sys().EnableAuditWithOptions(auditDevice.Path+"/", &options)
			if err != nil {
				return errors.Wrapf(err, "error enabling audit device %s in vault", auditDevice.Path)
			}

			logrus.Infoln("mounted audit device", auditDevice.Type, "to", auditDevice.Path)
		}
	}

	return nil
}

// Disables any audit that's not managed if purgeUnmanagedConfig option is enabled, otherwise it leaves them
func (v *vault) removeUnmanagedAudits(unmanagedAudits map[string]bool) error {
	if len(unmanagedAudits) == 0 || !extConfig.PurgeUnmanagedConfig.Enabled || extConfig.PurgeUnmanagedConfig.Exclude.Audit {
		return nil
	}

	for auditPath := range unmanagedAudits {
		logrus.Infof("removing unmanged audit %s", auditPath)
		err := v.cl.Sys().DisableAudit(auditPath)
		if err != nil {
			return errors.Wrapf(err, "error disabling %s audit in vault", auditPath)
		}
	}
	return nil
}

func (v *vault) configureAuditDevices() error {
	managedAudits := extConfig.Audit
	for i := range managedAudits {
		managedAudits[i].setDefaults()
	}
	existingAudits, _ := v.getExistingAudits()
	unmanagedAudits := v.getUnmanagedAudits(managedAudits)

	err := v.addManagedAudits(managedAudits, existingAudits)
	if err != nil {
		return errors.Wrap(err, "error configuring managed audits")
	}

	err = v.removeUnmanagedAudits(unmanagedAudits)
	if err != nil {
		return errors.Wrap(err, "error while disabling unmanaged auth methods")
	}

	return nil
}
