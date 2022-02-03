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
	"github.com/spf13/viper"
)

type audit struct {
	Type        string                 `json:"type"`
	Path        string                 `json:"path"`
	Description string                 `json:"description"`
	Options     map[string]interface{} `json:"options`
}

func (audit *audit) setPath() {
	if audit.Path == "" {
		audit.Path = audit.Type
		return
	}

	audit.Path = strings.Trim(audit.Path, "/")
}

func (a *audit) setDefaults() {
	if a.Path == "" {
		a.Path = a.Type
	}
}

// getExistingAudits gets all audits that are already in Vault.
func (v *vault) getExistingAudits() (map[string]bool, error) {
	existingAudits := make(map[string]bool)

	existingAuditsList, err := v.cl.Sys().ListAudit()
	if err != nil {
		return nil, errors.Wrapf(err, "unable to list existing audits")
	}

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

func (v *vault) addManagedAudits(managedAudits []audit, existingAudits map[string]*audit) error {
	return nil
}

func (v *vault) removeUnmanagedAudits(unmanagedAudits map[string]bool) error {
	if len(unmanagedAudits) == 0 || !extConfig.PurgeUnmanagedConfig.Enabled || extConfig.PurgeUnmanagedConfig.Exclude.Audits {
		return nil
	}

	// TODO: Refactor this to remove the map of bools
	for auditPath, _ := range unmanagedAudits {
		logrus.Infof("removing unmanged audit %s", auditPath)
		err := v.cl.Sys().DisableAudit(auditPath)
		if err != nil {
			return errors.Wrapf(err, "error disabling %s audit in vault", auditPath)
		}
	}
	return nil
}

func (v *vault) configureAuditDevices(config *viper.Viper) error {
	managedAudits := extConfig.Audit
	for i := range managedAudits {
		managedAudits[i].setDefaults()
	}
	unmanagedAudits := v.getUnmanagedAudits(managedAudits)

	err := v.removeUnmanagedAudits(unmanagedAudits)
	if err != nil {
		return errors.Wrap(err, "error while disabling unmanaged auth methods")
	}

	for _, auditDevice := range managedAudits {
		path := auditDevice.Type

		mounts, err := v.cl.Sys().ListAudit()
		if err != nil {
			return errors.Wrap(err, "error reading audit mounts from vault")
		}

		logrus.Infof("already existing audit devices: %#v", mounts)

		if mounts[path+"/"] == nil {
			var options api.EnableAuditOptions
			err = mapstructure.Decode(auditDevice, &options)
			if err != nil {
				return errors.Wrap(err, "error parsing audit options")
			}
			logrus.Infof("enabling audit device with options: %#v", options)
			err = v.cl.Sys().EnableAuditWithOptions(path, &options)
			if err != nil {
				return errors.Wrapf(err, "error enabling audit device %s in vault", path)
			}

			// logrus.Infoln("mounted audit device", auditDeviceType, "to", path)
		} else {
			logrus.Infof("audit device is already mounted: %s/", path)
		}
	}

	return nil
}
