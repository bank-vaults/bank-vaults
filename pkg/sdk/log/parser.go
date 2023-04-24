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

package log

import (
	syslogformat "gopkg.in/mcuadros/go-syslog.v2/format"

	"github.com/bank-vaults/vault-sdk/log"
)

// Deprecated: use [log.ConnectionError] instead.
const ConnectionError = log.ConnectionError

// Deprecated: use [log.GetClientFromLog] instead.
func GetClientFromLog(logParts syslogformat.LogParts) (string, error) {
	return log.GetClientFromLog(logParts)
}

// Deprecated: use [log.GetContentFromLog] instead.
func GetContentFromLog(logParts syslogformat.LogParts) ([]string, error) {
	return log.GetContentFromLog(logParts)
}

// Deprecated: use [log.ParseLogMessage] instead.
func ParseLogMessage(content []string) map[string]string {
	return log.ParseLogMessage(content)
}
