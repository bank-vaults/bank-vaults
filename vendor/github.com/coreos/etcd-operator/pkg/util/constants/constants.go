// Copyright 2016 The etcd-operator Authors
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

package constants

import "time"

const (
	DefaultDialTimeout    = 5 * time.Second
	DefaultRequestTimeout = 5 * time.Second
	// DefaultBackupTimeout is the default maximal allowed time of the entire backup process.
	DefaultBackupTimeout    = 1 * time.Minute
	DefaultSnapshotInterval = 1800 * time.Second

	DefaultBackupPodHTTPPort = 19999

	OperatorRoot   = "/var/tmp/etcd-operator"
	BackupMountDir = "/var/etcd-backup"

	EnvOperatorPodName      = "MY_POD_NAME"
	EnvOperatorPodNamespace = "MY_POD_NAMESPACE"
)
