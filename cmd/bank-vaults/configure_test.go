// Copyright © 2026 Bank-Vaults Maintainers
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
	"testing"

	"github.com/stretchr/testify/assert"
)

type recordingLoader struct {
	calls *[]string
}

func (l recordingLoader) LoadConfig(path string, _ map[string]any) error {
	*l.calls = append(*l.calls, "load:"+path)

	return nil
}

func runBatches(batches ...[]*configFile) []string {
	configurations := make(chan []*configFile, len(batches))
	for _, batch := range batches {
		configurations <- batch
	}
	close(configurations)

	calls := []string{}
	processBatches(recordingLoader{&calls}, configurations, func(config *configFile) {
		calls = append(calls, "apply:"+config.Path)
	})

	return calls
}

// Every file of a batch is loaded before the first one is applied, so that it
// does not purge what the following ones declare.
func TestProcessBatchesLoadsEveryFileBeforeApplying(t *testing.T) {
	calls := runBatches([]*configFile{{Path: "a.yml"}, {Path: "b.yml"}})

	assert.Equal(t, []string{"load:a.yml", "load:b.yml", "apply:a.yml", "apply:b.yml"}, calls)
}

// The batches already queued are loaded with the current one, and a file
// queued twice is applied once: Configure applies its latest version.
func TestProcessBatchesMergesQueuedBatches(t *testing.T) {
	calls := runBatches(
		[]*configFile{{Path: "a.yml"}},
		[]*configFile{{Path: "b.yml"}},
		[]*configFile{{Path: "a.yml"}},
	)

	assert.Equal(t, []string{
		"load:a.yml", "load:b.yml", "load:a.yml",
		"apply:a.yml", "apply:b.yml",
	}, calls)
}
