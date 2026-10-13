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
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jpillora/backoff"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeVault records the calls in order. Sealed returns the scripted values,
// then false; Configure fails for the failing paths.
type fakeVault struct {
	calls   []string
	sealed  []bool
	failing map[string]bool
}

func (f *fakeVault) LoadConfig(path string, _ map[string]any) error {
	f.calls = append(f.calls, "load:"+path)

	return nil
}

func (f *fakeVault) Sealed() (bool, error) {
	sealed := false
	if len(f.sealed) > 0 {
		sealed, f.sealed = f.sealed[0], f.sealed[1:]
	}
	f.calls = append(f.calls, fmt.Sprintf("sealed:%t", sealed))

	return sealed, nil
}

func (f *fakeVault) Configure(_ context.Context, path string) error {
	f.calls = append(f.calls, "configure:"+path)
	if f.failing[path] {
		return errors.New("configure failed")
	}

	return nil
}

func runBatches(v *fakeVault, opts applyOptions, batches ...[]*configFile) error {
	configurations := make(chan []*configFile, len(batches))
	for _, batch := range batches {
		configurations <- batch
	}
	close(configurations)

	if opts.backoff == nil {
		opts.backoff = &backoff.Backoff{Min: time.Millisecond, Max: time.Second, Factor: 2}
	}

	return processBatches(context.Background(), v, configurations, opts)
}

// daemon returns the options of the daemon mode, recording the retries.
func daemon(v *fakeVault) applyOptions {
	return applyOptions{retry: func(path string, delay time.Duration) {
		v.calls = append(v.calls, fmt.Sprintf("retry:%s:%s", path, delay))
	}}
}

// Every file of a batch is loaded before the first one is applied, so that it
// does not purge what the following ones declare.
func TestProcessBatchesLoadsEveryFileBeforeApplying(t *testing.T) {
	v := &fakeVault{}
	err := runBatches(v, daemon(v), []*configFile{{Path: "a.yml"}, {Path: "b.yml"}})

	require.NoError(t, err)
	assert.Equal(t, []string{
		"load:a.yml", "load:b.yml",
		"sealed:false", "configure:a.yml",
		"sealed:false", "configure:b.yml",
	}, v.calls)
}

// The batches already queued are loaded with the current one, and a file
// queued twice is applied once: Configure applies its latest version.
func TestProcessBatchesMergesQueuedBatches(t *testing.T) {
	v := &fakeVault{}
	err := runBatches(v, daemon(v),
		[]*configFile{{Path: "a.yml"}},
		[]*configFile{{Path: "b.yml"}},
		[]*configFile{{Path: "a.yml"}},
	)

	require.NoError(t, err)
	assert.Equal(t, []string{
		"load:a.yml", "load:b.yml", "load:a.yml",
		"sealed:false", "configure:a.yml",
		"sealed:false", "configure:b.yml",
	}, v.calls)
}

// A file is configured only once Vault is unsealed.
func TestProcessBatchesWaitsForUnseal(t *testing.T) {
	v := &fakeVault{sealed: []bool{true, true}}
	err := runBatches(v, daemon(v), []*configFile{{Path: "a.yml"}})

	require.NoError(t, err)
	assert.Equal(t, []string{
		"load:a.yml",
		"sealed:true", "sealed:true", "sealed:false", "configure:a.yml",
	}, v.calls)
}

// The daemon retries a failed file with the backoff, which any success resets.
func TestProcessBatchesRetriesInDaemonMode(t *testing.T) {
	v := &fakeVault{failing: map[string]bool{"a.yml": true, "c.yml": true}}
	err := runBatches(v, daemon(v), []*configFile{{Path: "a.yml"}, {Path: "b.yml"}, {Path: "c.yml"}})

	require.NoError(t, err)
	assert.Equal(t, []string{
		"load:a.yml", "load:b.yml", "load:c.yml",
		"sealed:false", "configure:a.yml", "retry:a.yml:1ms",
		"sealed:false", "configure:b.yml",
		"sealed:false", "configure:c.yml", "retry:c.yml:1ms",
	}, v.calls)
}

// With --once the channel is closed: a failed file is not retried, the other
// files are still applied, and the run fails at the end.
func TestProcessBatchesOnceFailsWithoutRetrying(t *testing.T) {
	v := &fakeVault{failing: map[string]bool{"a.yml": true}}
	err := runBatches(v, applyOptions{}, []*configFile{{Path: "a.yml"}, {Path: "b.yml"}})

	require.Error(t, err)
	assert.Equal(t, []string{
		"load:a.yml", "load:b.yml",
		"sealed:false", "configure:a.yml",
		"sealed:false", "configure:b.yml",
	}, v.calls)
}

// With --fatal the first failed file stops the run.
func TestProcessBatchesFatalStopsAtFirstFailure(t *testing.T) {
	v := &fakeVault{failing: map[string]bool{"a.yml": true}}
	opts := daemon(v)
	opts.fatal = true
	err := runBatches(v, opts, []*configFile{{Path: "a.yml"}, {Path: "b.yml"}})

	require.Error(t, err)
	assert.Equal(t, []string{
		"load:a.yml", "load:b.yml",
		"sealed:false", "configure:a.yml",
	}, v.calls)
}
