// Copyright © 2025 Bank-Vaults Maintainers
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
	"os"
	"path/filepath"
	"testing"

	"github.com/bank-vaults/vault-sdk/utils/templater"
)

func TestRenderTemplates_FileMode(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		mode os.FileMode
	}{
		{name: "default 0640", mode: 0o640},
		{name: "restrictive 0600", mode: 0o600},
		{name: "world readable 0644", mode: 0o644},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()
			src := filepath.Join(dir, "src.tmpl")
			dst := filepath.Join(dir, "dst.out")

			if err := os.WriteFile(src, []byte("hello\n"), 0o600); err != nil {
				t.Fatalf("seeding source: %v", err)
			}

			tmpl := templater.NewTemplater("[[", "]]")
			if err := renderTemplates(&tmpl, []string{src + ":" + dst}, tc.mode); err != nil {
				t.Fatalf("renderTemplates returned error: %v", err)
			}

			info, err := os.Stat(dst)
			if err != nil {
				t.Fatalf("stat destination: %v", err)
			}

			got := info.Mode().Perm()
			if got != tc.mode {
				t.Errorf("destination mode = %o, want %o", got, tc.mode)
			}
		})
	}
}

func TestRenderTemplates_MultipleFiles(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	srcA := filepath.Join(dir, "a.tmpl")
	dstA := filepath.Join(dir, "a.out")
	srcB := filepath.Join(dir, "b.tmpl")
	dstB := filepath.Join(dir, "b.out")

	if err := os.WriteFile(srcA, []byte("alpha"), 0o600); err != nil {
		t.Fatalf("seeding source A: %v", err)
	}
	if err := os.WriteFile(srcB, []byte("bravo"), 0o600); err != nil {
		t.Fatalf("seeding source B: %v", err)
	}

	tmpl := templater.NewTemplater("[[", "]]")
	mode := os.FileMode(0o640)
	pairs := []string{srcA + ":" + dstA, srcB + ":" + dstB}

	if err := renderTemplates(&tmpl, pairs, mode); err != nil {
		t.Fatalf("renderTemplates returned error: %v", err)
	}

	for _, dst := range []string{dstA, dstB} {
		info, err := os.Stat(dst)
		if err != nil {
			t.Fatalf("stat %s: %v", dst, err)
		}
		if got := info.Mode().Perm(); got != mode {
			t.Errorf("%s mode = %o, want %o", dst, got, mode)
		}
	}
}

func TestRenderTemplates_MalformedPair(t *testing.T) {
	t.Parallel()

	tmpl := templater.NewTemplater("[[", "]]")
	err := renderTemplates(&tmpl, []string{"only-one-segment"}, 0o640)
	if err == nil {
		t.Fatal("expected error for malformed pair, got nil")
	}
}

func TestRenderInlineConfig_FileMode(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	dst := filepath.Join(dir, "vault.json")

	tmpl := templater.NewTemplater("${", "}")
	mode := os.FileMode(0o640)
	if err := renderInlineConfig(&tmpl, `{"foo":"bar"}`, dst, mode); err != nil {
		t.Fatalf("renderInlineConfig returned error: %v", err)
	}

	info, err := os.Stat(dst)
	if err != nil {
		t.Fatalf("stat destination: %v", err)
	}
	if got := info.Mode().Perm(); got != mode {
		t.Errorf("destination mode = %o, want %o", got, mode)
	}
}
