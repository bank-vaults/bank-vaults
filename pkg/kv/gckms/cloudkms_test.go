// Copyright © 2026 Banzai Cloud
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

package gckms

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	cloudkms "google.golang.org/api/cloudkms/v1"
	"google.golang.org/api/option"

	"github.com/bank-vaults/bank-vaults/pkg/kv"
)

type memStore map[string][]byte

func (m memStore) Get(_ context.Context, key string) ([]byte, error) {
	v, ok := m[key]
	if !ok {
		return nil, kv.NewNotFoundError("key not found: %s", key)
	}
	return v, nil
}

func (m memStore) Set(_ context.Context, key string, val []byte) error {
	m[key] = val
	return nil
}

// fakeKMS encrypts by prefixing the plaintext with the key version, like
// Cloud KMS binds a ciphertext to the version that made it.
type fakeKMS struct {
	primary  string
	disabled map[string]bool
	encrypts int
}

func (f *fakeKMS) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Plaintext  string `json:"plaintext"`
		Ciphertext string `json:"ciphertext"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	switch {
	case strings.HasSuffix(r.URL.Path, ":encrypt"):
		f.encrypts++
		plain, _ := base64.StdEncoding.DecodeString(req.Plaintext)
		ct := base64.StdEncoding.EncodeToString([]byte(f.primary + ":" + string(plain)))
		_ = json.NewEncoder(w).Encode(cloudkms.EncryptResponse{Ciphertext: ct})
	case strings.HasSuffix(r.URL.Path, ":decrypt"):
		ct, _ := base64.StdEncoding.DecodeString(req.Ciphertext)
		version, plain, _ := strings.Cut(string(ct), ":")
		if f.disabled[version] {
			http.Error(w, fmt.Sprintf(`{"error":{"code":400,"message":"cryptoKeyVersions/%s is not enabled"}}`, version), http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(cloudkms.DecryptResponse{
			Plaintext:   base64.StdEncoding.EncodeToString([]byte(plain)),
			UsedPrimary: version == f.primary,
		})
	default:
		http.NotFound(w, r)
	}
}

func newTestKms(t *testing.T, fake *fakeKMS, store kv.Service) *googleKms {
	t.Helper()
	srv := httptest.NewServer(fake)
	t.Cleanup(srv.Close)

	svc, err := cloudkms.NewService(context.Background(), option.WithEndpoint(srv.URL+"/"), option.WithHTTPClient(srv.Client()))
	if err != nil {
		t.Fatal(err)
	}
	return &googleKms{svc: svc, store: store, keyPath: "projects/p/locations/global/keyRings/r/cryptoKeys/k"}
}

func TestGetReencryptsAfterKeyRotation(t *testing.T) {
	ctx := context.Background()
	fake := &fakeKMS{primary: "1", disabled: map[string]bool{}}
	store := memStore{}
	g := newTestKms(t, fake, store)

	if err := g.Set(ctx, "vault-root", []byte("s3cr3t")); err != nil {
		t.Fatal(err)
	}

	// Rotate the key, the stored value is still bound to version 1.
	fake.primary = "2"
	got, err := g.Get(ctx, "vault-root")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "s3cr3t" {
		t.Fatalf("got %q, want %q", got, "s3cr3t")
	}
	if string(store["vault-root"][:2]) != "2:" {
		t.Fatalf("value wasn't re-encrypted with the primary version, stored %q", store["vault-root"])
	}

	// Now the old version can be disabled without losing the value.
	fake.disabled["1"] = true
	got, err = g.Get(ctx, "vault-root")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "s3cr3t" {
		t.Fatalf("got %q, want %q", got, "s3cr3t")
	}
}

func TestGetDoesNotReencryptWithPrimary(t *testing.T) {
	ctx := context.Background()
	fake := &fakeKMS{primary: "1", disabled: map[string]bool{}}
	g := newTestKms(t, fake, memStore{})

	if err := g.Set(ctx, "vault-root", []byte("s3cr3t")); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err := g.Get(ctx, "vault-root"); err != nil {
			t.Fatal(err)
		}
	}
	if fake.encrypts != 1 {
		t.Fatalf("got %d encrypt calls, want 1", fake.encrypts)
	}
}

type failingSetStore struct{ memStore }

func (failingSetStore) Set(context.Context, string, []byte) error {
	return fmt.Errorf("read-only store")
}

func TestGetReturnsValueWhenReencryptionFails(t *testing.T) {
	ctx := context.Background()
	fake := &fakeKMS{primary: "2", disabled: map[string]bool{}}
	store := failingSetStore{memStore{"vault-root": []byte("1:s3cr3t")}}
	g := newTestKms(t, fake, store)

	got, err := g.Get(ctx, "vault-root")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "s3cr3t" {
		t.Fatalf("got %q, want %q", got, "s3cr3t")
	}
}
