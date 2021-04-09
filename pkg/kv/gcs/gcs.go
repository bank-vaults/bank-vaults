// Copyright © 2018 Banzai Cloud
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

package gcs

import (
	"context"
	"fmt"
	"io/ioutil"

	"cloud.google.com/go/storage"
	"emperror.dev/errors"

	"github.com/banzaicloud/bank-vaults/pkg/kv"
)

type gcsStorage struct {
	cl     *storage.Client
	bucket string
	prefix string
}

// New creates a new kv.Service backed by Google GCS
func New(bucket, prefix string) (kv.Service, error) {
	cl, err := storage.NewClient(context.Background())
	if err != nil {
		return nil, errors.Wrap(err, "error creating gcs client")
	}

	return &gcsStorage{cl, bucket, prefix}, nil
}

func (g *gcsStorage) Set(key string, val []byte) error {
	ctx := context.Background()
	n := objectNameWithPrefix(g.prefix, key)
	w := g.cl.Bucket(g.bucket).Object(n).NewWriter(ctx)
	defer w.Close()

	if _, err := w.Write(val); err != nil {
		return errors.Wrapf(err, "error writing key '%s' to gcs bucket '%s'", n, g.bucket)
	}

	return nil
}

func (g *gcsStorage) Get(key string) ([]byte, error) {
	ctx := context.Background()
	n := objectNameWithPrefix(g.prefix, key)

	r, err := g.cl.Bucket(g.bucket).Object(n).NewReader(ctx)
	if err != nil {
		if errors.Is(err, storage.ErrObjectNotExist) {
			return nil, kv.NewNotFoundError("error getting object for key '%s': %s", n, err.Error())
		}

		return nil, errors.Wrapf(err, "error getting object for key '%s'", n)
	}

	defer r.Close()

	b, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, errors.Wrapf(err, "error reading object with key '%s'", n)
	}

	return b, nil
}

func objectNameWithPrefix(prefix, key string) string {
	return fmt.Sprintf("%s%s", prefix, key)
}
