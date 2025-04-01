// Copyright © 2024 Bank-Vaults Maintainers
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

package oci

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"

	"emperror.dev/errors"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"

	"github.com/bank-vaults/bank-vaults/pkg/kv"
)

// ociStorage is an implementation of the kv.Service interface, that store
// data using Oracle Object Storage.
type ociStorage struct {
	client    *objectstorage.ObjectStorageClient
	namespace string
	bucket    string
	prefix    string
}

// New creates a new kv.Service backed by Oracle OCI Object Storage
func New(namespace, bucket, prefix string) (kv.Service, error) {
	client, err := objectstorage.NewObjectStorageClientWithConfigurationProvider(common.DefaultConfigProvider())
	if err != nil {
		slog.Error(fmt.Sprintf("error creating oracle object storage client: %s", err.Error()))
	}

	return &ociStorage{client: &client, namespace: namespace, bucket: bucket, prefix: prefix}, nil
}

func (oci *ociStorage) Get(key string) ([]byte, error) {
	n := objectNameWithPrefix(oci.prefix, key)
	request := objectstorage.GetObjectRequest{
		NamespaceName: &oci.namespace,
		BucketName:    &oci.bucket,
		ObjectName:    &n,
	}
	response, err := oci.client.GetObject(context.Background(), request)
	if err != nil {
		if failure, ok := common.IsServiceError(err); ok {
			switch os := failure.GetCode(); os {
			case "ObjectNotFound":
				return nil, kv.NewNotFoundError("error getting object for key '%s': %s", *request.ObjectName, err.Error())

			default:
				return nil, errors.Wrapf(err, "error getting object for key '%s'", *request.ObjectName)
			}
		}
		return nil, errors.Wrapf(err, "error getting object for key '%s'", *request.ObjectName)
	}

	r := response.Content
	defer func() {
		if err := r.Close(); err != nil {
			slog.Error(fmt.Sprintf("error closing response body: %s", err.Error()))
		}
	}()

	b, err := io.ReadAll(r)
	if err != nil {
		return nil, errors.Wrapf(err, "error reading object with key '%s'", n)
	}

	return b, nil
}

func (oci *ociStorage) Set(key string, val []byte) error {
	n := objectNameWithPrefix(oci.prefix, key)
	request := objectstorage.PutObjectRequest{
		NamespaceName: &oci.namespace,
		BucketName:    &oci.bucket,
		ObjectName:    &n,
		PutObjectBody: io.NopCloser(bytes.NewReader(val)),
	}
	_, err := oci.client.PutObject(context.Background(), request)
	if err != nil {
		return errors.Wrapf(err, "error setting object for key '%s'", *request.ObjectName)
	}

	return nil
}

func objectNameWithPrefix(prefix, key string) string {
	return fmt.Sprintf("%s/%s", prefix, key)
}
