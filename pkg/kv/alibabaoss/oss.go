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

package alibabaoss

import (
	"bytes"
	"fmt"
	"io/ioutil"

	"emperror.dev/errors"
	"github.com/aliyun/aliyun-oss-go-sdk/oss"

	"github.com/banzaicloud/bank-vaults/pkg/kv"
)

type ossStorage struct {
	client *oss.Client
	bucket string
	prefix string
}

// New creates a new kv.Service backed by AWS S3
func New(endpoint, accessKeyID, accessKeySecret, bucket, prefix string) (kv.Service, error) {
	client, err := oss.New(endpoint, accessKeyID, accessKeySecret)
	if err != nil {
		return nil, err
	}

	return &ossStorage{client, bucket, prefix}, nil
}

func (o *ossStorage) Set(key string, val []byte) error {
	objectKey := objectNameWithPrefix(o.prefix, key)

	bucket, err := o.client.Bucket(o.bucket)
	if err != nil {
		return err
	}

	if err := bucket.PutObject(objectKey, bytes.NewReader(val)); err != nil {
		return errors.Wrapf(err, "error writing key '%s' to OSS bucket '%s'", objectKey, o.bucket)
	}

	return nil
}

func (o *ossStorage) Get(key string) ([]byte, error) {
	objectKey := objectNameWithPrefix(o.prefix, key)

	bucket, err := o.client.Bucket(o.bucket)
	if err != nil {
		return nil, err
	}

	body, err := bucket.GetObject(objectKey)
	if err != nil {
		var serviceErr oss.ServiceError
		if errors.As(err, &serviceErr) && serviceErr.StatusCode == 404 && serviceErr.Code == "NoSuchKey" {
			return nil, kv.NewNotFoundError("error getting object for key '%s': %s", objectKey, err.Error())
		}

		return nil, errors.Wrapf(err, "error getting object for key '%s'", objectKey)
	}

	b, err := ioutil.ReadAll(body)
	defer body.Close()

	if err != nil {
		return nil, errors.Wrapf(err, "error reading object with key '%s'", objectKey)
	}

	return b, nil
}

func objectNameWithPrefix(prefix, key string) string {
	return fmt.Sprintf("%s%s", prefix, key)
}
