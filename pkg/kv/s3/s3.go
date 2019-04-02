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

package s3

import (
	"bytes"
	"fmt"
	"io/ioutil"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	awss3 "github.com/aws/aws-sdk-go/service/s3"

	"github.com/banzaicloud/bank-vaults/pkg/kv"
)

type s3Storage struct {
	client *awss3.S3
	bucket string
	prefix string
}

// New creates a new kv.Service backed by AWS S3
func New(region, bucket, prefix string) (kv.Service, error) {
	if region == "" {
		return nil, fmt.Errorf("region must be specified")
	}

	if bucket == "" {
		return nil, fmt.Errorf("bucket must be specified")
	}

	sess := session.Must(session.NewSession(aws.NewConfig().WithRegion(region)))

	cl := awss3.New(sess)

	return &s3Storage{cl, bucket, prefix}, nil
}

func (s3 *s3Storage) Set(key string, val []byte) error {
	n := objectNameWithPrefix(s3.prefix, key)
	input := awss3.PutObjectInput{
		Bucket: aws.String(s3.bucket),
		Key:    aws.String(n),
		Body:   bytes.NewReader(val),
	}

	if _, err := s3.client.PutObject(&input); err != nil {
		return fmt.Errorf("error writing key '%s' to s3 bucket '%s': '%s'", n, s3.bucket, err.Error())
	}

	return nil
}

func (s3 *s3Storage) Get(key string) ([]byte, error) {
	n := objectNameWithPrefix(s3.prefix, key)

	input := awss3.GetObjectInput{
		Bucket: aws.String(s3.bucket),
		Key:    aws.String(n),
	}

	r, err := s3.client.GetObject(&input)

	if err != nil {
		if aerr, ok := err.(awserr.Error); ok && aerr.Code() == awss3.ErrCodeNoSuchKey {
			return nil, kv.NewNotFoundError("error getting object for key '%s': %s", n, aerr.Error())
		}
		return nil, fmt.Errorf("error getting object for key '%s': %s", n, err.Error())
	}

	b, err := ioutil.ReadAll(r.Body)
	defer r.Body.Close()

	if err != nil {
		return nil, fmt.Errorf("error reading object with key '%s': %s", n, err.Error())
	}

	return b, nil
}

func objectNameWithPrefix(prefix, key string) string {
	return fmt.Sprintf("%s%s", prefix, key)
}
