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

	"emperror.dev/errors"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	awss3 "github.com/aws/aws-sdk-go/service/s3"

	"github.com/banzaicloud/bank-vaults/pkg/kv"
	"github.com/banzaicloud/bank-vaults/pkg/kv/awskms"
)

type s3Storage struct {
	client   *awss3.S3
	bucket   string
	prefix   string
	sseAlgo  string
	sseKeyID string
}

// New creates a new kv.Service backed by AWS S3
func New(region, bucket, prefix, sseAlgo, sseKeyID string) (kv.Service, error) {
	if region == "" {
		return nil, errors.New("region must be specified")
	}

	if bucket == "" {
		return nil, errors.New("bucket must be specified")
	}

	if sseAlgo == awskms.SseAES256 && sseKeyID != "" {
		return nil, errors.New("can't set a keyID when using AES256 as the encryption algorithm")
	}

	if sseAlgo == awskms.SseKMS && sseKeyID == "" {
		return nil, errors.New("you need to provide a CMK KeyID when using aws:kms for SSE")
	}

	sess := session.Must(session.NewSession(aws.NewConfig().WithRegion(region)))

	cl := awss3.New(sess)

	return &s3Storage{cl, bucket, prefix, sseAlgo, sseKeyID}, nil
}

func (s3 *s3Storage) Set(key string, val []byte) error {
	n := objectNameWithPrefix(s3.prefix, key)
	input := awss3.PutObjectInput{
		Bucket: aws.String(s3.bucket),
		Key:    aws.String(n),
		Body:   bytes.NewReader(val),
	}
	if s3.sseAlgo != "" {
		input.ServerSideEncryption = &s3.sseAlgo
		if s3.sseAlgo == awskms.SseKMS {
			input.SSEKMSKeyId = &s3.sseKeyID
		}
	}

	if _, err := s3.client.PutObject(&input); err != nil {
		return errors.Wrapf(err, "error writing key '%s' to s3 bucket '%s'", n, s3.bucket)
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
		var aerr awserr.Error
		if errors.As(err, &aerr) && aerr.Code() == awss3.ErrCodeNoSuchKey {
			return nil, kv.NewNotFoundError("error getting object for key '%s': %s", n, aerr.Error())
		}

		return nil, errors.Wrapf(err, "error getting object for key '%s'", n)
	}

	b, err := ioutil.ReadAll(r.Body)
	defer r.Body.Close()

	if err != nil {
		return nil, errors.Wrapf(err, "error reading object with key '%s'", n)
	}

	return b, nil
}

func objectNameWithPrefix(prefix, key string) string {
	return fmt.Sprintf("%s%s", prefix, key)
}
