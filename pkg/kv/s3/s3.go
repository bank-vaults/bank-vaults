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
	"context"
	"fmt"
	"io"

	"emperror.dev/errors"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"

	"github.com/bank-vaults/bank-vaults/pkg/kv"
	"github.com/bank-vaults/bank-vaults/pkg/kv/awskms"
)

type s3Storage struct {
	ctx      context.Context
	client   *s3.Client
	bucket   string
	prefix   string
	sseAlgo  string
	sseKeyID string
}

// New creates a new kv.Service backed by AWS S3
func New(ctx context.Context, region, bucket, prefix, sseAlgo, sseKeyID string) (kv.Service, error) {
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

	config, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil, errors.WrapIf(err, "failed to load AWS config")
	}

	return &s3Storage{ctx, s3.NewFromConfig(config), bucket, prefix, sseAlgo, sseKeyID}, nil
}

func (s3Storage *s3Storage) Set(ctx context.Context, key string, val []byte) error {
	input := s3.PutObjectInput{
		Bucket: aws.String(s3Storage.bucket),
		Key:    aws.String(objectNameWithPrefix(s3Storage.prefix, key)),
		Body:   bytes.NewReader(val),
	}
	if s3Storage.sseAlgo != "" {
		input.ServerSideEncryption = s3types.ServerSideEncryption(s3Storage.sseAlgo)
		if s3Storage.sseAlgo == awskms.SseKMS {
			input.SSEKMSKeyId = &s3Storage.sseKeyID
		}
	}

	if _, err := s3Storage.client.PutObject(ctx, &input); err != nil {
		return errors.Wrapf(err, "error writing key '%s' to s3 bucket '%s'", aws.ToString(input.Key), s3Storage.bucket)
	}

	return nil
}

func (s3Storage *s3Storage) Get(ctx context.Context, key string) ([]byte, error) {
	input := s3.GetObjectInput{
		Bucket: aws.String(s3Storage.bucket),
		Key:    aws.String(objectNameWithPrefix(s3Storage.prefix, key)),
	}

	r, err := s3Storage.client.GetObject(ctx, &input)
	if err != nil {
		const ErrCodeNoSuchKey = "NoSuchKey"
		var noSuchKeyError *s3types.NoSuchKey
		if errors.As(err, &noSuchKeyError) && noSuchKeyError.ErrorCode() == ErrCodeNoSuchKey {
			return nil, kv.NewNotFoundError("error getting object for key '%s': %s", aws.ToString(input.Key), noSuchKeyError.Error())
		}

		return nil, errors.Wrapf(err, "error getting object for key '%s'", aws.ToString(input.Key))
	}
	b, err := io.ReadAll(r.Body)
	defer func() {
		if err := r.Body.Close(); err != nil {
			print(err)
		}
	}()

	if err != nil {
		return nil, errors.Wrapf(err, "error reading object with key '%s'", aws.ToString(input.Key))
	}

	return b, nil
}

func objectNameWithPrefix(prefix, key string) string {
	return fmt.Sprintf("%s%s", prefix, key)
}
