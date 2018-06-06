package alibabaoss

import (
	"bytes"
	"fmt"
	"io/ioutil"

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
	name := objectNameWithPrefix(o.prefix, key)

	bucket, err := o.client.Bucket(o.bucket)
	if err != nil {
		return err
	}

	if err := bucket.PutObject(name, bytes.NewReader(val)); err != nil {
		return fmt.Errorf("error writing key '%s' to OSS bucket '%s': '%s'", name, o.bucket, err.Error())
	}

	return nil
}

func (o *ossStorage) Get(key string) ([]byte, error) {
	n := objectNameWithPrefix(o.prefix, key)

	bucket, err := o.client.Bucket(o.bucket)
	if err != nil {
		return nil, err
	}

	body, err := bucket.GetObject(n)

	if err != nil {
		switch err.(type) {
		case oss.ServiceError:
			if err.(oss.ServiceError).StatusCode == 404 && err.(oss.ServiceError).Code == "NoSuchKey" {
				return nil, kv.NewNotFoundError("error getting object for key '%s': %s", n, err.Error())
			}
		}
		return nil, fmt.Errorf("error getting object for key '%s': %s", n, err.Error())
	}

	b, err := ioutil.ReadAll(body)
	defer body.Close()

	if err != nil {
		return nil, fmt.Errorf("error reading object with key '%s': %s", n, err.Error())
	}

	return b, nil
}

func objectNameWithPrefix(prefix, key string) string {
	return fmt.Sprintf("%s%s", prefix, key)
}

func (o *ossStorage) Test(key string) error {
	// TODO: Implement me properly
	return nil
}
