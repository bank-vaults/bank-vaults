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
	cl     *awss3.S3
	bucket string
	prefix string
}

func New(bucket, prefix string) (kv.Service, error) {
	sess := session.New()
	cl := awss3.New(sess)

	return &s3Storage{cl, bucket, prefix}, nil
}

func (g *s3Storage) Set(key string, val []byte) error {
	n := objectNameWithPrefix(g.prefix, key)
	input := awss3.PutObjectInput{
		Bucket: aws.String(g.bucket),
		Key:    aws.String(n),
		Body:   bytes.NewReader(val),
	}

	if _, err := g.cl.PutObject(&input); err != nil {
		return fmt.Errorf("error writing key '%s' to s3 bucket '%s': '%s'", n, g.bucket, err.Error())
	}

	return nil
}

func (g *s3Storage) Get(key string) ([]byte, error) {
	n := objectNameWithPrefix(g.prefix, key)

	input := awss3.GetObjectInput{
		Bucket: aws.String(g.bucket),
		Key:    aws.String(n),
	}

	r, err := g.cl.GetObject(&input)

	if err != nil {
		if aerr, ok := err.(awserr.Error); ok && aerr.Code() == awss3.ErrCodeNoSuchKey {
			return nil, kv.NewNotFoundError("error getting object for key '%s': %s", n, aerr.Error())
		}
		return nil, fmt.Errorf("error getting object for key '%s': %s", n, err.Error())
	}

	b, err := ioutil.ReadAll(r.Body)

	if err != nil {
		return nil, fmt.Errorf("error reading object with key '%s': %s", n, err.Error())
	}

	return b, nil
}

func objectNameWithPrefix(prefix, key string) string {
	return fmt.Sprintf("%s%s", prefix, key)
}

func (g *s3Storage) Test(key string) error {
	// TODO: Implement me properly
	return nil
}
