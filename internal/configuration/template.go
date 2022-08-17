// Copyright © 2019 Banzai Cloud
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

package configuration

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net/url"
	"os"
	"strings"
	"text/template"

	cloudkms "cloud.google.com/go/kms/apiv1"
	"emperror.dev/errors"
	"github.com/Masterminds/sprig/v3"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
	"gocloud.dev/blob"

	// These drivers are supported currently by the blob function
	_ "gocloud.dev/blob/azureblob"
	_ "gocloud.dev/blob/fileblob"
	_ "gocloud.dev/blob/gcsblob"
	_ "gocloud.dev/blob/s3blob"
	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"
)

const (
	// DefaultLeftDelimiter is the default left-hand delimeter that will be used for the templates
	DefaultLeftDelimiter = "${"
	// DefaultRightDelimiter is the default right-hand delimeter that will be used for the templates
	DefaultRightDelimiter = "}"
)

const templateName = "config"

// Templater is used to hold the delimeters used to configure the template engine
type Templater struct {
	leftDelimiter  string
	rightDelimiter string
}

// NewTemplater initializes a new templater object
func NewTemplater(leftDelimiter, rightDelimiter string) Templater {
	return Templater{
		leftDelimiter:  leftDelimiter,
		rightDelimiter: rightDelimiter,
	}
}

// EnvTemplate interpolates environment variables in a configuration text
func (t Templater) EnvTemplate(templateText string) (*bytes.Buffer, error) {
	var env struct {
		Env map[string]string
	}
	env.Env = make(map[string]string, len(os.Environ()))

	for _, v := range os.Environ() {
		split := strings.SplitN(v, "=", 2)
		env.Env[split[0]] = split[1]
	}

	return t.Template(templateText, env)
}

// Template interpolates a data structure in a template
func (t Templater) Template(templateText string, data interface{}) (*bytes.Buffer, error) {
	configTemplate, err := template.New(templateName).
		Funcs(sprig.TxtFuncMap()).
		Funcs(customFuncs()).
		Delims(t.leftDelimiter, t.rightDelimiter).
		Parse(templateText)
	if err != nil {
		return nil, errors.WrapIf(err, "error parsing template")
	}

	buffer := bytes.NewBuffer(nil)

	err = configTemplate.ExecuteTemplate(buffer, templateName, data)
	if err != nil {
		return nil, errors.WrapIf(err, "error executing template")
	}

	return buffer, nil
}

func customFuncs() template.FuncMap {
	return funcMap()
}

func funcMap() map[string]interface{} {
	return map[string]interface{}{
		"awskms":   awsKmsDecrypt,
		"file":     fileContent,
		"gcpkms":   gcpKmsDecrypt,
		"blob":     blobRead,
		"accessor": accessorPlaceholder,
	}
}

func accessorPlaceholder(path string) (string, error) {
	return fmt.Sprintf("__accessor__%s", strings.TrimRight(path, "/")), nil
}

// blob reads a content from a blob url
// examples:
// - file:///path/to/dir/file
// - s3://my-bucket/object?region=us-west-1
// - gs://my-bucket/object
// - azblob://my-container/blob
func blobRead(urlstr string) (string, error) {
	ctx := context.Background()

	u, err := url.Parse(urlstr)
	if err != nil {
		return "", errors.Wrapf(err, "failed to parse blob url: %s", urlstr)
	}

	i := strings.LastIndex(u.Path, "/")
	key := u.Path[i+1:]
	u.Path = u.Path[:i]

	bucket, err := blob.OpenBucket(ctx, u.String())
	if err != nil {
		return "", errors.Wrapf(err, "failed to open blob bucket: %s", u.String())
	}
	defer bucket.Close()

	data, err := bucket.ReadAll(ctx, key)
	if err != nil {
		return "", errors.Wrapf(err, "failed to read blob bucket key: %s", key)
	}

	return string(data), nil
}

func awsKmsDecrypt(encodedString string, encryptionContext ...string) (string, error) {
	awsSession, err := session.NewSession()
	if err != nil {
		return "", errors.Wrap(err, "failed to create AWS session")
	}
	svc := kms.New(awsSession)
	decoded, err := base64.StdEncoding.DecodeString(encodedString)
	if err != nil {
		return "", errors.Wrap(err, "failed to decode base64 string")
	}
	result, err := svc.Decrypt(&kms.DecryptInput{CiphertextBlob: decoded, EncryptionContext: convertContextMap(encryptionContext)})
	if err != nil {
		return "", errors.Wrap(err, "failed to decrypt ciphertext")
	}

	return string(result.Plaintext), nil
}

func gcpKmsDecrypt(encodedString string, projectID string, location string, keyRing string, key string) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(encodedString)
	if err != nil {
		return "", errors.Wrapf(err, "failed to base64 decode ciphertext")
	}
	ctx := context.Background()
	client, err := cloudkms.NewKeyManagementClient(ctx)
	if err != nil {
		return "", errors.Wrapf(err, "failed to construct KMS client")
	}
	req := &kmspb.DecryptRequest{
		Name:       fmt.Sprintf("projects/%s/locations/%s/keyRings/%s/cryptoKeys/%s", projectID, location, keyRing, key),
		Ciphertext: decoded,
	}
	resp, err := client.Decrypt(ctx, req)
	if err != nil {
		panic(fmt.Sprintf("Decrypt: %v", err))
	}

	return string(resp.Plaintext), nil
}

func fileContent(path string) (string, error) {
	r, err := ioutil.ReadFile(path)
	if err != nil {
		return "", err
	}

	return strings.ReplaceAll(string(r), "\n", "\\n"), nil
}

func convertContextMap(encryptionContext []string) map[string]*string {
	m := make(map[string]*string)
	for _, p := range encryptionContext {
		v := strings.Split(p, "=")
		m[v[0]] = &v[1]
	}

	return m
}

// IsGoTemplate returns true if s is probably a Go Template
func (t Templater) IsGoTemplate(templateText string) bool {
	return strings.Contains(templateText, t.leftDelimiter) && strings.Contains(templateText, t.rightDelimiter)
}
