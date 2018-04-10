package k8s

import (
	"encoding/base64"
	"fmt"
	"os"

	"github.com/banzaicloud/bank-vaults/pkg/kv"
	"k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

type s3Storage struct {
	cl        *kubernetes.Clientset
	namespace string
	secret    string
}

func New(namespace, secret string) (service kv.Service, err error) {
	kubeconfig := os.Getenv("KUBECONFIG")
	var config *rest.Config

	if kubeconfig != "" {
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
	} else {
		config, err = rest.InClusterConfig()
	}

	if err != nil {
		return nil, fmt.Errorf("error creating k8s config: %s", err.Error())
	}

	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("error creating k8s client: %s", err.Error())
	}

	service = &s3Storage{client, namespace, secret}

	return
}

func (g *s3Storage) Set(key string, val []byte) error {
	secret, err := g.cl.Core().Secrets(g.namespace).Get(g.secret, metav1.GetOptions{})

	b64val := make([]byte, base64.StdEncoding.EncodedLen(len(val)))
	base64.StdEncoding.Encode(b64val, val)

	if errors.IsNotFound(err) {
		secret := &v1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: g.namespace,
				Name:      g.secret,
			},
			Data: map[string][]byte{key: b64val},
		}
		secret, err = g.cl.Core().Secrets(g.namespace).Create(secret)
	} else if err == nil {
		secret.Data[key] = b64val
		secret, err = g.cl.Core().Secrets(g.namespace).Update(secret)
		//reflect.DeepEqual()
	} else {
		return fmt.Errorf("error checking if '%s' secret exists: '%s'", g.secret, err.Error())
	}

	if err != nil {
		return fmt.Errorf("error writing secret key '%s' into secret '%s': '%s'", key, g.secret, err.Error())
	}
	return nil
}

func (g *s3Storage) Get(key string) ([]byte, error) {
	secret, err := g.cl.Core().Secrets(g.namespace).Get(g.secret, metav1.GetOptions{})

	if err != nil {
		if errors.IsNotFound(err) {
			return nil, kv.NewNotFoundError("error getting secret for key '%s': %s", key, err.Error())
		}
		return nil, fmt.Errorf("error getting secret for key '%s': %s", key, err.Error())
	}

	val := secret.Data[key]
	if val == nil {
		return nil, kv.NewNotFoundError("key '%s' is not present in secret: %s", key)
	}

	return base64.StdEncoding.DecodeString(string(val))
}

func (g *s3Storage) Test(key string) error {
	// TODO: Implement me properly
	return nil
}
