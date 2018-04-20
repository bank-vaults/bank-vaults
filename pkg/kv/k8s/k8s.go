package k8s

import (
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

type k8sStorage struct {
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

	service = &k8sStorage{client, namespace, secret}

	return
}

func (k *k8sStorage) Set(key string, val []byte) error {
	secret, err := k.cl.CoreV1().Secrets(k.namespace).Get(k.secret, metav1.GetOptions{})

	if errors.IsNotFound(err) {
		secret := &v1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: k.namespace,
				Name:      k.secret,
			},
			Data: map[string][]byte{key: val},
		}
		secret, err = k.cl.CoreV1().Secrets(k.namespace).Create(secret)
	} else if err == nil {
		secret.Data[key] = val
		secret, err = k.cl.CoreV1().Secrets(k.namespace).Update(secret)
		//reflect.DeepEqual()
	} else {
		return fmt.Errorf("error checking if '%s' secret exists: '%s'", k.secret, err.Error())
	}

	if err != nil {
		return fmt.Errorf("error writing secret key '%s' into secret '%s': '%s'", key, k.secret, err.Error())
	}
	return nil
}

func (k *k8sStorage) Get(key string) ([]byte, error) {
	secret, err := k.cl.CoreV1().Secrets(k.namespace).Get(k.secret, metav1.GetOptions{})

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

	return val, nil
}

func (k *k8sStorage) Test(key string) error {
	return nil
}
