package tls

import (
	"bytes"
	"text/template"

	"github.com/Masterminds/sprig"
	"k8s.io/api/core/v1"

	"github.com/ghodss/yaml"
)

const certsSecretTemplate = `
{{- $ca := genCA "vault-ca" 365 -}}
{{- $cert := genSignedCert .cn (list "127.0.0.1") (list .cn .externalDNS) 365 $ca -}}
apiVersion: v1
kind: Secret
data:
  ca.crt: {{ $ca.Cert | b64enc }}
  ca.key: {{ $ca.Key | b64enc }}
  server.crt: {{ $cert.Cert | b64enc }}
  server.key: {{ $cert.Key | b64enc }}
`

// GenerateSecretForCerts is fenerating TLS certificates with sprig (just like in Helm), shamelessly.
func GenerateSecretForCerts(name string, namespace string) (*v1.Secret, error) {
	secretTemplate, err := template.New("").Funcs(sprig.TxtFuncMap()).Parse(certsSecretTemplate)
	if err != nil {
		return nil, err
	}

	buffer := bytes.NewBuffer(nil)

	err = secretTemplate.Execute(buffer, map[string]string{"cn": name, "externalDNS": name + "." + namespace})

	if err != nil {
		return nil, err
	}

	var secret v1.Secret

	err = yaml.Unmarshal(buffer.Bytes(), &secret)
	if err != nil {
		return nil, err
	}

	secret.Name = name + "-tls"
	secret.Namespace = namespace

	return &secret, nil
}
