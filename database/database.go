package database

import (
	"fmt"
	"strings"

	"github.com/banzaicloud/bank-vaults/vault"
	vaultapi "github.com/hashicorp/vault/api"
	"github.com/pkg/errors"
)

// DynamicSecretDataSource creates a SQL data source but instead of passing username:password
// in the connection source, one just has to pass in a Vault role name:
//     ds, err := DynamicSecretDataSource("mysql", "my-role@localhost:3306/dbname?parseTime=True")
//
// MySQL (github.com/go-sql-driver/mysql) and PostgreSQL URI is supported.
//
// The underlying Vault client will make sure that the credential is renewed when it
// is close to the time of expiry.
func DynamicSecretDataSource(dialect string, source string) (dynamicSecretDataSource string, err error) {

	postgresql := false
	if strings.HasPrefix(source, "postgresql://") {
		source = strings.TrimPrefix(source, "postgresql://")
		postgresql = true
	}

	sourceParts := strings.Split(source, "@")
	if len(sourceParts) != 2 {
		err = errors.New("invalid database source")
		return "", err
	}

	vaultRole := sourceParts[0]
	vaultCredsEndpoint := "database/creds/" + vaultRole

	vaultClient, err := vault.NewClient(vaultRole)

	if err != nil {
		err = errors.Wrap(err, "failed to establish vault connection")
		return "", err
	}

	secret, err := vaultClient.Vault().Logical().Read(vaultCredsEndpoint)
	if err != nil {
		err = errors.Wrap(err, "failed to read db credentials")
		return "", err
	}

	if secret == nil {
		err = errors.New("failed to find '" + vaultCredsEndpoint + "' secret in vault")
		return "", err
	}

	secretRenewer, err := vaultClient.Vault().NewRenewer(&vaultapi.RenewerInput{Secret: secret})
	go secretRenewer.Renew()

	username := secret.Data["username"].(string)
	password := secret.Data["password"].(string)

	dynamicSecretDataSource = fmt.Sprintf("%s:%s@%s", username, password, sourceParts[1])
	if postgresql {
		dynamicSecretDataSource = "postgresql://" + source
	}

	return dynamicSecretDataSource, nil
}
