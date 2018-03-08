package gorm

import (
	"fmt"
	"os"
	"strings"

	"github.com/banzaicloud/vault-dogsbody/vault"
	vaultapi "github.com/hashicorp/vault/api"
	gormapi "github.com/jinzhu/gorm"
	"github.com/pkg/errors"
)

// Open opens a gorm based SQL connection but instead of passing username:password in
// the connection source, one just has to pass in a Vault role name:
//     db, err := gorm.Open("mysql", "my-role@localhost:3306/dbname?parseTime=True")
//
// The underlying Vault client will make sure that the credential is renewed when it
// is close to the time of expiry.
func Open(dialect string, source string) (db *gormapi.DB, err error) {

	sourceParts := strings.Split(source, "@")
	if len(sourceParts) != 2 {
		err = errors.New("invalid database source")
		return nil, err
	}

	vaultRole := sourceParts[0]
	vaultCredsEndpoint := "database/creds/" + vaultRole

	vaultClient, err := vault.NewClient(os.Getenv("HOME"), vaultRole)

	if err != nil {
		err = errors.Wrap(err, "failed to establish vault connection")
		return nil, err
	}

	secret, err := vaultClient.Vault().Logical().Read(vaultCredsEndpoint)
	if err != nil {
		err = errors.Wrap(err, "failed to read db credentials")
		return nil, err
	}

	if secret == nil {
		err = errors.New("failed to find '" + vaultCredsEndpoint + "' secret in vault")
		return nil, err
	}

	secretRenewer, err := vaultClient.Vault().NewRenewer(&vaultapi.RenewerInput{Secret: secret})
	go secretRenewer.Renew()

	username := secret.Data["username"].(string)
	password := secret.Data["password"].(string)

	source = fmt.Sprintf("%s:%s@%s", username, password, sourceParts[1])

	db, err = gormapi.Open(dialect, source)

	if err != nil {
		vaultClient.Close()
		err = errors.Wrap(err, "failed to open db connection")
		return nil, err
	}

	db.DB().Close()

	return db, err
}
