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

package database

import database "github.com/bank-vaults/vault-sdk/db"

// DynamicSecretDataSource creates a SQL data source but instead of passing username:password
// in the connection source, one just has to pass in a Vault role name:
//
//	ds, err := DynamicSecretDataSource("mysql", "my-role@localhost:3306/dbname?parseTime=True")
//
// MySQL (github.com/go-sql-driver/mysql) and PostgreSQL URI is supported.
//
// The underlying Vault client will make sure that the credential is renewed when it
// is close to the time of expiry.
//
// Deprecated: use [database.DynamicSecretDataSource] instead.
func DynamicSecretDataSource(dialect string, source string) (dynamicSecretDataSource string, err error) {
	return database.DynamicSecretDataSource(dialect, source)
}
