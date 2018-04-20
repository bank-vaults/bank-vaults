package main

import (
	"fmt"

	"github.com/banzaicloud/bank-vaults/database"
	"github.com/banzaicloud/bank-vaults/vault"
)

func vaultExample() {
	client, err := vault.NewClient("my-role")
	if err != nil {
		panic(err)
	}

	secret, err := client.Vault().Logical().List("secret/accesstokens")
	if err != nil {
		panic(err)
	}
	if secret != nil {
		for _, v := range secret.Data {
			fmt.Printf("-> %+v", v)
			for _, v := range v.([]interface{}) {
				fmt.Printf("-> %+v", v)
			}
		}

	} else {
		println("found nothing")
	}
}

func gormExample() {
	secretSource, err := database.DynamicSecretDataSource("mysql", "my-role@tcp(127.0.0.1:3306)/sparky?charset=utf8&parseTime=True&loc=Local")
	if err != nil {
		panic(err)
	}
	fmt.Printf("use this with GORM:\ndb, err := gorm.Open(\"mysql\", \"%s\")", secretSource)
}

func main() {
	vaultExample()
	gormExample()
}
