package main

import (
	"log"
	"os"
	"time"

	"github.com/banzaicloud/bank-vaults/database"
	"github.com/banzaicloud/bank-vaults/vault"
)

func vaultExample() {
	client, err := vault.NewClient("default")
	if err != nil {
		log.Fatal(err)
	}

	log.Println("Created Vault client.")

	secret, err := client.Vault().Logical().List("secret/accesstokens")
	if err != nil {
		log.Fatal(err)
	}
	if secret != nil {
		for _, v := range secret.Data {
			log.Printf("-> %+v", v)
			for _, v := range v.([]interface{}) {
				log.Printf("-> %+v", v)
			}
		}

	} else {
		log.Println("Found nothing")
		time.Sleep(time.Minute)
		client.Close()
		time.Sleep(time.Hour)
	}
}

func gormExample() {
	secretSource, err := database.DynamicSecretDataSource("mysql", "my-role@tcp(127.0.0.1:3306)/sparky?charset=utf8&parseTime=True&loc=Local")
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("use this with GORM:\ndb, err := gorm.Open(\"mysql\", \"%s\")", secretSource)
}

func main() {
	os.Setenv("VAULT_ADDR", "http://vault-vault:8200")
	vaultExample()
	gormExample()
}
