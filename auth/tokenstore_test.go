package auth

import (
	"os"
	"testing"
	"time"
)

func TestVaultTokenStore(t *testing.T) {
	os.Setenv("VAULT_ADDR", "http://localhost:8200")

	startTime := time.Now()
	ts := NewVaultTokenStore("")
	userID := "12"
	token := NewToken("id12", "nandi's token")

	err := ts.Store(userID, token)
	if err != nil {
		t.Fatal(err.Error())
	}

	err = ts.Store(userID, token)
	if err == nil {
		t.Fatal("Second Store for the same ids shouldn't work")
	}

	tokens, err := ts.List(userID)
	if err != nil {
		t.Fatal(err.Error())
	}

	if len(tokens) != 1 {
		t.Fatal("There should be only one Token listed, but there are", len(tokens))
	}

	listedToken := tokens[0]

	if listedToken.ID != token.ID || listedToken.Name != token.Name || listedToken.CreatedAt.Before(startTime) {
		t.Fatalf("The listed token doesn't match: %#v", listedToken)
	}

	err = ts.Revoke(userID, token.ID)
	if err != nil {
		t.Fatal(err.Error())
	}
}
