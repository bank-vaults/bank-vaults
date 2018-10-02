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

package auth

import (
	"context"
	"encoding/base32"
	"fmt"
	"log"
	"net/http"

	"github.com/dgrijalva/jwt-go"
	jwtRequest "github.com/dgrijalva/jwt-go/request"
	"github.com/gin-gonic/gin"
	"github.com/qor/qor/utils"
)

// CurrentUser context key to get current user from Request
const CurrentUser utils.ContextKey = "current_user"

// TokenType represents one of the possible token Types
type TokenType string

// ClaimConverter converts claims to another domain object for saving into Context
type ClaimConverter func(*ScopedClaims) interface{}

// ScopedClaims struct to store the scoped claim related things
type ScopedClaims struct {
	jwt.StandardClaims
	Scope string `json:"scope,omitempty"`
	// Drone fields
	Type TokenType `json:"type,omitempty"`
	Text string    `json:"text,omitempty"`
}

// JWTAuth returns a new JWT authentication handler
func JWTAuth(tokenStore TokenStore, signingKey string, claimConverter ClaimConverter) gin.HandlerFunc {

	signingKeyBase32 := []byte(base32.StdEncoding.EncodeToString([]byte(signingKey)))

	hmacKeyFunc := func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Method.Alg())
		}
		return signingKeyBase32, nil
	}

	return func(c *gin.Context) {

		var claims ScopedClaims
		accessToken, err := jwtRequest.ParseFromRequest(c.Request, jwtRequest.OAuth2Extractor, hmacKeyFunc, jwtRequest.WithClaims(&claims))

		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized,
				gin.H{
					"message": "Invalid token",
					"error":   err.Error(),
				})
			return
		}

		isTokenWhitelisted, err := isTokenWhitelisted(tokenStore, &claims)

		if err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError,
				gin.H{
					"message": "Failed to validate user token",
					"error":   err.Error(),
				})
			log.Println("Failed to lookup user token:", err)
			return
		}

		if !accessToken.Valid || !isTokenWhitelisted {
			c.AbortWithStatusJSON(http.StatusUnauthorized,
				gin.H{
					"message": "Invalid token",
				})
			return
		}

		saveUserIntoContext(c, &claims, claimConverter)
	}
}

func isTokenWhitelisted(tokenStore TokenStore, claims *ScopedClaims) (bool, error) {
	userID := claims.Subject
	tokenID := claims.Id
	token, err := tokenStore.Lookup(userID, tokenID)
	return token != nil, err
}

func saveUserIntoContext(c *gin.Context, claims *ScopedClaims, claimConverter func(*ScopedClaims) interface{}) {
	var toSave interface{}
	toSave = claims
	if claimConverter != nil {
		toSave = claimConverter(claims)
	}
	newContext := context.WithValue(c.Request.Context(), CurrentUser, toSave)
	c.Request = c.Request.WithContext(newContext)
}

// GetCurrentUser tries to get the saved user from Context
func GetCurrentUser(c *gin.Context) interface{} {
	return c.Request.Context().Value(CurrentUser)
}
