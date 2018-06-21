// Path Transparency Observatory JWT-based authorization

package papi

import (
	"fmt"
	"net/http"
	"strings"
	"encoding/base64"

	"github.com/dgrijalva/jwt-go"
)


type JWTAuthorizer struct {
	// The secret (base64 encoded)
	Key []byte
}

func (azr *JWTAuthorizer) Configure(config map[string]interface{}) error {
	keyEntry := config["key"]

	if keyEntry == nil {
		keyEntry = config["secret"]
	}

	key, ok := keyEntry.(string)

	if !ok {
		return fmt.Errorf("Invalid config!")
	}

	keyBytes, err := base64.StdEncoding.DecodeString(key)

	if err != nil {
		return err
	}

	azr.Key = keyBytes

	return nil
}


func (azr *JWTAuthorizer) IsAuthorized(w http.ResponseWriter, r *http.Request, permission string) bool {
	// look for an authorization header
	authhdr := r.Header.Get("Authorization")

	if authhdr != "" {

		authfield := strings.Fields(authhdr)

		if len(authfield) < 2 {
			http.Error(w, fmt.Sprintf("malformed Authorization header: %v", authhdr), http.StatusBadRequest)
			return false
		} else if authfield[0] == "Bearer" {
			token, err := jwt.Parse(authfield[1], func(token *jwt.Token) (interface{}, error) {
				 // only accept HMAC
				 if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					  return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
				 }

				 return azr.Key, nil
			})

			
			if err != nil {
				http.Error(w, fmt.Sprintf("malformed Authorization header: %v", authhdr), http.StatusBadRequest)
				return false
			}

			if !token.Valid {
				http.Error(w, fmt.Sprintf("token is not valid!", authhdr), http.StatusBadRequest)
				return false
			}

			claims, ok := token.Claims.(jwt.MapClaims)

			if !ok {
				http.Error(w, fmt.Sprintf("invalid claims!", authhdr), http.StatusBadRequest)
				return false
			}

			permEntry := claims[permission]

			if permEntry == nil {
				http.Error(w, fmt.Sprintf("not authorized for %v", authhdr), http.StatusForbidden)
				return false
			}

			perm, ok := permEntry.(bool)

			if !perm || !ok {
				http.Error(w, fmt.Sprintf("not authorized for %v", authhdr), http.StatusForbidden)
				return false
			}

			return true
		} else {
			http.Error(w, fmt.Sprintf("unsupported authorization type %s", authfield[0]), http.StatusBadRequest)
			return false
		}
	} 

	http.Error(w, fmt.Sprintf("malformed Authorization header: %v", authhdr), http.StatusBadRequest)
	return false
}
