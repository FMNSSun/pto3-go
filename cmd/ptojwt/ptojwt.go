package main

import (
	"flag"
	"github.com/dgrijalva/jwt-go"
	"log"
	"bufio"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"time"
)

func main() {
	action := flag.String("action", "gen", "gen[erate] or val[idate]")
	sub := flag.String("sub", "", "Subject (sub claim for JWT token)")
	secret := flag.String("secret", "", "Secret (for HMAC)")
	token := flag.String("token", "", "JWT Token")
	perms := flag.String("permissions", "", "Permissions (only valid for generate, semi-colon separated)")
	dur := flag.Int("duration", 360, "Duration in days (only valid for generate)")

	flag.Parse()

	if *sub == "" {
		if *action != "val" && *action != "validate" {
			log.Fatal("Empty `sub`!")
		}
	}

	reader := bufio.NewReader(os.Stdin)

	secretBytes := []byte{}

	if *secret == "" {
		line := readln(reader, "Enter Secret (b64): ")
	
		secretDecoded, err := base64.StdEncoding.DecodeString(line)

		if err != nil {
			log.Fatal("Decode (base64) failed!")
		}

		secretBytes = secretDecoded
	}

	if *token == "" {
		if *action != "gen" && *action != "generate" {

			line := readln(reader, "Enter Token: ")

			*token = line
		}
	}		

	

	switch *action {
	case "gen", "generate":
		generate(*dur, *sub, *perms, secretBytes)
	case "val", "validate":
		validate(*token, secretBytes)
	}
}

func readln(reader *bufio.Reader, msg string, args... interface{}) string {
	fmt.Printf(msg, args...)	

	line, err := reader.ReadString('\n')

	if err != nil {
		log.Fatalf("Reading secret failed: %v", err.Error())
	}

	return strings.Trim(line, "\r\t\n ")
}

func generate(dur int, sub, permStr string, secret []byte) {
	mapClaims := jwt.MapClaims{}
	
	perms := strings.Split(permStr, ";")

	for _, v := range perms {
		if v == "" {
			log.Fatal("Empty permission!")
		}

		mapClaims[v] = true
	}

	mapClaims["sub"] = sub
	mapClaims["iat"] = time.Now().Unix()
	mapClaims["nbf"] = time.Now().Unix()
	mapClaims["iss"] = "pto"

	day := time.Hour * 24

	mapClaims["exp"] = time.Now().Add(time.Duration(dur) * day).Unix()

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, mapClaims)

	signedToken, err := token.SignedString(secret)

	if err != nil {
		log.Fatalf("Error generating Token: %v", err.Error())
	}

	fmt.Printf("Token: %s\n", signedToken)
}

func validate(str string, secret []byte) {
	token, err := jwt.Parse(str, func(token *jwt.Token) (interface{}, error) {
		 // only accept HMAC
		 if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			  return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		 }

		 return secret, nil
	})

	if err != nil {
		log.Fatalf("Failed to parse token: %v", err.Error())
	}

	if !token.Valid {
		log.Fatal("Token is not valid!")
	} else {
		log.Println("Token is valid!")
	}

	claims, ok := token.Claims.(jwt.MapClaims)

	if !ok {
		log.Fatal("Invalid claims!")
	}

	validErr := claims.Valid()
		
	if validErr != nil {
		log.Fatalf("validation error: %v", validErr.Error())
	}

	log.Println(token.Claims)
}
