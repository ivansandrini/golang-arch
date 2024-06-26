package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"log"

	"golang.org/x/crypto/bcrypt"
)

const key = []byte{}

func main() {
	for i := 1; i < 64; i++ {
		key = append(key, byte(i))
	}
	pass := "12345"
	hashedPass, err := hashPassword(pass)
	if err != nil {
		panic(err)
	}

	err = comparePasswords(pass, hashedPass)
	if err != nil {
		log.Fatalln("Not logged in")
	}
	log.Println("Logged in")
}

func hashPassword(password string) ([]byte, error) {
	bs, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("Error while generating bcrypt hash: %v", err)
	}
	return bs, nil
}

func comparePasswords(password string, hashedPass []byte) error {
	err := bcrypt.CompareHashAndPassword(hashedPass, []byte(password))
	if err != nil {
		return fmt.Errorf("Invalid password: %v", err)
	}
	return nil
}

func signMessage(msg []byte) ([]byte, error) {
	h := hmac.New(sha256.New, key)
	_, err := h.Write(msg)
	if err != nil {
		return nil, fmt.Errorf("Error while signing message: %v", err)
	}

	signed := h.Sum(nil)
	return signed, nil
}

func checkSign(msg, sig []byte) (bool, error) {
	newSig, err := signMessage(msg)
	if err != nil {
		return false, fmt.Errorf("Error while checking signature: %v", err)
	}

	same := hmac.Equal(newSig, sig)
	return same, nil
}	
