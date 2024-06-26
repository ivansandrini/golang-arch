package main

import (
	"fmt"
	"log"
	"golang.org/x/crypto/bcrypt"
)

func main() {
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