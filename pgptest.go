package main

import (
	"bytes"
	"encoding/base64"
	"flag"
	"io/ioutil"
	"log"
	"os"

	"golang.org/x/crypto/openpgp"
)

var prefix string
var passphrase string
var secretKeyring string
var publicKeyring string
var mySecretString string

func encTest(secretString string) (string, error) {

	log.Println("Secret to hide:", secretString)
	log.Println("Public Keyring:", publicKeyring)

	// Read in public key
	keyringFileBuffer, _ := os.Open(publicKeyring)
	defer keyringFileBuffer.Close()
	entityList, err := openpgp.ReadKeyRing(keyringFileBuffer)
	if err != nil {
		return "", err
	}

	// encrypt string
	buf := new(bytes.Buffer)
	w, err := openpgp.Encrypt(buf, entityList, nil, nil, nil)
	if err != nil {
		return "", err
	}
	_, err = w.Write([]byte(mySecretString))
	if err != nil {
		return "", err
	}
	err = w.Close()
	if err != nil {
		return "", err
	}

	// Encode to base64
	bytes, err := ioutil.ReadAll(buf)
	if err != nil {
		return "", err
	}
	encStr := base64.StdEncoding.EncodeToString(bytes)

	// Output encrypted/encoded string
	log.Println("Encrypted Secret:", encStr)

	return encStr, nil
}

func decTest(encString string) (string, error) {

	log.Println("Secret Keyring:", secretKeyring)
	log.Println("Passphrase:", passphrase)

	// init some vars
	var entity *openpgp.Entity
	var entityList openpgp.EntityList

	// Open the private key file
	keyringFileBuffer, err := os.Open(secretKeyring)
	if err != nil {
		return "", err
	}
	defer keyringFileBuffer.Close()
	entityList, err = openpgp.ReadKeyRing(keyringFileBuffer)
	if err != nil {
		return "", err
	}
	entity = entityList[0]

	// Get the passphrase and read the private key.
	// Have not touched the encrypted string yet
	passphraseByte := []byte(passphrase)
	log.Println("Decrypting private key using passphrase")
	entity.PrivateKey.Decrypt(passphraseByte)
	for _, subkey := range entity.Subkeys {
		subkey.PrivateKey.Decrypt(passphraseByte)
	}
	log.Println("Finished decrypting private key using passphrase")

	// Decode the base64 string
	dec, err := base64.StdEncoding.DecodeString(encString)
	if err != nil {
		return "", err
	}

	// Decrypt it with the contents of the private key
	md, err := openpgp.ReadMessage(bytes.NewBuffer(dec), entityList, nil, nil)
	if err != nil {
		return "", err
	}
	bytes, err := ioutil.ReadAll(md.UnverifiedBody)
	if err != nil {
		return "", err
	}
	decStr := string(bytes)

	return decStr, nil
}

func main() {
	prefix = os.Getenv("HOME")
	passphrase = os.Getenv("pass")
	secretKeyring = prefix + "/.gnupg/secring.gpg"
	publicKeyring = prefix + "/.gnupg/pubring.gpg"
	flag.StringVar(&mySecretString, "mySecretString", "fark", "the data to encrypt")
	flag.Parse()

	encStr, err := encTest(mySecretString)
	if err != nil {
		log.Fatal(err)
	}
	decStr, err := decTest(encStr)
	if err != nil {
		log.Fatal(err)
	}
	// should be done
	log.Println("Decrypted Secret:", decStr)
}
