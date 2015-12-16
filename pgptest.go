package main

import (
	"flag"
	"io"
	"log"
	"os"

	"golang.org/x/crypto/openpgp"
)

var prefix string
var passphrase string
var secretKeyring string
var publicKeyring string
var mySecretString string

func getEntityList(ring string) (entityList openpgp.EntityList, err error) {
	keyringFileBuffer, _ := os.Open(ring)
	defer keyringFileBuffer.Close()
	entityList, err = openpgp.ReadKeyRing(keyringFileBuffer)
	return
}

func encTest(r io.Reader, w io.Writer) error {
	entityList, err := getEntityList(publicKeyring)
	if err != nil {
		return err
	}

	wPipe, err := openpgp.Encrypt(w, entityList, nil, nil, nil)
	if err != nil {
		return err
	}
	defer wPipe.Close()
	io.Copy(wPipe, r)
	return nil
}

func decTest(r io.Reader, w io.Writer) error {
	entityList, err := getEntityList(secretKeyring)
	if err != nil {
		return err
	}

	entityList[0].PrivateKey.Decrypt([]byte(passphrase))
	for _, subkey := range entityList[0].Subkeys {
		subkey.PrivateKey.Decrypt([]byte(passphrase))
	}
	rPipe, err := openpgp.ReadMessage(r, entityList, nil, nil)
	if err != nil {
		return err
	}
	io.Copy(w, rPipe.UnverifiedBody)
	return nil
}

func main() {
	prefix = os.Getenv("HOME")
	//SET THE PGP PASSWORD IN A TEMP ENV VAR!
	//    pass=foobar go run pgptest.go -in ~/Downloads/giantFile.iso -out giantFile.iso
	passphrase = os.Getenv("pass")
	secretKeyring = prefix + "/.gnupg/secring.gpg"
	publicKeyring = prefix + "/.gnupg/pubring.gpg"
	flag.StringVar(&mySecretString, "mySecretString", "fark", "the data to encrypt")
	var inFileName string
	var outFileName string
	flag.StringVar(&inFileName, "in", "plaintext", "the input file to encrypt")
	flag.StringVar(&outFileName, "out", "ciphertext", "the ciphertext")
	flag.Parse()

	in, err := os.Open(inFileName)
	if err != nil {
		log.Fatal(err)
	}
	defer in.Close()

	out, err := os.Create(outFileName)
	if err != nil {
		log.Fatal(err)
	}
	defer out.Close()

	err = encTest(in, out)
	if err != nil {
		log.Fatal(err)
	}

	in2, err := os.Open(outFileName)
	if err != nil {
		log.Fatal(err)
	}
	defer in2.Close()

	out2, err := os.Create(outFileName + ".decrypt")
	if err != nil {
		log.Fatal(err)
	}

	err = decTest(in2, out2)
}
