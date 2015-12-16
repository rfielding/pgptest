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
var inFileName string
var outFileName string

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
	for i := range entityList {
		for k := range entityList[i].Identities {
			log.Printf("encrypt to: %v %v", k, entityList[i].Identities[k])
		}
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
	flag.StringVar(&secretKeyring, "secring", prefix+"/.gnupg/secring.gpg", "the secret ring")
	flag.StringVar(&publicKeyring, "pubring", prefix+"/.gnupg/pubring.gpg", "the public ring")
	flag.StringVar(&mySecretString, "mySecretString", "fark", "the data to encrypt")
	flag.StringVar(&inFileName, "in", "plaintext", "the input file to encrypt")
	flag.StringVar(&outFileName, "out", "ciphertext", "the ciphertext")
	var batchCreate string
	flag.StringVar(&batchCreate, "create", "", "batch create the keyring")
	flag.Parse()
	if batchCreate != "" {
		log.Println("Creating keyring.  This can take minutes!! ....")
		args := []string{
			"--verbose",
			"--batch",
			"--gen-key",
			batchCreate,
		}
		attr := new(os.ProcAttr)
		rFile, err := os.Open("/dev/random")
		if err != nil {
			log.Fatal("cannot open random")
		}
		defer rFile.Close()
		cmd := "/usr/bin/gpg"
		attr.Files = []*os.File{
			rFile,
			os.Stdout,
			os.Stderr,
		}
		log.Printf("running: %v, %v", cmd, args)
		if proc, err := os.StartProcess("/usr/bin/gpg", args, attr); err != nil {
			log.Fatal(err)
		} else {
			proc.Wait()
		}
	}

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
