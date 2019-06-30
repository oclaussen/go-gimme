package ssh

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/pkg/errors"
	"golang.org/x/crypto/ssh"
)

type KeyPair struct {
	PrivateKey []byte
	PublicKey  []byte
}

func GimmeKeyPair(path string) (*KeyPair, error) {
	var keyPair KeyPair

	privateKey, exist, err := readFileIfExist(path)
	if err != nil {
		return nil, errors.Wrap(err, "could not read file")
	}
	if !exist {
		return generateKeyPair(path)
	}
	keyPair.PrivateKey = privateKey

	publicKey, exist, err := readFileIfExist(path)
	if err != nil {
		return nil, errors.Wrap(err, "could not read file")
	}
	if !exist {
		return generatePublicKey(path, &keyPair)
	}
	keyPair.PublicKey = publicKey

	return &keyPair, nil
}

func generateKeyPair(path string) (*KeyPair, error) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, errors.Wrap(err, "could not generate key")
	}

	if err := rsaKey.Validate(); err != nil {
		return nil, errors.Wrap(err, "could not validate key")
	}

	privateKey := pem.EncodeToMemory(&pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   x509.MarshalPKCS1PrivateKey(rsaKey),
	})

	privateKeyFile, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return nil, errors.Wrap(err, "could not write to file")
	}
	defer privateKeyFile.Close()

	_, err = privateKeyFile.Write(privateKey)
	if err != nil {
		return nil, errors.Wrap(err, "could not write to file")
	}

	publicKey, err := ssh.NewPublicKey(&rsaKey.PublicKey)
	if err != nil {
		return nil, errors.Wrap(err, "could not generate public key")
	}

	authorizedKey := ssh.MarshalAuthorizedKey(publicKey)

	publicKeyFile, err := os.Create(fmt.Sprintf("%s.pub", path))
	if err != nil {
		return nil, errors.Wrap(err, "could not write to file")
	}
	defer publicKeyFile.Close()

	_, err = publicKeyFile.Write(authorizedKey)
	if err != nil {
		return nil, errors.Wrap(err, "could not write to file")
	}

	return &KeyPair{
		PrivateKey: privateKey,
		PublicKey:  authorizedKey,
	}, nil
}

func generatePublicKey(path string, keyPair *KeyPair) (*KeyPair, error) {
	pemData, _ := pem.Decode(keyPair.PrivateKey)
	if pemData == nil {
		return nil, errors.New("could not read pem data")
	}

	rsaKey, err := x509.ParsePKCS1PrivateKey(pemData.Bytes)
	if err != nil {
		return nil, errors.Wrap(err, "could not decrypt private key")
	}

	publicKey, err := ssh.NewPublicKey(&rsaKey.PublicKey)
	if err != nil {
		return nil, errors.Wrap(err, "could not generate public key")
	}

	authorizedKey := ssh.MarshalAuthorizedKey(publicKey)

	publicKeyFile, err := os.Create(fmt.Sprintf("%s.pub", path))
	if err != nil {
		return nil, errors.Wrap(err, "could not write to file")
	}
	defer publicKeyFile.Close()

	_, err = publicKeyFile.Write(authorizedKey)
	if err != nil {
		return nil, errors.Wrap(err, "could not write to file")
	}

	keyPair.PublicKey = authorizedKey
	return keyPair, nil
}

func readFileIfExist(path string) ([]byte, bool, error) {
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return []byte{}, false, nil
		}
		return []byte{}, true, err
	}
	contents, err := ioutil.ReadFile(path)
	return contents, true, err
}
