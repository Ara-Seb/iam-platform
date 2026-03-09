package keys

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

type Keys struct {
	Private *rsa.PrivateKey
	Public  *rsa.PublicKey
}

func LoadKeys(privateKeyPath, publicKeyPath string) (*Keys, error) {
	privateBytes, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("could not read private key: %w", err)
	}

	block, _ := pem.Decode(privateBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to decode private key PEM block")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("could not parse private key: %w", err)
	}

	publicBytes, err := os.ReadFile(publicKeyPath)
	if err != nil {
		return nil, fmt.Errorf("could not read public key: %w", err)
	}

	block, _ = pem.Decode(publicBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to decode public key PEM block")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("could not parse public key: %w", err)
	}

	keys := &Keys{
		Private: key.(*rsa.PrivateKey),
		Public:  pub.(*rsa.PublicKey),
	}
	return keys, nil
}
