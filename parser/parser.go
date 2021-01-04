package parser

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

var (
	ErrKeyMustBePEMEncoded = errors.New("key must be a PEM encoded PKCS1 or PKCS8 key")
	ErrNotRSAPublicKey     = errors.New("key is not a valid RSA public key")
)

func parseKey(key []byte) (interface{}, error) {
	var (
		parsedKey interface{}
		err       error
	)

	if parsedKey, err = x509.ParsePKIXPublicKey(key); err != nil {
		if cert, err := x509.ParseCertificate(key); err == nil {
			parsedKey = cert.PublicKey
		} else {
			return nil, err
		}
	}

	return parsedKey, nil
}

func ParseRSAPublicKey(publicKey []byte) (*rsa.PublicKey, error) {
	var block *pem.Block
	if block, _ = pem.Decode(publicKey); block == nil {
		return nil, fmt.Errorf("invalid key: %w", ErrKeyMustBePEMEncoded)
	}

	key, err := parseKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	var pkey *rsa.PublicKey
	var ok bool
	if pkey, ok = key.(*rsa.PublicKey); !ok {
		return nil, ErrNotRSAPublicKey
	}

	return pkey, nil
}
