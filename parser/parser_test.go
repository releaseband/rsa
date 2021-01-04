package parser

import (
	"errors"
	"testing"
)

func testInvalidKey() func(t *testing.T) {
	const key = "invalid key"
	return func(t *testing.T) {
		_, err := ParseRSAPublicKey([]byte(key))
		if err == nil {
			t.Errorf("err must be not nil")
		}

		if !errors.Is(err, ErrKeyMustBePEMEncoded) {
			t.Errorf("exp err mess: %s, got err mess: %s", ErrKeyMustBePEMEncoded.Error(), err.Error())
		}
	}
}



func testParseKeyFailed() func(t *testing.T) {
	return func(t *testing.T) {
		// todo: implement me
	}
}

func testParseKeySuccess() func(t *testing.T) {
	return func(t *testing.T) {
		// todo: implement me
	}
}

func testParseRsaKeySuccess() func(t *testing.T){
	const (
		keySize = 512
		publicKey = `
-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAlRuRnThUjU8/prwYxbty
WPT9pURI3lbsKMiB6Fn/VHOKE13p4D8xgOCADpdRagdT6n4etr9atzDKUSvpMtR3
CP5noNc97WiNCggBjVWhs7szEe8ugyqF23XwpHQ6uV1LKH50m92MbOWfCtjU9p/x
qhNpQQ1AZhqNy5Gevap5k8XzRmjSldNAFZMY7Yv3Gi+nyCwGwpVtBUwhuLzgNFK/
yDtw2WcWmUU7NuC8Q6MWvPebxVtCfVp/iQU6q60yyt6aGOBkhAX0LpKAEhKidixY
nP9PNVBvxgu3XZ4P36gZV6+ummKdBVnc3NqwBLu5+CcdRdusmHPHd5pHf4/38Z3/
6qU2a/fPvWzceVTEgZ47QjFMTCTmCwNt29cvi7zZeQzjtwQgn4ipN9NibRH/Ax/q
TbIzHfrJ1xa2RteWSdFjwtxi9C20HUkjXSeI4YlzQMH0fPX6KCE7aVePTOnB69I/
a9/q96DiXZajwlpq3wFctrs1oXqBp5DVrCIj8hU2wNgB7LtQ1mCtsYz//heai0K9
PhE4X6hiE0YmeAZjR0uHl8M/5aW9xCoJ72+12kKpWAa0SFRWLy6FejNYCYpkupVJ
yecLk/4L1W0l6jQQZnWErXZYe0PNFcmwGXy1Rep83kfBRNKRy5tvocalLlwXLdUk
AIU+2GKjyT3iMuzZxxFxPFMCAwEAAQ==
-----END PUBLIC KEY-----`
	)

	return func(t *testing.T) {
		pKey, err := ParseRSAPublicKey([]byte(publicKey))
		if err != nil {
			t.Fatal(err)
		}

		if pKey.Size() != keySize {
			t.Fatal("key size invalid")
		}
	}
}

func TestParseRSAPublicKey(t *testing.T) {
	t.Run("fails", func(t *testing.T) {
		t.Run("parseKey", testParseKeyFailed())
		t.Run("invalid key", testInvalidKey())
	})

	t.Run("success", func(t *testing.T) {
		t.Run("parseKey", testParseKeySuccess())
		t.Run("ParseRsaPublicKey", testParseRsaKeySuccess())
	})
}