package crypto

import (
	"crypto"
	"crypto/rand"
	"encoding/base64"

	"golang.org/x/crypto/bcrypt"
)

func GenerateRandomToken() (string, error) {
	randomBytes := make([]byte, 32)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(randomBytes), nil
}

func VerifyCodeChallenge(codeVerifier, codeChallenge, method string) bool {
	if method == "S256" {
		return SHA256Hash(codeVerifier) == codeChallenge
	}
	if method == "plain" {
		return codeVerifier == codeChallenge
	}
	return false
}

func SHA256Hash(value string) string {
	hash := crypto.SHA256.New()
	hash.Write([]byte(value))
	return base64.RawURLEncoding.EncodeToString(hash.Sum(nil))
}

func VerifyHash(hash, value string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(value))
}
