package service

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/yourname/iam-platform/keys"
	"github.com/yourname/iam-platform/models"
)

func TestGenerate_FailToValidate(t *testing.T) {
	user := models.User{
		ID:    "user-id",
		Email: "user-email",
		Role:  "user-role",
	}
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	keys := &keys.Keys{
		Private: privateKey,
		Public:  &privateKey.PublicKey,
	}
	service := NewTokenService(keys)
	token, _ := service.GenerateToken(&user)
	token = token + "invalid"
	_, err := service.ValidateToken(token)
	assert.Error(t, err)
}
