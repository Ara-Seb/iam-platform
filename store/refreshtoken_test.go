package store

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestRefreshTokenStore_CreateToken(t *testing.T) {
	store := NewRefreshTokenStore()
	userID := "user123"
	clientID := "client123"
	scope := "read write"
	expiration := 1 * time.Hour

	token, err := store.CreateRefreshToken(userID, clientID, scope, expiration)
	assert.NoError(t, err)
	assert.NotEmpty(t, token.Token)
}

func TestRefreshTokenStore_VerifyToken_Valid(t *testing.T) {
	store := NewRefreshTokenStore()
	userID := "user123"
	clientID := "client123"
	scope := "read write"
	expiration := 1 * time.Hour

	token, err := store.CreateRefreshToken(userID, clientID, scope, expiration)
	assert.NoError(t, err)

	verifiedToken, err := store.VerifyToken(token.Token)
	assert.NoError(t, err)
	assert.Equal(t, token.Token, verifiedToken.Token)
}

func TestRefreshTokenStore_VerifyToken_Expired(t *testing.T) {
	store := NewRefreshTokenStore()
	userID := "user123"
	clientID := "client123"
	scope := "read write"
	expiration := 1 * time.Second

	token, err := store.CreateRefreshToken(userID, clientID, scope, expiration)
	assert.NoError(t, err)

	token.ExpiresAt = time.Now().Add(-1 * time.Second)

	_, err = store.VerifyToken(token.Token)
	assert.ErrorIs(t, err, ErrTokenExpired)
}

func TestRefreshTokenStore_VerifyToken_NotFound(t *testing.T) {
	store := NewRefreshTokenStore()

	_, err := store.VerifyToken("nonexistenttoken")
	assert.ErrorIs(t, err, ErrTokenNotFound)
}

func TestRefreshTokenStore_DeleteToken(t *testing.T) {
	store := NewRefreshTokenStore()
	userID := "user123"
	clientID := "client123"
	scope := "read write"
	expiration := 1 * time.Hour

	token, err := store.CreateRefreshToken(userID, clientID, scope, expiration)
	assert.NoError(t, err)

	err = store.DeleteToken(token.Token)
	assert.NoError(t, err)

	_, err = store.VerifyToken(token.Token)
	assert.ErrorIs(t, err, ErrTokenNotFound)
}

func TestRefreshTokenStore_DeleteToken_NotFound(t *testing.T) {
	store := NewRefreshTokenStore()

	err := store.DeleteToken("nonexistenttoken")
	assert.ErrorIs(t, err, ErrTokenNotFound)
}
