package store

import (
	"sync"
	"time"

	"github.com/yourname/iam-platform/crypto"
)

type RefreshToken struct {
	Token     string
	UserID    string
	ClientID  string
	Scope     string
	ExpiresAt time.Time
}

type RefreshTokenStore struct {
	tokens map[string]*RefreshToken
	mutex  sync.RWMutex
}

func NewRefreshTokenStore() *RefreshTokenStore {
	return &RefreshTokenStore{
		tokens: make(map[string]*RefreshToken),
	}
}

func (s *RefreshTokenStore) CreateRefreshToken(userID, clientID, scope string, expiration time.Duration) (*RefreshToken, error) {
	token, err := crypto.GenerateRandomToken()
	if err != nil {
		return nil, err
	}
	var refreshToken = &RefreshToken{
		Token:     token,
		UserID:    userID,
		ClientID:  clientID,
		Scope:     scope,
		ExpiresAt: time.Now().Add(expiration),
	}
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.tokens[refreshToken.Token] = refreshToken
	return refreshToken, nil
}

func (s *RefreshTokenStore) VerifyToken(token string) (*RefreshToken, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	refreshToken, ok := s.tokens[token]
	if !ok {
		return nil, ErrTokenNotFound
	}
	if time.Now().After(refreshToken.ExpiresAt) {
		delete(s.tokens, token)
		return nil, ErrTokenExpired
	}
	return refreshToken, nil
}

func (s *RefreshTokenStore) DeleteToken(token string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if _, ok := s.tokens[token]; !ok {
		return ErrTokenNotFound
	}
	delete(s.tokens, token)
	return nil
}
