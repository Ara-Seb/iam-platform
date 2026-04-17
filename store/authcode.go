package store

import (
	"sync"
	"time"

	"github.com/yourname/iam-platform/crypto"
)

type AuthorizationCode struct {
	Code        string
	ClientID    string
	UserID      string
	RedirectURI string
	Scope       string
	State       string
	CreatedAt   time.Time
}

type AuthCodeStore struct {
	codes map[string]*AuthorizationCode
	mutex sync.RWMutex
}

const CodeExpiry = 300 * time.Second

func NewAuthCodeStore() *AuthCodeStore {
	return &AuthCodeStore{
		codes: make(map[string]*AuthorizationCode),
	}
}

func (s *AuthCodeStore) CreateCode(clientID, userID, redirectURI, scope, state string) (*AuthorizationCode, error) {
	randomCode, err := crypto.GenerateRandomToken()
	if err != nil {
		return nil, err
	}
	code := &AuthorizationCode{
		Code:        randomCode,
		ClientID:    clientID,
		UserID:      userID,
		RedirectURI: redirectURI,
		Scope:       scope,
		State:       state,
		CreatedAt:   time.Now(),
	}
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.codes[code.Code] = code
	return code, nil
}

func (s *AuthCodeStore) VerifyCode(code string) (*AuthorizationCode, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	authCode, ok := s.codes[code]
	if !ok {
		return nil, ErrCodeNotFound
	}
	if time.Since(authCode.CreatedAt) > CodeExpiry {
		delete(s.codes, code)
		return nil, ErrCodeExpired
	}
	delete(s.codes, code)
	return authCode, nil
}
