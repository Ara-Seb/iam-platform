package handler

import (
	"context"
	"net/http"

	"github.com/yourname/iam-platform/models"
	"github.com/yourname/iam-platform/session"
	"github.com/yourname/iam-platform/store"
)

type MockClientService struct {
	GetClientByIDCalled  bool
	GetClientByIDFunc    func(ctx context.Context, id string) (*models.Client, error)
	ValidateSecretCalled bool
	ValidateSecretFunc   func(ctx context.Context, clientID string, secret string) error
}

func (m *MockClientService) GetClientByID(ctx context.Context, id string) (*models.Client, error) {
	m.GetClientByIDCalled = true
	if m.GetClientByIDFunc == nil {
		return &models.Client{
			ID:           "abc123",
			RedirectURIs: []string{"https://example.com/callback"},
			ClientType:   models.ClientTypeConfidential,
		}, nil
	}
	return m.GetClientByIDFunc(ctx, id)
}

func (m *MockClientService) ValidateSecret(ctx context.Context, clientID string, secret string) error {
	m.ValidateSecretCalled = true
	if m.ValidateSecretFunc == nil {
		return nil
	}
	return m.ValidateSecretFunc(ctx, clientID, secret)
}

type MockAuthService struct {
	RegisterFunc      func(ctx context.Context, email, password string) (*models.User, error)
	LoginFunc         func(ctx context.Context, email, password string) (string, *models.User, error)
	GetUserByIDCalled bool
	GetUserByIDFunc   func(ctx context.Context, id string) (*models.User, error)
}

func (m *MockAuthService) Register(ctx context.Context, email, password string) (*models.User, error) {
	if m.RegisterFunc == nil {
		return &models.User{ID: "123", Email: email}, nil
	}
	return m.RegisterFunc(ctx, email, password)
}

func (m *MockAuthService) Login(ctx context.Context, email, password string) (string, *models.User, error) {
	if m.LoginFunc == nil {
		return "token123", &models.User{ID: "123", Email: email}, nil
	}
	return m.LoginFunc(ctx, email, password)
}

func (m *MockAuthService) GetUserByID(ctx context.Context, id string) (*models.User, error) {
	m.GetUserByIDCalled = true
	if m.GetUserByIDFunc == nil {
		return nil, nil
	}
	return m.GetUserByIDFunc(ctx, id)
}

type MockSessionStore struct {
	SetCalled bool
	SetFunc   func(w http.ResponseWriter, session *session.AuthorizationSession) error
	GetFunc   func(r *http.Request) (*session.AuthorizationSession, error)
	ClearFunc func(w http.ResponseWriter)
}

func (m *MockSessionStore) Set(w http.ResponseWriter, session *session.AuthorizationSession) error {
	m.SetCalled = true
	if m.SetFunc == nil {
		return nil
	}
	return m.SetFunc(w, session)
}

func (m *MockSessionStore) Get(r *http.Request) (*session.AuthorizationSession, error) {
	if m.GetFunc == nil {
		return &session.AuthorizationSession{ClientID: "abc123", RedirectURI: "https://example.com/callback", Scope: "openid", State: "xyz"}, nil
	}
	return m.GetFunc(r)
}

func (m *MockSessionStore) Clear(w http.ResponseWriter) {
	if m.ClearFunc == nil {
		return
	}
	m.ClearFunc(w)
}

type MockCodeStore struct {
	VerifyCodeCalled bool
	CreateCodeFunc   func(clientID, userID, redirectURI, scope, state string) (*store.AuthorizationCode, error)
	VerifyCodeFunc   func(code string) (*store.AuthorizationCode, error)
}

func (m *MockCodeStore) CreateCode(clientID, userID, redirectURI, scope, state string) (*store.AuthorizationCode, error) {
	if m.CreateCodeFunc == nil {
		return &store.AuthorizationCode{Code: "authcode123"}, nil
	}
	return m.CreateCodeFunc(clientID, userID, redirectURI, scope, state)
}

func (m *MockCodeStore) VerifyCode(code string) (*store.AuthorizationCode, error) {
	m.VerifyCodeCalled = true
	if m.VerifyCodeFunc == nil {
		return &store.AuthorizationCode{
			ClientID:    "abc123",
			UserID:      "123",
			RedirectURI: "https://example.com/callback",
			Scope:       "openid",
			State:       "xyz",
		}, nil
	}
	return m.VerifyCodeFunc(code)
}

type MockTokenService struct {
	GenerateTokenCalled bool
	GenerateTokenFunc   func(user *models.User) (string, error)
}

func (m *MockTokenService) GenerateToken(user *models.User) (string, error) {
	m.GenerateTokenCalled = true
	if m.GenerateTokenFunc == nil {
		return "token123", nil
	}
	return m.GenerateTokenFunc(user)
}
