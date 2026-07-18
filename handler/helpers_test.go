package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/yourname/iam-platform/crypto"
	"github.com/yourname/iam-platform/models"
	"github.com/yourname/iam-platform/session"
	"github.com/yourname/iam-platform/store"
)

const (
	testClientID        = "abc123"
	testRedirectURI     = "https://example.com/callback"
	testScope           = "openid"
	testState           = "xyz"
	testUserID          = "123"
	testCode            = "authcode123"
	testValidVerifier   = "atLeast43CharactersLongCodeVerifierWhichIsValid"
	testInvalidVerifier = "atLeast43CharactersLongCodeVerifierWhichIsBad"
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
			ID:           testClientID,
			RedirectURIs: []string{testRedirectURI},
			ClientType:   models.ClientTypeConfidential,
		}, nil
	}
	return m.GetClientByIDFunc(ctx, id)
}

func GetMockClientServiceWithPublicClient() *MockClientService {
	return &MockClientService{
		GetClientByIDFunc: func(ctx context.Context, id string) (*models.Client, error) {
			return &models.Client{
				ID:           testClientID,
				RedirectURIs: []string{testRedirectURI},
				ClientType:   models.ClientTypePublic,
			}, nil
		},
	}
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
		return &models.User{ID: testUserID, Email: email}, nil
	}
	return m.RegisterFunc(ctx, email, password)
}

func (m *MockAuthService) Login(ctx context.Context, email, password string) (string, *models.User, error) {
	if m.LoginFunc == nil {
		return "token123", &models.User{ID: testUserID, Email: email}, nil
	}
	return m.LoginFunc(ctx, email, password)
}

func (m *MockAuthService) GetUserByID(ctx context.Context, id string) (*models.User, error) {
	m.GetUserByIDCalled = true
	if m.GetUserByIDFunc == nil {
		return &models.User{ID: testUserID}, nil
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
		return &session.AuthorizationSession{
			ClientID:    testClientID,
			RedirectURI: testRedirectURI,
			Scope:       testScope,
			State:       testState,
		}, nil
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
	CreateCodeFunc   func(clientID, userID, redirectURI, scope, state, codeChallenge, codeChallengeMethod string) (*store.AuthorizationCode, error)
	VerifyCodeFunc   func(code string) (*store.AuthorizationCode, error)
}

func (m *MockCodeStore) CreateCode(clientID, userID, redirectURI, scope, state, codeChallenge, codeChallengeMethod string) (*store.AuthorizationCode, error) {
	if m.CreateCodeFunc == nil {
		return &store.AuthorizationCode{Code: testCode}, nil
	}
	return m.CreateCodeFunc(clientID, userID, redirectURI, scope, state, codeChallenge, codeChallengeMethod)
}

func (m *MockCodeStore) VerifyCode(code string) (*store.AuthorizationCode, error) {
	m.VerifyCodeCalled = true
	if m.VerifyCodeFunc == nil {
		return &store.AuthorizationCode{
			ClientID:            testClientID,
			UserID:              testUserID,
			RedirectURI:         testRedirectURI,
			Scope:               testScope,
			State:               testState,
			CodeChallenge:       crypto.SHA256Hash(testValidVerifier),
			CodeChallengeMethod: "S256",
		}, nil
	}
	return m.VerifyCodeFunc(code)
}

func GetMockCodeStoreWithPKCE() *MockCodeStore {
	challenge := crypto.SHA256Hash(testValidVerifier)
	method := "S256"
	return &MockCodeStore{
		VerifyCodeFunc: func(code string) (*store.AuthorizationCode, error) {
			return &store.AuthorizationCode{
				ClientID:            testClientID,
				UserID:              testUserID,
				RedirectURI:         testRedirectURI,
				Scope:               testScope,
				State:               testState,
				CodeChallenge:       challenge,
				CodeChallengeMethod: method,
			}, nil
		},
	}
}

type MockRefreshTokenStore struct {
	CreateRefreshTokenCalled bool
	CreateRefreshTokenFunc   func(userID, clientID, scope string, expiration time.Duration) (*store.RefreshToken, error)
	VerifyTokenCalled        bool
	VerifyTokenFunc          func(token string) (*store.RefreshToken, error)
	DeleteTokenCalled        bool
	DeleteTokenFunc          func(token string) error
}

func (m *MockRefreshTokenStore) CreateRefreshToken(userID, clientID, scope string, expiration time.Duration) (*store.RefreshToken, error) {
	m.CreateRefreshTokenCalled = true
	if m.CreateRefreshTokenFunc == nil {
		return &store.RefreshToken{
			Token:     "refreshtoken123",
			UserID:    userID,
			ClientID:  clientID,
			Scope:     scope,
			ExpiresAt: time.Now().Add(expiration),
		}, nil
	}
	return m.CreateRefreshTokenFunc(userID, clientID, scope, expiration)
}

func (m *MockRefreshTokenStore) VerifyToken(token string) (*store.RefreshToken, error) {
	m.VerifyTokenCalled = true
	if m.VerifyTokenFunc == nil {
		return &store.RefreshToken{
			Token:     token,
			UserID:    testUserID,
			ClientID:  testClientID,
			Scope:     testScope,
			ExpiresAt: time.Now().Add(1 * time.Hour),
		}, nil
	}
	return m.VerifyTokenFunc(token)
}

func (m *MockRefreshTokenStore) DeleteToken(token string) error {
	m.DeleteTokenCalled = true
	if m.DeleteTokenFunc == nil {
		return nil
	}
	return m.DeleteTokenFunc(token)
}

type MockTokenService struct {
	GenerateUserTokenCalled   bool
	GenerateUserTokenFunc     func(user *models.User) (string, error)
	GenerateClientTokenCalled bool
	GenerateClientTokenFunc   func(clientID string) (string, error)
}

func (m *MockTokenService) GenerateUserToken(user *models.User) (string, error) {
	m.GenerateUserTokenCalled = true
	if m.GenerateUserTokenFunc == nil {
		return "token123", nil
	}
	return m.GenerateUserTokenFunc(user)
}

func (m *MockTokenService) GenerateClientToken(clientID string) (string, error) {
	m.GenerateClientTokenCalled = true
	if m.GenerateClientTokenFunc == nil {
		return "token456", nil
	}
	return m.GenerateClientTokenFunc(clientID)
}

func ConfirmErrorResponse(t *testing.T, w *httptest.ResponseRecorder, expectedStatus int, expectedError OAuthErrorResponse) {
	assert.Equal(t, expectedStatus, w.Result().StatusCode)
	var resp map[string]string
	assert.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Equal(t, string(expectedError), resp["error"])
}
