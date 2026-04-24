package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/yourname/iam-platform/models"
	"github.com/yourname/iam-platform/repository"
	"github.com/yourname/iam-platform/service"
	"github.com/yourname/iam-platform/session"
	"github.com/yourname/iam-platform/store"
)

func TestRegister_EmailExists(t *testing.T) {
	mockAuthService := &MockAuthService{
		RegisterFunc: func(ctx context.Context, email, password string) (*models.User, error) {
			return nil, service.ErrEmailAlreadyExists
		},
	}
	handler := NewAuthHandler(nil, mockAuthService, nil, nil, nil)
	body := `{"email": "test@example.com", "password": "password123"}`
	req := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.Register(w, req)
	assert.Equal(t, http.StatusConflict, w.Result().StatusCode)
}

func TestRegister_Success(t *testing.T) {
	handler := NewAuthHandler(nil, &MockAuthService{}, nil, nil, nil)
	body := `{"email": "test@example.com", "password": "password123"}`
	req := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.Register(w, req)
	res := w.Result()
	assert.Equal(t, http.StatusCreated, res.StatusCode)
	var resp RegisterUserResponse
	err := json.NewDecoder(res.Body).Decode(&resp)
	assert.NoError(t, err)
	assert.Equal(t, "test@example.com", resp.Email)
	assert.Equal(t, "123", resp.ID)
}

func TestAuthorize_MissingResponseType(t *testing.T) {
	handler := NewAuthHandler(nil, nil, nil, nil, nil)
	reqTarget := "/authorize?client_id=abc123&redirect_uri=https://example.com/callback&scope=openid&state=xyz"
	req := httptest.NewRequest(http.MethodGet, reqTarget, nil)
	w := httptest.NewRecorder()
	handler.Authorize(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Result().StatusCode)
}

func TestAuthorize_InvalidRedirectURI(t *testing.T) {
	handler := NewAuthHandler(&MockClientService{}, nil, nil, nil, nil)
	reqTarget := "/authorize?response_type=code&client_id=abc123&redirect_uri=https://malicious.com/callback&scope=openid&state=xyz"
	req := httptest.NewRequest(http.MethodGet, reqTarget, nil)
	w := httptest.NewRecorder()
	handler.Authorize(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Result().StatusCode)
}

func TestAuthorize_Success(t *testing.T) {
	mockSessionStore := &MockSessionStore{}
	handler := NewAuthHandler(&MockClientService{}, nil, mockSessionStore, nil, nil)
	reqTarget := "/authorize?response_type=code&client_id=abc123&redirect_uri=https://example.com/callback&scope=openid&state=xyz"
	req := httptest.NewRequest(http.MethodGet, reqTarget, nil)
	w := httptest.NewRecorder()
	handler.Authorize(w, req)
	res := w.Result()
	assert.True(t, mockSessionStore.SetCalled)
	assert.Equal(t, http.StatusFound, res.StatusCode)
	assert.Equal(t, "/login", res.Header.Get("Location"))
}

func TestLoginPost_BadCredentials(t *testing.T) {
	mockAuthService := &MockAuthService{
		LoginFunc: func(ctx context.Context, email, password string) (string, *models.User, error) {
			return "", nil, service.ErrInvalidCredentials
		},
	}
	handler := NewAuthHandler(nil, mockAuthService, nil, nil, nil)
	body := `{"email": "test@example.com", "password": "password123"}`
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.LoginPost(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Result().StatusCode)
}

func TestLoginPost_DirectLogin(t *testing.T) {
	mockSessionStore := &MockSessionStore{
		GetFunc: func(r *http.Request) (*session.AuthorizationSession, error) {
			return nil, nil
		},
	}
	handler := NewAuthHandler(nil, &MockAuthService{}, mockSessionStore, nil, nil)
	body := `{"email": "test@example.com", "password": "password123"}`
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.LoginPost(w, req)
	assert.Equal(t, http.StatusOK, w.Result().StatusCode)
}

func TestLoginPost_OAuthFlow(t *testing.T) {
	handler := NewAuthHandler(nil, &MockAuthService{}, &MockSessionStore{}, &MockCodeStore{}, nil)
	body := `{"email": "test@example.com", "password": "password123"}`
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.LoginPost(w, req)
	res := w.Result()
	assert.Equal(t, http.StatusFound, res.StatusCode)
	assert.Equal(t, "https://example.com/callback?code=authcode123&state=xyz", res.Header.Get("Location"))
}

func TestLoginPost_OAuthFlow_FailedCreateCode(t *testing.T) {
	mockCodeStore := &MockCodeStore{
		CreateCodeFunc: func(clientID, userID, redirectURI, scope, state string) (*store.AuthorizationCode, error) {
			return nil, errors.New("failed to create code")
		},
	}
	handler := NewAuthHandler(nil, &MockAuthService{}, &MockSessionStore{}, mockCodeStore, nil)
	body := `{"email": "test@example.com", "password": "password123"}`
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.LoginPost(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Result().StatusCode)
}

func TestToken_UnrecognizedClientID(t *testing.T) {
	mockClientService := &MockClientService{
		GetClientByIDFunc: func(ctx context.Context, id string) (*models.Client, error) {
			return nil, repository.ErrNotFound
		},
	}
	handler := NewAuthHandler(mockClientService, nil, nil, nil, nil)
	body := `client_id=invalid&client_secret=secret&grant_type=authorization_code`
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handler.Token(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Result().StatusCode)
	assert.True(t, mockClientService.GetClientByIDCalled)
	assert.False(t, mockClientService.ValidateSecretCalled)
}

func TestToken_BadSecret(t *testing.T) {
	mockClientService := &MockClientService{
		ValidateSecretFunc: func(ctx context.Context, clientID string, secret string) error {
			return errors.New("invalid secret")
		},
	}
	handler := NewAuthHandler(mockClientService, nil, nil, nil, nil)
	body := `client_id=abc123&client_secret=secret&grant_type=authorization_code&code=valid`
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handler.Token(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Result().StatusCode)
	assert.True(t, mockClientService.ValidateSecretCalled)
}

func TestToken_InvalidCode(t *testing.T) {
	mockCodeStore := &MockCodeStore{
		VerifyCodeFunc: func(code string) (*store.AuthorizationCode, error) {
			return nil, errors.New("invalid code")
		},
	}
	handler := NewAuthHandler(&MockClientService{}, nil, nil, mockCodeStore, nil)
	body := `client_id=abc123&client_secret=secret&grant_type=authorization_code&code=invalid`
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handler.Token(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Result().StatusCode)
	assert.True(t, mockCodeStore.VerifyCodeCalled)
}

func TestToken_ClientIDMismatch(t *testing.T) {
	handler := NewAuthHandler(&MockClientService{}, nil, nil, &MockCodeStore{}, nil)
	body := `client_id=321cba&client_secret=secret&grant_type=authorization_code&code=valid`
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handler.Token(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Result().StatusCode)
	assert.Contains(t, w.Body.String(), "client_id mismatch")
}

func TestToken_RedirectURIMismatch(t *testing.T) {
	handler := NewAuthHandler(&MockClientService{}, nil, nil, &MockCodeStore{}, nil)
	body := `client_id=abc123&client_secret=secret&grant_type=authorization_code&code=valid&redirect_uri=https://malicious.com/callback`
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handler.Token(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Result().StatusCode)
	assert.Contains(t, w.Body.String(), "redirect_uri mismatch")
}

func TestToken_UserNotFound(t *testing.T) {
	mockAuthService := &MockAuthService{
		GetUserByIDFunc: func(ctx context.Context, id string) (*models.User, error) {
			return nil, repository.ErrNotFound
		},
	}
	handler := NewAuthHandler(&MockClientService{}, mockAuthService, nil, &MockCodeStore{}, nil)
	body := `client_id=abc123&client_secret=secret&grant_type=authorization_code&code=valid&redirect_uri=https://example.com/callback`
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handler.Token(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Result().StatusCode)
	assert.True(t, mockAuthService.GetUserByIDCalled)
}

func TestToken_Success(t *testing.T) {
	mockTokenService := &MockTokenService{}
	handler := NewAuthHandler(&MockClientService{}, &MockAuthService{}, nil, &MockCodeStore{}, mockTokenService)
	body := `client_id=abc123&client_secret=secret&grant_type=authorization_code&code=valid&redirect_uri=https://example.com/callback`
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handler.Token(w, req)
	assert.Equal(t, http.StatusOK, w.Result().StatusCode)
	assert.True(t, mockTokenService.GenerateTokenCalled)
}
