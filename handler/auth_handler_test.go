package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yourname/iam-platform/models"
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
	handler := NewAuthHandler(nil, mockAuthService, nil, nil)

	body := `{"email": "test@example.com", "password": "password123"}`
	req := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.Register(w, req)
	res := w.Result()
	if res.StatusCode != http.StatusConflict {
		t.Errorf("expected 409 Conflict, got %v", res.StatusCode)
	}
}

func TestRegister_Success(t *testing.T) {
	handler := NewAuthHandler(nil, GetHappyAuthService(), nil, nil)

	body := `{"email": "test@example.com", "password": "password123"}`
	req := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.Register(w, req)
	res := w.Result()
	if res.StatusCode != http.StatusCreated {
		t.Errorf("expected 201 Created, got %v", res.StatusCode)
	}
	var resp RegisterUserResponse
	if err := json.NewDecoder(res.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response body: %v", err)
	}
	if resp.Email != "test@example.com" {
		t.Errorf("expected email test@example.com, got %v", resp.Email)
	}
	if resp.ID != "123" {
		t.Errorf("expected id 123, got %v", resp.ID)
	}
}

func TestAuthorize_MissingResponseType(t *testing.T) {
	handler := NewAuthHandler(nil, nil, nil, nil)

	reqTarget := "/authorize?client_id=abc123&redirect_uri=https://example.com/callback&scope=openid&state=xyz"
	req := httptest.NewRequest(http.MethodGet, reqTarget, nil)
	w := httptest.NewRecorder()
	handler.Authorize(w, req)
	res := w.Result()
	if res.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 Bad Request, got %v", res.StatusCode)
	}
}

func TestAuthorize_InvalidRedirectURI(t *testing.T) {
	handler := NewAuthHandler(GetHappyClientService(), nil, nil, nil)

	reqTarget := "/authorize?response_type=code&client_id=abc123&redirect_uri=https://malicious.com/callback&scope=openid&state=xyz"
	req := httptest.NewRequest(http.MethodGet, reqTarget, nil)
	w := httptest.NewRecorder()
	handler.Authorize(w, req)
	res := w.Result()
	if res.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 Unauthorized, got %v", res.StatusCode)
	}
}

func TestAuthorize_Success(t *testing.T) {
	mockSessionStore := &MockSessionStore{}
	handler := NewAuthHandler(GetHappyClientService(), nil, mockSessionStore, nil)

	reqTarget := "/authorize?response_type=code&client_id=abc123&redirect_uri=https://example.com/callback&scope=openid&state=xyz"
	req := httptest.NewRequest(http.MethodGet, reqTarget, nil)
	w := httptest.NewRecorder()
	handler.Authorize(w, req)
	if !mockSessionStore.SetCalled {
		t.Error("expected SessionStore.Set to be called")
	}
	res := w.Result()
	if res.StatusCode != http.StatusFound {
		t.Errorf("expected 302 Found, got %v", res.StatusCode)
	}
	location := res.Header.Get("Location")
	if location != "/login" {
		t.Errorf("expected redirect to /login, got %v", location)
	}
}

func TestLoginPost_BadCredentials(t *testing.T) {
	mockAuthService := &MockAuthService{
		LoginFunc: func(ctx context.Context, email, password string) (string, *models.User, error) {
			return "", nil, service.ErrInvalidCredentials
		},
	}
	handler := NewAuthHandler(nil, mockAuthService, nil, nil)

	body := `{"email": "test@example.com", "password": "password123"}`
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.LoginPost(w, req)
	res := w.Result()
	if res.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 Unauthorized, got %v", res.StatusCode)
	}
}

func TestLoginPost_DirectLogin(t *testing.T) {
	handler := NewAuthHandler(nil, GetHappyAuthService(), &MockSessionStore{}, nil)

	body := `{"email": "test@example.com", "password": "password123"}`
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.LoginPost(w, req)
	res := w.Result()
	if res.StatusCode != http.StatusOK {
		t.Errorf("expected 200 OK, got %v", res.StatusCode)
	}
}

func TestLoginPost_OAuthFlow(t *testing.T) {
	mockSessionStore := &MockSessionStore{
		GetFunc: func(r *http.Request) (*session.AuthorizationSession, error) {
			return &session.AuthorizationSession{ClientID: "abc123", RedirectURI: "https://example.com/callback", Scope: "openid", State: "xyz"}, nil
		},
		ClearFunc: func(w http.ResponseWriter) {},
	}
	mockCodeStore := &MockCodeStore{
		CreateCodeFunc: func(clientID, userID, redirectURI, scope, state string) (*store.AuthorizationCode, error) {
			return &store.AuthorizationCode{Code: "authcode123"}, nil
		},
	}
	handler := NewAuthHandler(nil, GetHappyAuthService(), mockSessionStore, mockCodeStore)

	body := `{"email": "test@example.com", "password": "password123"}`
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.LoginPost(w, req)
	res := w.Result()
	if res.StatusCode != http.StatusFound {
		t.Errorf("expected 302 Found, got %v", res.StatusCode)
	}
	location := res.Header.Get("Location")
	expectedLocation := "https://example.com/callback?code=authcode123&state=xyz"
	if location != expectedLocation {
		t.Errorf("expected redirect to %v, got %v", expectedLocation, location)
	}
}

func TestLoginPost_OAuthFlow_FailedCreateCode(t *testing.T) {
	mockSessionStore := &MockSessionStore{
		GetFunc: func(r *http.Request) (*session.AuthorizationSession, error) {
			return &session.AuthorizationSession{ClientID: "abc123", RedirectURI: "https://example.com/callback", Scope: "openid", State: "xyz"}, nil
		},
		ClearFunc: func(w http.ResponseWriter) {},
	}
	mockCodeStore := &MockCodeStore{
		CreateCodeFunc: func(clientID, userID, redirectURI, scope, state string) (*store.AuthorizationCode, error) {
			return nil, errors.New("failed to create code")
		},
	}
	handler := NewAuthHandler(nil, GetHappyAuthService(), mockSessionStore, mockCodeStore)

	body := `{"email": "test@example.com", "password": "password123"}`
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.LoginPost(w, req)
	res := w.Result()
	if res.StatusCode != http.StatusInternalServerError {
		t.Errorf("expected 500 Internal Server Error, got %v", res.StatusCode)
	}
}
