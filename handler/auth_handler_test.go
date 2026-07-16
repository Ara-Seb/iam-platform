package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/yourname/iam-platform/models"
	"github.com/yourname/iam-platform/repository"
	"github.com/yourname/iam-platform/service"
	"github.com/yourname/iam-platform/session"
	"github.com/yourname/iam-platform/store"
	"github.com/yourname/iam-platform/utils"
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
	assert.Equal(t, testUserID, resp.ID)
}

func TestAuthorize_MissingClientID(t *testing.T) {
	handler := NewAuthHandler(&MockClientService{}, nil, nil, nil, nil)
	reqTarget := "/authorize?response_type=code&redirect_uri=" + testRedirectURI + "&scope=" + testScope + "&state=" + testState
	req := httptest.NewRequest(http.MethodGet, reqTarget, nil)
	w := httptest.NewRecorder()
	handler.Authorize(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Result().StatusCode)
}

func TestAuthorize_UnrecognizedClientID(t *testing.T) {
	mockClientService := &MockClientService{
		GetClientByIDFunc: func(ctx context.Context, id string) (*models.Client, error) {
			return nil, repository.ErrNotFound
		},
	}
	handler := NewAuthHandler(mockClientService, nil, nil, nil, nil)
	reqTarget := "/authorize?response_type=code&client_id=invalid&redirect_uri=" + testRedirectURI + "&scope=" + testScope + "&state=" + testState
	req := httptest.NewRequest(http.MethodGet, reqTarget, nil)
	w := httptest.NewRecorder()
	handler.Authorize(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Result().StatusCode)
	assert.True(t, mockClientService.GetClientByIDCalled)
}

func TestAuthorize_MissingResponseType(t *testing.T) {
	handler := NewAuthHandler(&MockClientService{}, nil, nil, nil, nil)
	reqTarget := "/authorize?client_id=" + testClientID + "&redirect_uri=" + testRedirectURI + "&scope=" + testScope + "&state=" + testState
	req := httptest.NewRequest(http.MethodGet, reqTarget, nil)
	w := httptest.NewRecorder()
	handler.Authorize(w, req)
	expected := utils.BuildErrorRedirectURI(testRedirectURI, string(ErrUnsupportedResponseType), testState)
	assert.Equal(t, http.StatusFound, w.Result().StatusCode)
	assert.Equal(t, expected, w.Result().Header.Get("Location"))
}

func TestAuthorize_MissingRedirectURI(t *testing.T) {
	handler := NewAuthHandler(&MockClientService{}, nil, nil, nil, nil)
	reqTarget := "/authorize?response_type=code&client_id=" + testClientID + "&scope=" + testScope + "&state=" + testState
	req := httptest.NewRequest(http.MethodGet, reqTarget, nil)
	w := httptest.NewRecorder()
	handler.Authorize(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Result().StatusCode)
}

func TestAuthorize_InvalidRedirectURI(t *testing.T) {
	handler := NewAuthHandler(&MockClientService{}, nil, nil, nil, nil)
	reqTarget := "/authorize?response_type=code&client_id=" + testClientID + "&redirect_uri=https://malicious.com/callback&scope=" + testScope + "&state=" + testState
	req := httptest.NewRequest(http.MethodGet, reqTarget, nil)
	w := httptest.NewRecorder()
	handler.Authorize(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Result().StatusCode)
}

func TestAuthorize_MissingCodeChallenge(t *testing.T) {
	handler := NewAuthHandler(GetMockClientServiceWithPublicClient(), nil, nil, nil, nil)
	reqTarget := "/authorize?response_type=code&client_id=" + testClientID + "&redirect_uri=" + testRedirectURI + "&scope=" + testScope + "&state=" + testState
	req := httptest.NewRequest(http.MethodGet, reqTarget, nil)
	w := httptest.NewRecorder()
	handler.Authorize(w, req)
	expected := utils.BuildErrorRedirectURI(testRedirectURI, string(ErrInvalidRequest), testState)
	assert.Equal(t, http.StatusFound, w.Result().StatusCode)
	assert.Equal(t, expected, w.Result().Header.Get("Location"))
}

func TestAuthorize_InvalidCodeChallengeMethod(t *testing.T) {
	handler := NewAuthHandler(GetMockClientServiceWithPublicClient(), nil, nil, nil, nil)
	reqTarget := "/authorize?response_type=code&client_id=" + testClientID + "&redirect_uri=" + testRedirectURI + "&scope=" + testScope + "&state=" + testState + "&code_challenge=challenge&code_challenge_method=invalid"
	req := httptest.NewRequest(http.MethodGet, reqTarget, nil)
	w := httptest.NewRecorder()
	handler.Authorize(w, req)
	expected := utils.BuildErrorRedirectURI(testRedirectURI, string(ErrInvalidRequest), testState)
	assert.Equal(t, http.StatusFound, w.Result().StatusCode)
	assert.Equal(t, expected, w.Result().Header.Get("Location"))
}

func TestAuthorize_MissingScope(t *testing.T) {
	handler := NewAuthHandler(&MockClientService{}, nil, nil, nil, nil)
	reqTarget := "/authorize?response_type=code&client_id=" + testClientID + "&redirect_uri=" + testRedirectURI + "&state=" + testState
	req := httptest.NewRequest(http.MethodGet, reqTarget, nil)
	w := httptest.NewRecorder()
	handler.Authorize(w, req)
	expected := utils.BuildErrorRedirectURI(testRedirectURI, string(ErrInvalidRequest), testState)
	assert.Equal(t, http.StatusFound, w.Result().StatusCode)
	assert.Equal(t, expected, w.Result().Header.Get("Location"))
}

func TestAuthorize_MissingState(t *testing.T) {
	handler := NewAuthHandler(&MockClientService{}, nil, nil, nil, nil)
	reqTarget := "/authorize?response_type=code&client_id=" + testClientID + "&redirect_uri=" + testRedirectURI + "&scope=" + testScope
	req := httptest.NewRequest(http.MethodGet, reqTarget, nil)
	w := httptest.NewRecorder()
	handler.Authorize(w, req)
	expected := utils.BuildErrorRedirectURI(testRedirectURI, string(ErrInvalidRequest), "")
	assert.Equal(t, http.StatusFound, w.Result().StatusCode)
	assert.Equal(t, expected, w.Result().Header.Get("Location"))
}

func TestAuthorize_SessionStoreError(t *testing.T) {
	mockSessionStore := &MockSessionStore{
		SetFunc: func(w http.ResponseWriter, session *session.AuthorizationSession) error {
			return errors.New("failed to set session")
		},
	}
	handler := NewAuthHandler(&MockClientService{}, nil, mockSessionStore, nil, nil)
	reqTarget := "/authorize?response_type=code&client_id=" + testClientID + "&redirect_uri=" + testRedirectURI + "&scope=" + testScope + "&state=" + testState
	req := httptest.NewRequest(http.MethodGet, reqTarget, nil)
	w := httptest.NewRecorder()
	handler.Authorize(w, req)
	expected := utils.BuildErrorRedirectURI(testRedirectURI, string(ErrServerError), testState)
	assert.Equal(t, http.StatusFound, w.Result().StatusCode)
	assert.Equal(t, expected, w.Result().Header.Get("Location"))
}

func TestAuthorize_Success(t *testing.T) {
	mockSessionStore := &MockSessionStore{}
	handler := NewAuthHandler(&MockClientService{}, nil, mockSessionStore, nil, nil)
	reqTarget := "/authorize?response_type=code&client_id=" + testClientID + "&redirect_uri=" + testRedirectURI + "&scope=" + testScope + "&state=" + testState
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
	assert.Equal(t, testRedirectURI+"?code="+testCode+"&state="+testState, res.Header.Get("Location"))
}

func TestLoginPost_OAuthFlow_FailedCreateCode(t *testing.T) {
	mockCodeStore := &MockCodeStore{
		CreateCodeFunc: func(clientID, userID, redirectURI, scope, state, codeChallenge, codeChallengeMethod string) (*store.AuthorizationCode, error) {
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

func TestToken_UnrecognizedGrantType(t *testing.T) {
	handler := NewAuthHandler(nil, nil, nil, nil, nil)
	body := "client_id=" + testClientID + "&client_secret=secret&grant_type=invalid"
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handler.Token(w, req)
	ConfirmErrorResponse(t, w, http.StatusBadRequest, ErrUnsupportedGrantType)
}

func TestToken_UnrecognizedClientID(t *testing.T) {
	mockClientService := &MockClientService{
		GetClientByIDFunc: func(ctx context.Context, id string) (*models.Client, error) {
			return nil, repository.ErrNotFound
		},
	}
	handler := NewAuthHandler(mockClientService, nil, nil, nil, nil)
	body := "client_id=invalid&client_secret=secret&grant_type=authorization_code"
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
	body := "client_id=" + testClientID + "&client_secret=secret&grant_type=authorization_code&code=valid"
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
	body := "client_id=" + testClientID + "&client_secret=secret&grant_type=authorization_code&code=invalid"
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handler.Token(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Result().StatusCode)
	assert.True(t, mockCodeStore.VerifyCodeCalled)
}

func TestToken_ClientIDMismatch(t *testing.T) {
	handler := NewAuthHandler(&MockClientService{}, nil, nil, &MockCodeStore{}, nil)
	body := "client_id=321cba&client_secret=secret&grant_type=authorization_code&code=valid"
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handler.Token(w, req)
	ConfirmErrorResponse(t, w, http.StatusBadRequest, ErrInvalidGrant)
}

func TestToken_RedirectURIMismatch(t *testing.T) {
	handler := NewAuthHandler(&MockClientService{}, nil, nil, &MockCodeStore{}, nil)
	body := "client_id=" + testClientID + "&client_secret=secret&grant_type=authorization_code&code=valid&redirect_uri=https://malicious.com/callback"
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handler.Token(w, req)
	ConfirmErrorResponse(t, w, http.StatusBadRequest, ErrInvalidGrant)
}

func TestToken_UserNotFound(t *testing.T) {
	mockAuthService := &MockAuthService{
		GetUserByIDFunc: func(ctx context.Context, id string) (*models.User, error) {
			return nil, repository.ErrNotFound
		},
	}
	handler := NewAuthHandler(&MockClientService{}, mockAuthService, nil, &MockCodeStore{}, nil)
	body := "client_id=" + testClientID + "&client_secret=secret&grant_type=authorization_code&code=valid&redirect_uri=" + testRedirectURI
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handler.Token(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Result().StatusCode)
	assert.True(t, mockAuthService.GetUserByIDCalled)
}

func TestToken_MissingCodeVerifier(t *testing.T) {
	handler := NewAuthHandler(GetMockClientServiceWithPublicClient(), nil, nil, GetMockCodeStoreWithPKCE(), nil)
	body := "client_id=" + testClientID + "&grant_type=authorization_code&code=valid&redirect_uri=" + testRedirectURI
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handler.Token(w, req)
	ConfirmErrorResponse(t, w, http.StatusBadRequest, ErrInvalidRequest)
}

func TestToken_BadCodeVerifier(t *testing.T) {
	handler := NewAuthHandler(GetMockClientServiceWithPublicClient(), nil, nil, GetMockCodeStoreWithPKCE(), nil)
	body := "client_id=" + testClientID + "&grant_type=authorization_code&code=valid&redirect_uri=" + testRedirectURI + "&code_verifier=" + testInvalidVerifier
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handler.Token(w, req)
	ConfirmErrorResponse(t, w, http.StatusBadRequest, ErrInvalidGrant)
}

func TestToken_Success(t *testing.T) {
	mockTokenService := &MockTokenService{}
	handler := NewAuthHandler(&MockClientService{}, &MockAuthService{}, nil, &MockCodeStore{}, mockTokenService)
	body := "client_id=" + testClientID + "&client_secret=secret&grant_type=authorization_code&code=valid&redirect_uri=" + testRedirectURI
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handler.Token(w, req)
	var resp TokenResponse
	assert.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Equal(t, "Bearer", resp.Type)
	assert.Equal(t, int64(service.TokenExpiration/time.Second), resp.ExpiresIn)
	assert.Equal(t, "token123", resp.Token)
	assert.Equal(t, http.StatusOK, w.Result().StatusCode)
	assert.True(t, mockTokenService.GenerateUserTokenCalled)
}

func TestToken_SuccessPKCE(t *testing.T) {
	mockTokenService := &MockTokenService{}
	handler := NewAuthHandler(GetMockClientServiceWithPublicClient(), &MockAuthService{}, nil, GetMockCodeStoreWithPKCE(), mockTokenService)
	body := "client_id=" + testClientID + "&grant_type=authorization_code&code=valid&redirect_uri=" + testRedirectURI + "&code_verifier=" + testValidVerifier
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handler.Token(w, req)
	var resp TokenResponse
	assert.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Equal(t, "Bearer", resp.Type)
	assert.Equal(t, int64(service.TokenExpiration/time.Second), resp.ExpiresIn)
	assert.Equal(t, "token123", resp.Token)
	assert.Equal(t, http.StatusOK, w.Result().StatusCode)
	assert.True(t, mockTokenService.GenerateUserTokenCalled)
}

func TestToken_ClientCredentials_Success(t *testing.T) {
	mockTokenService := &MockTokenService{}
	handler := NewAuthHandler(&MockClientService{}, nil, nil, nil, mockTokenService)
	body := "client_id=" + testClientID + "&client_secret=secret&grant_type=client_credentials"
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handler.Token(w, req)
	var resp TokenResponse
	assert.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Equal(t, "Bearer", resp.Type)
	assert.Equal(t, int64(service.TokenExpiration/time.Second), resp.ExpiresIn)
	assert.Equal(t, "token456", resp.Token)
	assert.Equal(t, http.StatusOK, w.Result().StatusCode)
	assert.True(t, mockTokenService.GenerateClientTokenCalled)
}

func TestToken_ClientCredentials_BadSecret(t *testing.T) {
	mockClientService := &MockClientService{
		ValidateSecretFunc: func(ctx context.Context, clientID string, secret string) error {
			return errors.New("invalid secret")
		},
	}
	handler := NewAuthHandler(mockClientService, nil, nil, nil, nil)
	body := "client_id=" + testClientID + "&client_secret=wrongsecret&grant_type=client_credentials"
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handler.Token(w, req)
	assert.True(t, mockClientService.ValidateSecretCalled)
	ConfirmErrorResponse(t, w, http.StatusUnauthorized, ErrInvalidClient)
}

func TestToken_ClientCredentials_InvalidClient(t *testing.T) {
	mockClientService := &MockClientService{
		GetClientByIDFunc: func(ctx context.Context, id string) (*models.Client, error) {
			return nil, repository.ErrNotFound
		},
	}
	handler := NewAuthHandler(mockClientService, nil, nil, nil, nil)
	body := "client_id=invalid&client_secret=secret&grant_type=client_credentials"
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handler.Token(w, req)
	assert.True(t, mockClientService.GetClientByIDCalled)
	ConfirmErrorResponse(t, w, http.StatusUnauthorized, ErrInvalidClient)
}

func TestToken_ClientCredential_PublicClient(t *testing.T) {
	mockClientService := &MockClientService{
		GetClientByIDFunc: func(ctx context.Context, id string) (*models.Client, error) {
			return &models.Client{ClientType: models.ClientTypePublic}, nil
		},
	}
	handler := NewAuthHandler(mockClientService, nil, nil, nil, nil)
	body := "client_id=" + testClientID + "&grant_type=client_credentials"
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handler.Token(w, req)
	assert.True(t, mockClientService.GetClientByIDCalled)
	assert.False(t, mockClientService.ValidateSecretCalled)
	ConfirmErrorResponse(t, w, http.StatusUnauthorized, ErrInvalidClient)
}
