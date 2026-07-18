package handler

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/gorilla/schema"
	"github.com/yourname/iam-platform/crypto"
	"github.com/yourname/iam-platform/models"
	"github.com/yourname/iam-platform/service"
	"github.com/yourname/iam-platform/session"
	"github.com/yourname/iam-platform/store"
	"github.com/yourname/iam-platform/utils"
)

type ClientService interface {
	GetClientByID(ctx context.Context, id string) (*models.Client, error)
	ValidateSecret(ctx context.Context, clientID string, secret string) error
}

type AuthService interface {
	Register(ctx context.Context, email, password string) (*models.User, error)
	Login(ctx context.Context, email, password string) (string, *models.User, error)
	GetUserByID(ctx context.Context, id string) (*models.User, error)
}

type SessionStore interface {
	Set(w http.ResponseWriter, session *session.AuthorizationSession) error
	Get(r *http.Request) (*session.AuthorizationSession, error)
	Clear(w http.ResponseWriter)
}

type CodeStore interface {
	CreateCode(clientID, userID, redirectURI, scope, state, codeChallenge, codeChallengeMethod string) (*store.AuthorizationCode, error)
	VerifyCode(code string) (*store.AuthorizationCode, error)
}

type RefreshTokenStore interface {
	CreateRefreshToken(userID, clientID, scope string, expiration time.Duration) (*store.RefreshToken, error)
	VerifyToken(token string) (*store.RefreshToken, error)
	DeleteToken(token string) error
}

type TokenService interface {
	GenerateUserToken(user *models.User) (string, error)
	GenerateClientToken(clientID string) (string, error)
}

type AuthHandler struct {
	ClientService     ClientService
	AuthService       AuthService
	SessionStore      SessionStore
	CodeStore         CodeStore
	TokenService      TokenService
	RefreshTokenStore RefreshTokenStore
	Decoder           *schema.Decoder
}

func NewAuthHandler(clientService ClientService, authService AuthService, sessionStore SessionStore, codeStore CodeStore, tokenStore RefreshTokenStore, tokenService TokenService) *AuthHandler {
	decoder := schema.NewDecoder()
	decoder.IgnoreUnknownKeys(true)
	return &AuthHandler{
		ClientService:     clientService,
		AuthService:       authService,
		SessionStore:      sessionStore,
		CodeStore:         codeStore,
		RefreshTokenStore: tokenStore,
		TokenService:      tokenService,
		Decoder:           decoder,
	}
}

type RegisterUserRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type RegisterUserResponse struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Role  string `json:"role"`
}

func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	var req RegisterUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	if req.Email == "" || len(req.Password) < 8 {
		http.Error(w, "email and password (min 8 chars) required", http.StatusBadRequest)
		return
	}

	user, err := h.AuthService.Register(r.Context(), req.Email, req.Password)

	if err != nil {
		if errors.Is(err, service.ErrEmailAlreadyExists) {
			http.Error(w, "email already exists", http.StatusConflict)
			return
		}
		log.Printf("error registering user: %v", err)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(RegisterUserResponse{
		ID:    user.ID,
		Email: user.Email,
		Role:  user.Role,
	})
}

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type LoginResponse struct {
	Token string `json:"token"`
}

func (h *AuthHandler) LoginPost(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	token, user, err := h.AuthService.Login(r.Context(), req.Email, req.Password)
	if err != nil {
		if errors.Is(err, service.ErrInvalidCredentials) {
			http.Error(w, "invalid credentials", http.StatusUnauthorized)
			return
		}
		log.Printf("login error: %v", err)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	cookie, _ := h.SessionStore.Get(r)
	if cookie != nil {
		code, err := h.CodeStore.CreateCode(cookie.ClientID, user.ID, cookie.RedirectURI, cookie.Scope, cookie.State, cookie.CodeChallenge, cookie.CodeChallengeMethod)
		if err != nil {
			log.Printf("failed to create authorization code: %v", err)
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}
		redirectURL := utils.BuildRedirectURI(cookie.RedirectURI, code.Code, cookie.State)
		h.SessionStore.Clear(w)
		http.Redirect(w, r, redirectURL, http.StatusFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(LoginResponse{Token: token})
}

func (h *AuthHandler) LoginGet(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "static/login.html")
}

type AuthorizeRequest struct {
	ResponseType        string `schema:"response_type"`
	ClientId            string `schema:"client_id"`
	RedirectURI         string `schema:"redirect_uri"`
	Scope               string `schema:"scope"`
	State               string `schema:"state"`
	CodeChallenge       string `schema:"code_challenge"`
	CodeChallengeMethod string `schema:"code_challenge_method"`
}

func (h *AuthHandler) Authorize(w http.ResponseWriter, r *http.Request) {
	var req AuthorizeRequest
	if err := h.Decoder.Decode(&req, r.URL.Query()); err != nil {
		log.Printf("failed to decode authorize request: %v", err)
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	if req.ClientId == "" || req.RedirectURI == "" {
		log.Printf("missing required parameters: client_id or redirect_uri")
		http.Error(w, "missing required parameters", http.StatusBadRequest)
		return
	}

	client, err := h.ClientService.GetClientByID(r.Context(), req.ClientId)
	if err != nil {
		log.Printf("unrecognized client_id: %v", err)
		http.Error(w, "unrecognized client_id", http.StatusUnauthorized)
		return
	}
	if !utils.Contains(client.RedirectURIs, req.RedirectURI) {
		log.Printf("invalid redirect_uri: %v", err)
		http.Error(w, "invalid redirect_uri", http.StatusUnauthorized)
		return
	}
	if req.Scope == "" || req.State == "" {
		log.Printf("missing required parameters: scope or state")
		URI := utils.BuildErrorRedirectURI(req.RedirectURI, string(ErrInvalidRequest), req.State)
		http.Redirect(w, r, URI, http.StatusFound)
		return
	}
	if req.ResponseType != "code" {
		log.Printf("unsupported response type: %s", req.ResponseType)
		URI := utils.BuildErrorRedirectURI(req.RedirectURI, string(ErrUnsupportedResponseType), req.State)
		http.Redirect(w, r, URI, http.StatusFound)
		return
	}
	if req.CodeChallenge == "" || req.CodeChallengeMethod != "S256" {
		log.Printf("invalid code challenge or method")
		URI := utils.BuildErrorRedirectURI(req.RedirectURI, string(ErrInvalidRequest), req.State)
		http.Redirect(w, r, URI, http.StatusFound)
		return
	}

	session := &session.AuthorizationSession{
		ClientID:            req.ClientId,
		RedirectURI:         req.RedirectURI,
		Scope:               req.Scope,
		State:               req.State,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod,
	}
	err = h.SessionStore.Set(w, session)
	if err != nil {
		log.Printf("failed to set session: %v", err)
		URI := utils.BuildErrorRedirectURI(req.RedirectURI, string(ErrServerError), req.State)
		http.Redirect(w, r, URI, http.StatusFound)
		return
	}
	http.Redirect(w, r, "/login", http.StatusFound)
}

func (h *AuthHandler) Token(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	grantType := r.FormValue("grant_type")

	switch grantType {
	case "client_credentials":
		h.handleClientCredentials(w, r)
	case "authorization_code":
		h.handleAuthorizationCode(w, r)
	case "refresh_token":
		h.handleRefreshToken(w, r)
	case "password":
		h.handleROPC(w, r)
	default:
		CreateErrorResponse(w, http.StatusBadRequest, ErrUnsupportedGrantType)
	}
}

func (h *AuthHandler) handleROPC(w http.ResponseWriter, r *http.Request) {
	panic("unimplemented")
}

type RefreshTokenRequest struct {
	Token        string `schema:"refresh_token"`
	ClientID     string `schema:"client_id"`
	ClientSecret string `schema:"client_secret"`
}

func (h *AuthHandler) handleRefreshToken(w http.ResponseWriter, r *http.Request) {
	var req RefreshTokenRequest
	if err := h.Decoder.Decode(&req, r.Form); err != nil {
		CreateErrorResponse(w, http.StatusBadRequest, ErrInvalidRequest)
		return
	}

	refreshToken, err := h.RefreshTokenStore.VerifyToken(req.Token)
	if err != nil {
		log.Printf("invalid refresh token: %v", err)
		CreateErrorResponse(w, http.StatusUnauthorized, ErrInvalidGrant)
		return
	}

	client, err := h.ClientService.GetClientByID(r.Context(), req.ClientID)
	if err != nil {
		log.Printf("unrecognized client: %v", err)
		CreateErrorResponse(w, http.StatusUnauthorized, ErrInvalidClient)
		return
	}

	if client.ClientType == models.ClientTypeConfidential {
		err = h.ClientService.ValidateSecret(r.Context(), req.ClientID, req.ClientSecret)
		if err != nil {
			log.Printf("invalid client secret: %v", err)
			CreateErrorResponse(w, http.StatusUnauthorized, ErrInvalidClient)
			return
		}
	}

	if refreshToken.ClientID != req.ClientID {
		log.Printf("client_id mismatch for refresh token")
		CreateErrorResponse(w, http.StatusUnauthorized, ErrUnauthorizedClient)
		return
	}

	user, err := h.AuthService.GetUserByID(r.Context(), refreshToken.UserID)
	if err != nil {
		log.Printf("user not found for refresh token: %v", err)
		CreateErrorResponse(w, http.StatusUnauthorized, ErrInvalidGrant)
		return
	}

	token, err := h.TokenService.GenerateUserToken(user)
	if err != nil {
		log.Printf("failed to generate new access token: %v", err)
		CreateErrorResponse(w, http.StatusInternalServerError, ErrServerError)
		return
	}

	refreshToken, err = h.RefreshTokenStore.CreateRefreshToken(user.ID, client.ID, refreshToken.Scope, service.RefreshTokenExpiration)
	if err != nil {
		log.Printf("failed to create new refresh token: %v", err)
		CreateErrorResponse(w, http.StatusInternalServerError, ErrServerError)
		return
	}

	err = h.RefreshTokenStore.DeleteToken(req.Token)
	if err != nil {
		log.Printf("failed to delete refresh token: %v", err)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(TokenResponse{Token: token, Type: "Bearer", ExpiresIn: int64(service.TokenExpiration / time.Second), RefreshToken: refreshToken.Token, Scope: refreshToken.Scope})
}

type AuthorizationCodeTokenRequest struct {
	ClientID     string  `schema:"client_id"`
	ClientSecret string  `schema:"client_secret"`
	RedirectURI  string  `schema:"redirect_uri"`
	Code         string  `schema:"code"`
	CodeVerifier *string `schema:"code_verifier"`
}

type TokenResponse struct {
	Token        string `json:"access_token"`
	Type         string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

func (h *AuthHandler) handleAuthorizationCode(w http.ResponseWriter, r *http.Request) {
	var req AuthorizationCodeTokenRequest
	if err := h.Decoder.Decode(&req, r.Form); err != nil {
		CreateErrorResponse(w, http.StatusBadRequest, ErrInvalidRequest)
		return
	}
	client, err := h.ClientService.GetClientByID(r.Context(), req.ClientID)
	if err != nil {
		log.Printf("unrecognized client, error: %v", err)
		CreateErrorResponse(w, http.StatusUnauthorized, ErrInvalidClient)
		return
	}
	if client.ClientType == models.ClientTypeConfidential {
		err = h.ClientService.ValidateSecret(r.Context(), req.ClientID, req.ClientSecret)
		if err != nil {
			log.Printf("invalid client secret, error: %v", err)
			CreateErrorResponse(w, http.StatusUnauthorized, ErrInvalidClient)
			return
		}
	}
	code, err := h.CodeStore.VerifyCode(req.Code)
	if err != nil {
		log.Printf("invalid code, error: %v", err)
		CreateErrorResponse(w, http.StatusBadRequest, ErrInvalidGrant)
		return
	}
	if req.ClientID != code.ClientID {
		log.Printf("client_id mismatch, expected %s, got %s", code.ClientID, req.ClientID)
		CreateErrorResponse(w, http.StatusBadRequest, ErrInvalidGrant)
		return
	}
	if req.CodeVerifier == nil || !utils.ValidateCodeVerifier(*req.CodeVerifier) {
		log.Printf("invalid code_verifier")
		CreateErrorResponse(w, http.StatusBadRequest, ErrInvalidRequest)
		return
	}
	if code.CodeChallenge == "" || code.CodeChallengeMethod == "" {
		log.Printf("code_challenge or code_challenge_method missing in stored code")
		CreateErrorResponse(w, http.StatusInternalServerError, ErrServerError)
		return
	}
	if !crypto.VerifyCodeChallenge(*req.CodeVerifier, code.CodeChallenge, code.CodeChallengeMethod) {
		log.Printf("code_verifier does not match code_challenge")
		CreateErrorResponse(w, http.StatusBadRequest, ErrInvalidGrant)
		return
	}

	if req.RedirectURI != code.RedirectURI {
		log.Printf("redirect_uri mismatch, expected %s, got %s", code.RedirectURI, req.RedirectURI)
		CreateErrorResponse(w, http.StatusBadRequest, ErrInvalidGrant)
		return
	}
	user, err := h.AuthService.GetUserByID(r.Context(), code.UserID)
	if err != nil {
		log.Printf("user not found, error: %v", err)
		CreateErrorResponse(w, http.StatusBadRequest, ErrInvalidGrant)
		return
	}
	token, err := h.TokenService.GenerateUserToken(user)
	if err != nil {
		log.Printf("token generation error: %v", err)
		CreateErrorResponse(w, http.StatusInternalServerError, ErrServerError)
		return
	}
	refreshToken, err := h.RefreshTokenStore.CreateRefreshToken(user.ID, client.ID, code.Scope, service.RefreshTokenExpiration)
	if err != nil {
		log.Printf("failed to create refresh token: %v", err)
		CreateErrorResponse(w, http.StatusInternalServerError, ErrServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(TokenResponse{Token: token, Type: "Bearer", ExpiresIn: int64(service.TokenExpiration / time.Second), RefreshToken: refreshToken.Token, Scope: code.Scope})
}

type ClientCredentialsTokenRequest struct {
	ClientID     string `schema:"client_id"`
	ClientSecret string `schema:"client_secret"`
}

func (h *AuthHandler) handleClientCredentials(w http.ResponseWriter, r *http.Request) {
	var req ClientCredentialsTokenRequest
	if err := h.Decoder.Decode(&req, r.Form); err != nil {
		CreateErrorResponse(w, http.StatusBadRequest, ErrInvalidRequest)
		return
	}
	client, err := h.ClientService.GetClientByID(r.Context(), req.ClientID)
	if err != nil {
		log.Printf("unrecognized client, error: %v", err)
		CreateErrorResponse(w, http.StatusUnauthorized, ErrInvalidClient)
		return
	}
	if client.ClientType != models.ClientTypeConfidential {
		log.Printf("client is not confidential")
		CreateErrorResponse(w, http.StatusUnauthorized, ErrInvalidClient)
		return
	}
	err = h.ClientService.ValidateSecret(r.Context(), req.ClientID, req.ClientSecret)
	if err != nil {
		log.Printf("invalid client secret, error: %v", err)
		CreateErrorResponse(w, http.StatusUnauthorized, ErrInvalidClient)
		return
	}
	token, err := h.TokenService.GenerateClientToken(client.ID)
	if err != nil {
		log.Printf("token generation error: %v", err)
		CreateErrorResponse(w, http.StatusInternalServerError, ErrServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(TokenResponse{Token: token, Type: "Bearer", ExpiresIn: int64(service.TokenExpiration / time.Second)})
}
