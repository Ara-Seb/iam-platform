package handler

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"

	"github.com/gorilla/schema"
	"github.com/yourname/iam-platform/models"
	"github.com/yourname/iam-platform/service"
	"github.com/yourname/iam-platform/session"
	"github.com/yourname/iam-platform/store"
	"github.com/yourname/iam-platform/utils"
)

type ClientService interface {
	GetClientByID(ctx context.Context, id string) (*models.Client, error)
}

type AuthService interface {
	Register(ctx context.Context, email, password string) (*models.User, error)
	Login(ctx context.Context, email, password string) (string, *models.User, error)
}

type SessionStore interface {
	Set(w http.ResponseWriter, session *session.AuthorizationSession) error
	Get(r *http.Request) (*session.AuthorizationSession, error)
	Clear(w http.ResponseWriter)
}

type CodeStore interface {
	CreateCode(clientID, userID, redirectURI, scope, state string) (*store.AuthorizationCode, error)
}

type AuthHandler struct {
	ClientService ClientService
	AuthService   AuthService
	SessionStore  SessionStore
	CodeStore     CodeStore
	Decoder       *schema.Decoder
}

func NewAuthHandler(clientService ClientService, authService AuthService, sessionStore SessionStore, codeStore CodeStore) *AuthHandler {
	decoder := schema.NewDecoder()
	decoder.IgnoreUnknownKeys(true)
	return &AuthHandler{
		ClientService: clientService,
		AuthService:   authService,
		SessionStore:  sessionStore,
		CodeStore:     codeStore,
		Decoder:       decoder,
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
		code, err := h.CodeStore.CreateCode(cookie.ClientID, user.ID, cookie.RedirectURI, cookie.Scope, cookie.State)
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
	ResponseType string `schema:"response_type"`
	ClientId     string `schema:"client_id"`
	RedirectURI  string `schema:"redirect_uri"`
	Scope        string `schema:"scope"`
	State        string `schema:"state"`
}

func (h *AuthHandler) Authorize(w http.ResponseWriter, r *http.Request) {
	var req AuthorizeRequest
	if err := h.Decoder.Decode(&req, r.URL.Query()); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	if req.ClientId == "" || req.RedirectURI == "" || req.Scope == "" || req.State == "" {
		http.Error(w, "missing required parameters", http.StatusBadRequest)
		return
	}
	if req.ResponseType != "code" {
		http.Error(w, "unsupported response_type", http.StatusBadRequest)
		return
	}
	client, err := h.ClientService.GetClientByID(r.Context(), req.ClientId)
	if err != nil {
		http.Error(w, "unrecognized client_id", http.StatusUnauthorized)
		return
	}
	if !utils.Contains(client.RedirectURIs, req.RedirectURI) {
		http.Error(w, "invalid redirect_uri", http.StatusUnauthorized)
		return
	}
	session := &session.AuthorizationSession{
		ClientID:    req.ClientId,
		RedirectURI: req.RedirectURI,
		Scope:       req.Scope,
		State:       req.State,
	}
	err = h.SessionStore.Set(w, session)
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
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
		// return OAuth2 error response
	}
}

func (h *AuthHandler) handleROPC(w http.ResponseWriter, r *http.Request) {
	panic("unimplemented")
}

func (h *AuthHandler) handleRefreshToken(w http.ResponseWriter, r *http.Request) {
	panic("unimplemented")
}

func (h *AuthHandler) handleAuthorizationCode(w http.ResponseWriter, r *http.Request) {
	panic("unimplemented")
}

func (h *AuthHandler) handleClientCredentials(w http.ResponseWriter, r *http.Request) {
	panic("unimplemented")
}
