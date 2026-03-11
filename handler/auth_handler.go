package handler

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"

	"github.com/yourname/iam-platform/repository"
	"github.com/yourname/iam-platform/service"
)

type AuthHandler struct {
	ClientRepo  *repository.ClientRepository
	AuthService *service.AuthService
}

func NewAuthHandler(clientRepo *repository.ClientRepository, authService *service.AuthService) *AuthHandler {
	return &AuthHandler{
		ClientRepo:  clientRepo,
		AuthService: authService,
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

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	token, err := h.AuthService.Login(r.Context(), req.Email, req.Password)
	if err != nil {
		if errors.Is(err, service.ErrInvalidCredentials) {
			http.Error(w, "invalid credentials", http.StatusUnauthorized)
			return
		}
		log.Printf("login error: %v", err)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(LoginResponse{Token: token})
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
