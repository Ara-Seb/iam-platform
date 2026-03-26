package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/yourname/iam-platform/models"
	"github.com/yourname/iam-platform/repository"
	"github.com/yourname/iam-platform/service"
)

type ClientHandler struct {
	ClientService *service.ClientService
}

func NewClientHandler(clientService *service.ClientService) *ClientHandler {
	return &ClientHandler{
		ClientService: clientService,
	}
}

type RegisterClientRequest struct {
	ClientType   string   `json:"client_type"`
	RedirectURIs []string `json:"redirect_uris"`
}

type RegisterClientResponse struct {
	ID           string            `json:"id"`
	ClientType   models.ClientType `json:"client_type"`
	RedirectURIs []string          `json:"redirect_uris"`
	Secret       string            `json:"secret,omitempty"`
}

func (h *ClientHandler) RegisterClient(w http.ResponseWriter, r *http.Request) {
	var req RegisterClientRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	clientType := models.ClientType(req.ClientType)
	if clientType != models.ClientTypeConfidential && clientType != models.ClientTypePublic {
		http.Error(w, "invalid client type", http.StatusBadRequest)
		return
	}

	if len(req.RedirectURIs) == 0 {
		http.Error(w, "at least one redirect URI required", http.StatusBadRequest)
		return
	}

	client, secret, err := h.ClientService.RegisterClient(r.Context(), clientType, req.RedirectURIs)
	if err != nil {
		http.Error(w, "failed to register client", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(RegisterClientResponse{
		ID:           client.ID,
		ClientType:   client.ClientType,
		RedirectURIs: client.RedirectURIs,
		Secret:       secret,
	})
}

type GetClientResponse struct {
	ID           string            `json:"id"`
	ClientType   models.ClientType `json:"client_type"`
	RedirectURIs []string          `json:"redirect_uris"`
	CreatedAt    time.Time         `json:"created_at"`
}

func (h *ClientHandler) GetClient(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	client, err := h.ClientService.GetClientByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			http.Error(w, "client not found", http.StatusNotFound)
			return
		}
		http.Error(w, "failed to get client", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(GetClientResponse{
		ID:           client.ID,
		ClientType:   client.ClientType,
		RedirectURIs: client.RedirectURIs,
		CreatedAt:    client.CreatedAt,
	})
}

func (h *ClientHandler) DeleteClient(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	err := h.ClientService.DeleteClient(r.Context(), id)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			http.Error(w, "client not found", http.StatusNotFound)
			return
		}
		http.Error(w, "failed to delete client", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
