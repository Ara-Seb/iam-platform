package handler

import (
	"encoding/json"
	"net/http"

	"github.com/yourname/iam-platform/models"
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
