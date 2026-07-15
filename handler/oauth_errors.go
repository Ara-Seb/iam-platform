package handler

import (
	"encoding/json"
	"net/http"
)

type OAuthErrorResponse string

const (
	ErrInvalidRequest          OAuthErrorResponse = "invalid_request"
	ErrInvalidClient           OAuthErrorResponse = "invalid_client"
	ErrInvalidGrant            OAuthErrorResponse = "invalid_grant"
	ErrUnauthorizedClient      OAuthErrorResponse = "unauthorized_client"
	ErrUnsupportedGrantType    OAuthErrorResponse = "unsupported_grant_type"
	ErrUnsupportedResponseType OAuthErrorResponse = "unsupported_response_type"
	ErrInvalidScope            OAuthErrorResponse = "invalid_scope"
	ErrServerError             OAuthErrorResponse = "server_error"
)

func CreateErrorResponse(w http.ResponseWriter, statusCode int, message OAuthErrorResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(map[string]string{"error": string(message)})
}
