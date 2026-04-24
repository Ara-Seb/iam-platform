package models

import "time"

type ClientType string

const (
	ClientTypeConfidential ClientType = "confidential"
	ClientTypePublic       ClientType = "public"
)

type Client struct {
	ID           string     `json:"id"`
	ClientType   ClientType `json:"client_type"`
	RedirectURIs []string   `json:"redirect_uris"`
	OwnerID      string     `json:"owner_id"`
	CreatedAt    time.Time  `json:"created_at"`
}
