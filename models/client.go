package models

import "time"

type Client struct {
	ID           string    `json:"id"`
	SecretHash   string    `json:"-"`
	ClientType   string    `json:"client_type"`
	RedirectURIs []string  `json:"redirect_uris"`
	CreatedAt    time.Time `json:"created_at"`
}
