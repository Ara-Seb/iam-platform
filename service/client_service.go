package service

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"github.com/yourname/iam-platform/models"
	"github.com/yourname/iam-platform/repository"
	"golang.org/x/crypto/bcrypt"
)

type ClientService struct {
	ClientRepo *repository.ClientRepository
}

func NewClientService(clientRepo *repository.ClientRepository) *ClientService {
	return &ClientService{
		ClientRepo: clientRepo,
	}
}

func (s *ClientService) RegisterClient(ctx context.Context, clientType models.ClientType, redirectURIs []string) (*models.Client, string, error) {
	var hash []byte
	var plaintext string
	if clientType == models.ClientTypeConfidential {
		secret := make([]byte, 32)
		_, err := rand.Read(secret)
		if err != nil {
			return nil, "", fmt.Errorf("failed to generate secret: %w", err)
		}
		plaintext = base64.URLEncoding.EncodeToString(secret)
		hash, err = bcrypt.GenerateFromPassword([]byte(plaintext), bcrypt.DefaultCost)
		if err != nil {
			return nil, "", fmt.Errorf("failed to hash secret: %w", err)
		}
	}

	client := &models.Client{SecretHash: string(hash), ClientType: clientType, RedirectURIs: redirectURIs}
	err := s.ClientRepo.Create(ctx, client)
	if err != nil {
		return nil, "", err
	}
	return client, plaintext, nil
}
