package service

import (
	"context"
	"fmt"

	"github.com/yourname/iam-platform/crypto"
	"github.com/yourname/iam-platform/models"
	"golang.org/x/crypto/bcrypt"
)

type ClientRepository interface {
	Create(ctx context.Context, client *models.Client) error
	FindByID(ctx context.Context, id string) (*models.Client, error)
	Delete(ctx context.Context, id string) error
	Update(ctx context.Context, id string, redirectURIs []string) error
}

type ClientService struct {
	ClientRepo ClientRepository
}

func NewClientService(clientRepo ClientRepository) *ClientService {
	return &ClientService{
		ClientRepo: clientRepo,
	}
}

func (s *ClientService) RegisterClient(ctx context.Context, clientType models.ClientType, redirectURIs []string, ownerID string) (*models.Client, string, error) {
	var hash []byte
	var secret string
	if clientType == models.ClientTypeConfidential {
		var err error
		secret, err = crypto.GenerateRandomToken()
		if err != nil {
			return nil, "", fmt.Errorf("failed to generate secret: %w", err)
		}
		hash, err = bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
		if err != nil {
			return nil, "", fmt.Errorf("failed to hash secret: %w", err)
		}
	}

	client := &models.Client{SecretHash: string(hash), ClientType: clientType, RedirectURIs: redirectURIs, OwnerID: ownerID}
	err := s.ClientRepo.Create(ctx, client)
	if err != nil {
		return nil, "", err
	}
	return client, secret, nil
}

func (s *ClientService) GetClientByID(ctx context.Context, id string) (*models.Client, error) {
	return s.ClientRepo.FindByID(ctx, id)
}

func (s *ClientService) DeleteClient(ctx context.Context, id string) error {
	return s.ClientRepo.Delete(ctx, id)
}

func (s *ClientService) UpdateClient(ctx context.Context, id string, redirectURIs []string) error {
	return s.ClientRepo.Update(ctx, id, redirectURIs)
}
