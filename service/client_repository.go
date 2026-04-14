package service

import (
	"context"

	"github.com/yourname/iam-platform/models"
)

type ClientRepository interface {
	Create(ctx context.Context, client *models.Client) error
	FindByID(ctx context.Context, id string) (*models.Client, error)
	Delete(ctx context.Context, id string) error
	Update(ctx context.Context, id string, redirectURIs []string) error
}
