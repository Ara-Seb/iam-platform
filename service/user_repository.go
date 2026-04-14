package service

import (
	"context"

	"github.com/yourname/iam-platform/models"
)

type UserRepository interface {
	Create(ctx context.Context, user *models.User) error
	FindByEmail(ctx context.Context, email string) (*models.User, error)
}
