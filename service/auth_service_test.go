package service

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/yourname/iam-platform/models"
	"github.com/yourname/iam-platform/repository"
)

func TestLogin_UserNotFound(t *testing.T) {
	mockRepo := &MockUserRepository{
		FindByEmailFunc: func(ctx context.Context, email string) (*models.User, error) {
			return nil, repository.ErrNotFound
		},
	}
	service := NewAuthService(mockRepo, nil)
	_, _, err := service.Login(context.Background(), "nonexistent@example.com", "password")
	assert.ErrorIs(t, err, ErrInvalidCredentials)
}
