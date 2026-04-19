package service

import (
	"context"
	"errors"
	"testing"

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
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("expected ErrInvalidCredentials, got %v", err)
	}
}
