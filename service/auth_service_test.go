package service

import (
	"context"
	"errors"
	"testing"

	"github.com/yourname/iam-platform/models"
	"github.com/yourname/iam-platform/repository"
)

type MockUserRepository struct {
	CreateFunc      func(ctx context.Context, user *models.User) error
	FindByEmailFunc func(ctx context.Context, email string) (*models.User, error)
}

func (m *MockUserRepository) Create(ctx context.Context, user *models.User) error {
	return m.CreateFunc(ctx, user)
}

func (m *MockUserRepository) FindByEmail(ctx context.Context, email string) (*models.User, error) {
	return m.FindByEmailFunc(ctx, email)
}

func TestLogin_UserNotFound(t *testing.T) {
	mockRepo := &MockUserRepository{
		FindByEmailFunc: func(ctx context.Context, email string) (*models.User, error) {
			return nil, repository.ErrNotFound
		},
	}
	service := NewAuthService(mockRepo, nil)

	_, err := service.Login(context.Background(), "nonexistent@example.com", "password")
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("expected ErrInvalidCredentials, got %v", err)
	}
}
