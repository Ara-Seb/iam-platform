package service

import (
	"context"

	"github.com/yourname/iam-platform/models"
	"golang.org/x/crypto/bcrypt"
)

type MockClientRepository struct {
	SecretHash            string
	CreateFunc            func(ctx context.Context, client *models.Client, secretHash string) error
	FindByIDFunc          func(ctx context.Context, id string) (*models.Client, error)
	DeleteFunc            func(ctx context.Context, id string) error
	UpdateFunc            func(ctx context.Context, id string, redirectURIs []string) error
	GetSecretHashByIDFunc func(ctx context.Context, id string) (string, error)
}

func (m *MockClientRepository) Create(ctx context.Context, client *models.Client, secretHash string) error {
	m.SecretHash = secretHash
	if m.CreateFunc == nil {
		return nil
	}
	return m.CreateFunc(ctx, client, secretHash)
}

func (m *MockClientRepository) FindByID(ctx context.Context, id string) (*models.Client, error) {
	if m.FindByIDFunc == nil {
		return nil, nil
	}
	return m.FindByIDFunc(ctx, id)
}

func (m *MockClientRepository) Delete(ctx context.Context, id string) error {
	if m.DeleteFunc == nil {
		return nil
	}
	return m.DeleteFunc(ctx, id)
}

func (m *MockClientRepository) Update(ctx context.Context, id string, redirectURIs []string) error {
	if m.UpdateFunc == nil {
		return nil
	}
	return m.UpdateFunc(ctx, id, redirectURIs)
}

type MockUserRepository struct {
	CreateFunc      func(ctx context.Context, user *models.User) error
	FindByEmailFunc func(ctx context.Context, email string) (*models.User, error)
	FindByIDFunc    func(ctx context.Context, id string) (*models.User, error)
}

func (m *MockUserRepository) Create(ctx context.Context, user *models.User) error {
	if m.CreateFunc == nil {
		return nil
	}
	return m.CreateFunc(ctx, user)
}

func (m *MockUserRepository) FindByEmail(ctx context.Context, email string) (*models.User, error) {
	if m.FindByEmailFunc == nil {
		return nil, nil
	}
	return m.FindByEmailFunc(ctx, email)
}

func (m *MockUserRepository) FindByID(ctx context.Context, id string) (*models.User, error) {
	if m.FindByIDFunc == nil {
		return nil, nil
	}
	return m.FindByIDFunc(ctx, id)
}

func (m *MockClientRepository) GetSecretHashByID(ctx context.Context, id string) (string, error) {
	if m.GetSecretHashByIDFunc == nil {
		hash, _ := bcrypt.GenerateFromPassword([]byte("correctsecret"), bcrypt.DefaultCost)
		return string(hash), nil
	}
	return m.GetSecretHashByIDFunc(ctx, id)
}
