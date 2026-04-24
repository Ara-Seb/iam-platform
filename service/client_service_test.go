package service

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/yourname/iam-platform/models"
	"golang.org/x/crypto/bcrypt"
)

func TestRegisterClient_Confidential(t *testing.T) {
	mockClientRepo := &MockClientRepository{}
	service := NewClientService(mockClientRepo)
	_, secret, err := service.RegisterClient(context.Background(), models.ClientTypeConfidential, []string{"https://example.com/callback"}, "owner-id")
	assert.NoError(t, err)
	assert.NotEmpty(t, secret)
	assert.NoError(t, bcrypt.CompareHashAndPassword([]byte(mockClientRepo.SecretHash), []byte(secret)))
}

func TestRegisterClient_Public(t *testing.T) {
	mockClientRepo := &MockClientRepository{}
	service := NewClientService(mockClientRepo)
	_, secret, err := service.RegisterClient(context.Background(), models.ClientTypePublic, []string{"https://example.com/callback"}, "owner-id")
	assert.NoError(t, err)
	assert.Empty(t, secret)
	assert.Empty(t, mockClientRepo.SecretHash)
}

func TestRepoFailure(t *testing.T) {
	mockRepo := &MockClientRepository{
		CreateFunc: func(ctx context.Context, client *models.Client, secretHash string) error {
			return fmt.Errorf("db error")
		},
	}
	service := NewClientService(mockRepo)
	client, secret, err := service.RegisterClient(context.Background(), models.ClientTypeConfidential, []string{"https://example.com/callback"}, "owner-id")
	assert.Nil(t, client)
	assert.Empty(t, secret)
	assert.Error(t, err)
}

func TestValidateSecret_InvalidSecret(t *testing.T) {
	service := NewClientService(&MockClientRepository{})
	err := service.ValidateSecret(context.Background(), "client-id", "wrongsecret")
	assert.ErrorIs(t, err, ErrInvalidClientSecret)
}

func TestValidateSecret_Success(t *testing.T) {
	service := NewClientService(&MockClientRepository{})
	err := service.ValidateSecret(context.Background(), "client-id", "correctsecret")
	assert.NoError(t, err)
}
