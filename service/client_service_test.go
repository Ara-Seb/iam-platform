package service

import (
	"context"
	"fmt"
	"testing"

	"github.com/yourname/iam-platform/models"
	"golang.org/x/crypto/bcrypt"
)

func TestRegisterClient_Confidential(t *testing.T) {
	service := NewClientService(&MockClientRepository{})

	client, secret, err := service.RegisterClient(context.Background(), models.ClientTypeConfidential, []string{"https://example.com/callback"}, "owner-id")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if secret == "" {
		t.Error("expected secret to be generated for confidential client")
	}
	err = bcrypt.CompareHashAndPassword([]byte(client.SecretHash), []byte(secret))
	if err != nil {
		t.Error("expected secret to match stored hash")
	}
}

func TestRegisterClient_Public(t *testing.T) {
	service := NewClientService(&MockClientRepository{})

	client, secret, err := service.RegisterClient(context.Background(), models.ClientTypePublic, []string{"https://example.com/callback"}, "owner-id")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if secret != "" {
		t.Error("expected no secret to be generated for public client")
	}
	if client.SecretHash != "" {
		t.Error("expected hashed secret to be empty for public client")
	}
}

func TestRepoFailure(t *testing.T) {
	mockRepo := &MockClientRepository{
		CreateFunc: func(ctx context.Context, client *models.Client) error {
			return fmt.Errorf("db error")
		},
	}
	service := NewClientService(mockRepo)

	client, secret, err := service.RegisterClient(context.Background(), models.ClientTypeConfidential, []string{"https://example.com/callback"}, "owner-id")
	if client != nil {
		t.Fatalf("expected client to be nil, got %v", client)
	}
	if secret != "" {
		t.Errorf("expected secret to be empty, got %v", secret)
	}
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}
