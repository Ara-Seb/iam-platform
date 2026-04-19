package handler

import (
	"context"
	"net/http"

	"github.com/yourname/iam-platform/models"
	"github.com/yourname/iam-platform/session"
	"github.com/yourname/iam-platform/store"
)

type MockClientService struct {
	GetClientByIDFunc func(ctx context.Context, id string) (*models.Client, error)
}

func (m *MockClientService) GetClientByID(ctx context.Context, id string) (*models.Client, error) {
	if m.GetClientByIDFunc == nil {
		return nil, nil
	}
	return m.GetClientByIDFunc(ctx, id)
}

func GetHappyClientService() *MockClientService {
	return &MockClientService{
		GetClientByIDFunc: func(ctx context.Context, id string) (*models.Client, error) {
			return &models.Client{
				ID:           "abc123",
				RedirectURIs: []string{"https://example.com/callback"},
			}, nil
		},
	}
}

type MockAuthService struct {
	RegisterFunc func(ctx context.Context, email, password string) (*models.User, error)
	LoginFunc    func(ctx context.Context, email, password string) (string, *models.User, error)
}

func (m *MockAuthService) Register(ctx context.Context, email, password string) (*models.User, error) {
	if m.RegisterFunc == nil {
		return nil, nil
	}
	return m.RegisterFunc(ctx, email, password)
}

func (m *MockAuthService) Login(ctx context.Context, email, password string) (string, *models.User, error) {
	if m.LoginFunc == nil {
		return "", nil, nil
	}
	return m.LoginFunc(ctx, email, password)
}

func GetHappyAuthService() *MockAuthService {
	return &MockAuthService{
		RegisterFunc: func(ctx context.Context, email, password string) (*models.User, error) {
			return &models.User{ID: "123", Email: email}, nil
		},
		LoginFunc: func(ctx context.Context, email, password string) (string, *models.User, error) {
			return "token123", &models.User{ID: "123", Email: email}, nil
		},
	}
}

type MockSessionStore struct {
	SetCalled bool
	SetFunc   func(w http.ResponseWriter, session *session.AuthorizationSession) error
	GetFunc   func(r *http.Request) (*session.AuthorizationSession, error)
	ClearFunc func(w http.ResponseWriter)
}

func (m *MockSessionStore) Set(w http.ResponseWriter, session *session.AuthorizationSession) error {
	m.SetCalled = true
	if m.SetFunc == nil {
		return nil
	}
	return m.SetFunc(w, session)
}

func (m *MockSessionStore) Get(r *http.Request) (*session.AuthorizationSession, error) {
	if m.GetFunc == nil {
		return nil, nil
	}
	return m.GetFunc(r)
}

func (m *MockSessionStore) Clear(w http.ResponseWriter) {
	if m.ClearFunc == nil {
		return
	}
	m.ClearFunc(w)
}

type MockCodeStore struct {
	CreateCodeFunc func(clientID, userID, redirectURI, scope, state string) (*store.AuthorizationCode, error)
}

func (m *MockCodeStore) CreateCode(clientID, userID, redirectURI, scope, state string) (*store.AuthorizationCode, error) {
	if m.CreateCodeFunc == nil {
		return nil, nil
	}
	return m.CreateCodeFunc(clientID, userID, redirectURI, scope, state)
}
