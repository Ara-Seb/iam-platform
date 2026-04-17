package service

import (
	"context"
	"errors"
	"fmt"

	"github.com/yourname/iam-platform/models"
	"github.com/yourname/iam-platform/repository"
	"golang.org/x/crypto/bcrypt"
)

type UserRepository interface {
	Create(ctx context.Context, user *models.User) error
	FindByEmail(ctx context.Context, email string) (*models.User, error)
}

type AuthService struct {
	UserRepo     UserRepository
	TokenService *TokenService
}

func NewAuthService(userRepo UserRepository, tokenService *TokenService) *AuthService {
	return &AuthService{
		UserRepo:     userRepo,
		TokenService: tokenService,
	}
}

func (s *AuthService) Register(ctx context.Context, email string, password string) (*models.User, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	user := models.User{Email: email, PasswordHash: string(hash)}
	err = s.UserRepo.Create(ctx, &user)
	if err != nil {
		if errors.Is(err, repository.ErrEmailAlreadyExists) {
			return nil, ErrEmailAlreadyExists
		}
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	return &user, nil
}

func (s *AuthService) Login(ctx context.Context, email string, password string) (string, *models.User, error) {
	user, err := s.UserRepo.FindByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return "", nil, ErrInvalidCredentials
		}
		return "", nil, fmt.Errorf("server error: %w", err)
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return "", nil, ErrInvalidCredentials
	}
	token, err := s.TokenService.GenerateToken(*user)
	return token, user, err
}
