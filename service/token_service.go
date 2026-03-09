package service

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/yourname/iam-platform/keys"
	"github.com/yourname/iam-platform/models"
)

type TokenService struct {
	keys *keys.Keys
}

func NewTokenService(keys *keys.Keys) *TokenService {
	return &TokenService{keys: keys}
}

func (s *TokenService) GenerateToken(user models.User) (string, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"jti":   uuid.New().String(),
		"sub":   user.ID,
		"email": user.Email,
		"role":  user.Role,
		"iss":   "iam-platform",
		"iat":   now.Unix(),
		"exp":   now.Add(24 * time.Hour).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(s.keys.Private)
}

func (s *TokenService) ValidateToken(tokenStr string) (*jwt.Token, error) {
	return jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return s.keys.Public, nil
	})
}
