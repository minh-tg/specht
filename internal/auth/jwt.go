package auth

import (
	"context"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type JWTAuthenticator struct {
	secret []byte
}

func NewJWTAuthenticator(secret string) (*JWTAuthenticator, error) {
	if secret == "" {
		return nil, fmt.Errorf("JWT_SECRET is required")
	}
	if secret == "dev-only-change-me" {
		return nil, fmt.Errorf("JWT_SECRET must not be the default value")
	}
	return &JWTAuthenticator{secret: []byte(secret)}, nil
}

func (a *JWTAuthenticator) CreateToken(userID, email string) (string, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"sub":   userID,
		"email": email,
		"iat":   now.Unix(),
		"exp":   now.Add(15 * time.Minute).Unix(),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return tok.SignedString(a.secret)
}

func (a *JWTAuthenticator) CreateRefreshToken(userID string) (string, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"sub":   userID,
		"type":  "refresh",
		"iat":   now.Unix(),
		"exp":   now.Add(7 * 24 * time.Hour).Unix(),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return tok.SignedString(a.secret)
}

func (a *JWTAuthenticator) Authenticate(ctx context.Context, token string) (*Identity, error) {
	tok, err := jwt.Parse(token, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return a.secret, nil
	})
	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}
	claims, ok := tok.Claims.(jwt.MapClaims)
	if !ok || !tok.Valid {
		return nil, fmt.Errorf("invalid token claims")
	}

	if tokenType, _ := claims["type"].(string); tokenType == "refresh" {
		return nil, fmt.Errorf("refresh tokens are not accepted for authentication")
	}

	sub, _ := claims.GetSubject()
	email, _ := claims["email"].(string)
	return &Identity{UserID: sub, Email: email}, nil
}
