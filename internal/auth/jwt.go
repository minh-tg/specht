package auth

import (
	"context"
	"fmt"
	"os"

	"github.com/golang-jwt/jwt/v5"
)

type JWTAuthenticator struct {
	secret []byte
}

func NewJWTAuthenticator() (*JWTAuthenticator, error) {
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		return nil, fmt.Errorf("JWT_SECRET is required")
	}
	if secret == "dev-only-change-me" {
		return nil, fmt.Errorf("JWT_SECRET must not be the default value")
	}
	return &JWTAuthenticator{secret: []byte(secret)}, nil
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
	sub, _ := claims.GetSubject()
	email, _ := claims["email"].(string)
	return &Identity{UserID: sub, Email: email}, nil
}
