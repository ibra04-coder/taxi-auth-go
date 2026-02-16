package auth

import (
	"context"
	"crypto/rsa"
	"fmt"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/redis/go-redis/v9"
)

type contextKey string

const (
	UserIDKey contextKey = "user_id"
	ScopesKey contextKey = "scopes"
)

type RevocationChecker interface {
	IsRevoked(ctx context.Context, jti string) bool
}

type RedisChecker struct {
	client *redis.Client
	prefix string
}

func NewRedisChecker(client *redis.Client, prefix string) *RedisChecker {
	return &RedisChecker{client: client, prefix: prefix}
}

func (r *RedisChecker) IsRevoked(ctx context.Context, jti string) bool {
	if r == nil || r.client == nil || jti == "" {
		return false
	}
	val, err := r.client.Exists(ctx, r.prefix+jti).Result()
	return err == nil && val > 0
}

type CustomClaims struct {
	Scopes []string `json:"scopes"`
	jwt.RegisteredClaims
}

type AuthMiddleware struct {
	publicKeys map[string]*rsa.PublicKey
	checker    RevocationChecker
}

func NewAuthMiddleware(keys map[string]string, checker RevocationChecker) (*AuthMiddleware, error) {
	parsedKeys := make(map[string]*rsa.PublicKey)

	for name, pemStr := range keys {
		pubKey, err := jwt.ParseRSAPublicKeyFromPEM([]byte(pemStr))
		if err != nil {
			return nil, fmt.Errorf("failed to parse public key [%s]: %w", name, err)
		}
		parsedKeys[name] = pubKey
	}

	return &AuthMiddleware{
		publicKeys: parsedKeys,
		checker:    checker,
	}, nil
}

func (m *AuthMiddleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Authorization header required", http.StatusUnauthorized)
			return
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			http.Error(w, "Invalid auth header format", http.StatusUnauthorized)
			return
		}

		tokenString := parts[1]
		claims := &CustomClaims{}
		var token *jwt.Token
		var err error

		valid := false
		for _, pubKey := range m.publicKeys {
			token, err = jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (interface{}, error) {
				return pubKey, nil
			})
			if err == nil && token.Valid {
				valid = true
				break
			}
		}

		if !valid {
			http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
			return
		}

		if m.checker != nil && m.checker.IsRevoked(r.Context(), claims.ID) {
			http.Error(w, "Token has been revoked", http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), UserIDKey, claims.Subject)
		ctx = context.WithValue(ctx, ScopesKey, claims.Scopes)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func GetUserID(ctx context.Context) string {
	if id, ok := ctx.Value(UserIDKey).(string); ok {
		return id
	}
	return ""
}

func GetScopes(ctx context.Context) []string {
	if scopes, ok := ctx.Value(ScopesKey).([]string); ok {
		return scopes
	}
	return []string{}
}

func HasScope(ctx context.Context, required string) bool {
	scopes := GetScopes(ctx)
	for _, s := range scopes {
		if s == required {
			return true
		}
	}
	return false
}