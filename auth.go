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
	UserIDKey   contextKey = "user_id"
	UserTypeKey contextKey = "user_type"
	ClientIDKey contextKey = "client_id"
	ScopesKey   contextKey = "scopes"
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
	Scopes   []string `json:"scopes"`
	ClientID string   `json:"client_id"`
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
		var validToken *jwt.Token
		var detectedType string

		for keyType, pubKey := range m.publicKeys {
			token, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (interface{}, error) {
				return pubKey, nil
			})
			if err == nil && token.Valid {
				validToken = token
				detectedType = keyType
				break
			}
		}

		if validToken == nil {
			http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
			return
		}

		if m.checker != nil && m.checker.IsRevoked(r.Context(), claims.ID) {
			http.Error(w, "Token has been revoked", http.StatusUnauthorized)
			return
		}

		ctx := r.Context()
		ctx = context.WithValue(ctx, UserIDKey, claims.Subject)
		ctx = context.WithValue(ctx, UserTypeKey, detectedType)
		ctx = context.WithValue(ctx, ClientIDKey, claims.ClientID)
		ctx = context.WithValue(ctx, ScopesKey, claims.Scopes)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func GetUserID(ctx context.Context) string {
	id, _ := ctx.Value(UserIDKey).(string)
	return id
}

func GetUserType(ctx context.Context) string {
	uType, _ := ctx.Value(UserTypeKey).(string)
	return uType
}

func GetClientID(ctx context.Context) string {
	id, _ := ctx.Value(ClientIDKey).(string)
	return id
}

func HasScope(ctx context.Context, scope string) bool {
	scopes, _ := ctx.Value(ScopesKey).([]string)
	for _, s := range scopes {
		if s == scope {
			return true
		}
	}
	return false
}

func Only(allowedTypes ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			currentType := GetUserType(r.Context())
			for _, t := range allowedTypes {
				if t == currentType {
					next.ServeHTTP(w, r)
					return
				}
			}
			http.Error(w, "Access denied for this user type", http.StatusForbidden)
		})
	}
}