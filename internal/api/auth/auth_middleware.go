package auth

import (
	"context"
	"net/http"
	"strings"

	"github.com/google/uuid"
)

type ctxKey string

const ctxKeyUser ctxKey = "user"

type UserContext struct {
	UserID		uuid.UUID
	Roles		[]string
}

// extracts the token from header Authorization: Bearer <token>, validates and injects in the context
func AuthMiddleware(s *AuthService) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := r.Header.Get("Authorization")
			if h == "" {
				http.Error(w, "missing auth header", http.StatusUnauthorized)
				return 
			}
			parts := strings.SplitN(h, " ", 2)
			if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
				http.Error(w, "invalid auth header", http.StatusUnauthorized)
				return 
			}

			tokenStr := parts[1]
			claims, err := s.ParseJWT(tokenStr)
			if err != nil {
				http.Error(w, "invalid token: "+err.Error(), http.StatusUnauthorized)
				return
			}

			roles := claims.Roles

			uc := &UserContext{
				UserID: claims.UserID,
				Roles: roles,
			}
			ctx := context.WithValue(r.Context(), ctxKeyUser, uc)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// verifies if user in ctx has the required role
func RequireRole(role string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			uc, ok := r.Context().Value(ctxKeyUser).(*UserContext)
			if !ok || uc == nil {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			for _, rname := range uc.Roles {
				if rname == role {
					next.ServeHTTP(w, r)
					return
				}
			}
			http.Error(w, "forbidden", http.StatusForbidden)
		})
	}
}