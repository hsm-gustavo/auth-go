package auth

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/hsm-gustavo/auth-go/internal/db"
)

type contextKey string

const ClaimsContextKey contextKey = "claims"

// AuthMiddleware creates a middleware for JWT authentication
func (h *AuthHandler) AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			h.sendErrorResponse(w, http.StatusUnauthorized, "unauthorized", "Missing authorization header")
			return
		}

		bearerToken := strings.Split(authHeader, " ")
		if len(bearerToken) != 2 || bearerToken[0] != "Bearer" {
			h.sendErrorResponse(w, http.StatusUnauthorized, "unauthorized", "Invalid authorization header format")
			return
		}

		claims, err := h.service.ParseJWT(bearerToken[1])
		if err != nil {
			h.sendErrorResponse(w, http.StatusUnauthorized, "unauthorized", "Invalid or expired token")
			return
		}

		// Add claims to request context
		ctx := context.WithValue(r.Context(), ClaimsContextKey, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// AdminMiddleware ensures the user has admin role
func (h *AuthHandler) AdminMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, ok := r.Context().Value(ClaimsContextKey).(*db.Claims)
		if !ok {
			h.sendErrorResponse(w, http.StatusUnauthorized, "unauthorized", "Authentication required")
			return
		}

		// Check if user has admin role
		hasAdminRole := false
		for _, role := range claims.Roles {
			if role == "admin" {
				hasAdminRole = true
				break
			}
		}

		if !hasAdminRole {
			h.sendErrorResponse(w, http.StatusForbidden, "forbidden", "Admin role required")
			return
		}

		next.ServeHTTP(w, r)
	})
}

// GetClaimsFromContext extracts claims from request context
func GetClaimsFromContext(r *http.Request) (*db.Claims, error) {
	claims, ok := r.Context().Value(ClaimsContextKey).(*db.Claims)
	if !ok {
		return nil, errors.New("no claims found in context")
	}
	return claims, nil
}