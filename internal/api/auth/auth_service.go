package auth

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/hsm-gustavo/auth-go/internal/api/user"
	"github.com/hsm-gustavo/auth-go/internal/db"
	"golang.org/x/crypto/bcrypt"
)

type AuthService struct {
	UserService 	*user.UserService
	JWTSecret		[]byte
	TTL				time.Duration
}

func (s *AuthService) HashPassword(password string) (string, error) {
	hashed, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(hashed), err
}

func (s *AuthService) CheckPasswordHash(password, hash string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}

func (s *AuthService) GenerateJWT(userID uuid.UUID, roles []string) (string, error) {
	now := time.Now()
	claims := db.Claims{
		UserID: userID,
		Roles: roles,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(s.TTL)),
			Issuer: "auth-go",
			Subject: userID.String(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(s.JWTSecret)
}

func (s *AuthService) ParseJWT(tokenStr string) (*db.Claims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &db.Claims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("alg not allowed")
		}
		return s.JWTSecret, nil
	})
	if err != nil {
		return nil, err
	}
	if c, ok := token.Claims.(*db.Claims); ok && token.Valid {
		return c, nil
	}
	return nil, errors.New("invalid token")
}

func (s *AuthService) NewRefreshToken() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}