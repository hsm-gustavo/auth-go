package db

import (
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type User struct {
	ID				uuid.UUID		`json:"id"`
	Name			string			`json:"name"`
	Email			string			`json:"email"`
	PasswordHash	string			`json:"-"` 
}

type Claims struct {
	UserID			uuid.UUID		`json:"user_id"`
	Email			string			`json:"email"`
	jwt.RegisteredClaims
}