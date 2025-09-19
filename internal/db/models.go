package db

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type User struct {
	ID				uuid.UUID		`json:"id"`
	Name			string			`json:"name"`
	Email			string			`json:"email"`
	PasswordHash	string			`json:"-"`
	CreatedAt		time.Time		`json:"createdAt"`
	UpdatedAt		time.Time		`json:"updatedAt"`
}

type Claims struct {
	UserID			uuid.UUID		`json:"userId"`
	Email			string			`json:"email"`
	jwt.RegisteredClaims
}