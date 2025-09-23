package user

import (
	"database/sql"

	"github.com/google/uuid"
	"github.com/hsm-gustavo/auth-go/internal/db"
)

type UserService struct {
	db	*sql.DB
}

func (s *UserService) CreateUser(name string, email string, passwordHash string) (int64, error) {
	id,err := uuid.NewUUID()
	
	if err!=nil {
		return 0, err
	}

	res, err := s.db.Exec("INSERT INTO users (id, name, email, password_hash) VALUES (?, ?, ?, ?)", id, name, email, passwordHash)

	if err!=nil {
		return 0, err
	}

	return res.LastInsertId()
}

func (s *UserService) GetUserByEmail(email string) (*db.User, error) {
	var u db.User
	err := s.db.QueryRow("SELECT id, name, email FROM users WHERE email LIKE ?", email).Scan(&u.ID, &u.Name, &u.Email)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil{
		return nil, err
	}

	return &u, nil
}

func (s *UserService) GetUserRoles(userID uuid.UUID) ([]string, error) {
	rows, err := s.db.Query(`
		SELECT r.name
		FROM roles r
		JOIN user_roles ur ON ur.role_id = r.id
		WHERE ur.user_id = ?`, userID)
	
	if err != nil {
		return nil, err
	}

	defer rows.Close()

	var roles []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return  nil, err
		}
		roles = append(roles, name)
	}
	return roles, nil
}

func (s *UserService) SaveRefreshToken(userID uuid.UUID, token string, expiresAt string) error {
	_, err := s.db.Exec("INSERT INTO refresh_tokens (user_id, token, expires_at) VALUES (?, ?, ?)", userID, token, expiresAt)
	return err
}