package user

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type Handler struct {
	service *UserService
}

func NewHandler(db *sql.DB) *Handler {
	return &Handler{
		service: &UserService{db: db},
	}
}

type CreateUserRequest struct {
	Name     string `json:"name" example:"João Silva"`
	Email    string `json:"email" example:"joao@example.com"`
	Password string `json:"password" example:"password123"`
}

type CreateUserResponse struct {
	ID      int64  `json:"id" example:"1"`
	Message string `json:"message" example:"User created successfully"`
}

type GetUserResponse struct {
	ID    string `json:"id" example:"550e8400-e29b-41d4-a716-446655440000"`
	Name  string `json:"name" example:"João Silva"`
	Email string `json:"email" example:"joao@example.com"`
}

type GetUserRolesResponse struct {
	UserID string   `json:"user_id" example:"550e8400-e29b-41d4-a716-446655440000"`
	Roles  []string `json:"roles" example:"admin,user"`
}

type ErrorResponse struct {
	Error   string `json:"error" example:"Invalid email format"`
	Message string `json:"message,omitempty" example:"Please provide a valid email address"`
}

// @Summary		Create a new user
// @Description	Create a new user with name, email and password
// @Tags			users
// @Accept			json
// @Produce		json
// @Param			user	body		CreateUserRequest	true	"User creation data"
// @Success		201		{object}	CreateUserResponse	"User created successfully"
// @Failure		400		{object}	ErrorResponse		"Bad request - invalid input"
// @Failure		409		{object}	ErrorResponse		"Conflict - user already exists"
// @Failure		500		{object}	ErrorResponse		"Internal server error"
// @Router			/users [post]
func (h *Handler) CreateUser(w http.ResponseWriter, r *http.Request) {
	var req CreateUserRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.sendErrorResponse(w, http.StatusBadRequest, "Invalid JSON format", err.Error())
		return
	}

	if err := h.validateCreateUserRequest(req); err != nil {
		h.sendErrorResponse(w, http.StatusBadRequest, "Validation failed", err.Error())
		return
	}

	existingUser, err := h.service.GetUserByEmail(req.Email)
	if err != nil {
		h.sendErrorResponse(w, http.StatusInternalServerError, "Error checking existing user", err.Error())
		return
	}
	if existingUser != nil {
		h.sendErrorResponse(w, http.StatusConflict, "User already exists", "A user with this email already exists")
		return
	}

	passwordHash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		h.sendErrorResponse(w, http.StatusInternalServerError, "Error processing password", err.Error())
		return
	}

	userID, err := h.service.CreateUser(req.Name, req.Email, string(passwordHash))
	if err != nil {
		h.sendErrorResponse(w, http.StatusInternalServerError, "Error creating user", err.Error())
		return
	}

	response := CreateUserResponse{
		ID:      userID,
		Message: "User created successfully",
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(response)
}

// @Summary		Get user by email
// @Description	Retrieve user information by email address
// @Tags			users
// @Accept			json
// @Produce		json
// @Param			email	query		string			true	"User email"	example(joao@example.com)
// @Success		200		{object}	GetUserResponse	"User found"
// @Failure		400		{object}	ErrorResponse	"Bad request - invalid email"
// @Failure		404		{object}	ErrorResponse	"User not found"
// @Failure		500		{object}	ErrorResponse	"Internal server error"
// @Router			/users [get]
func (h *Handler) GetUserByEmail(w http.ResponseWriter, r *http.Request) {
	email := r.URL.Query().Get("email")
	if email == "" {
		h.sendErrorResponse(w, http.StatusBadRequest, "Email parameter is required", "Please provide an email parameter")
		return
	}

	user, err := h.service.GetUserByEmail(email)
	if err != nil {
		h.sendErrorResponse(w, http.StatusInternalServerError, "Error retrieving user", err.Error())
		return
	}

	if user == nil {
		h.sendErrorResponse(w, http.StatusNotFound, "User not found", "No user found with the provided email")
		return
	}

	response := GetUserResponse{
		ID:    user.ID.String(),
		Name:  user.Name,
		Email: user.Email,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// @Summary		Get user roles
// @Description	Retrieve all roles assigned to a specific user
// @Tags			users
// @Accept			json
// @Produce		json
// @Param			id	path		string					true	"User ID"	example(550e8400-e29b-41d4-a716-446655440000)
// @Success		200	{object}	GetUserRolesResponse	"User roles retrieved"
// @Failure		400	{object}	ErrorResponse			"Bad request - invalid user ID"
// @Failure		404	{object}	ErrorResponse			"User not found"
// @Failure		500	{object}	ErrorResponse			"Internal server error"
// @Router			/users/{id}/roles [get]
func (h *Handler) GetUserRoles(w http.ResponseWriter, r *http.Request) {
	userIDStr := chi.URLParam(r, "id")
	if userIDStr == "" {
		h.sendErrorResponse(w, http.StatusBadRequest, "User ID is required", "Please provide a valid user ID")
		return
	}

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		h.sendErrorResponse(w, http.StatusBadRequest, "Invalid user ID format", "Please provide a valid UUID")
		return
	}

	roles, err := h.service.GetUserRoles(userID)
	if err != nil {
		h.sendErrorResponse(w, http.StatusInternalServerError, "Error retrieving user roles", err.Error())
		return
	}

	response := GetUserRolesResponse{
		UserID: userID.String(),
		Roles:  roles,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// Helpers

func (h *Handler) validateCreateUserRequest(req CreateUserRequest) error {
	if strings.TrimSpace(req.Name) == "" {
		return errors.New("name is required")
	}
	if strings.TrimSpace(req.Email) == "" {
		return errors.New("email is required")
	}
	if !h.isValidEmail(req.Email) {
		return errors.New("invalid email format")
	}
	if len(req.Password) < 6 {
		return errors.New("password must be at least 6 characters long")
	}
	return nil
}

func (h *Handler) isValidEmail(email string) bool {
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	return emailRegex.MatchString(email)
}

func (h *Handler) sendErrorResponse(w http.ResponseWriter, statusCode int, error string, message string) {
	response := ErrorResponse{
		Error:   error,
		Message: message,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(response)
}
