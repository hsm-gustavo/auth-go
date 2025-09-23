package auth

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/hsm-gustavo/auth-go/internal/api/user"
	"github.com/hsm-gustavo/auth-go/internal/db"
)

// Request/Response structures

type RegisterRequest struct {
	Name     string `json:"name" example:"João Silva"`
	Email    string `json:"email" example:"joao@example.com"`
	Password string `json:"password" example:"password123"`
}

type LoginRequest struct {
	Email    string `json:"email" example:"joao@example.com"`
	Password string `json:"password" example:"password123"`
}

type RefreshRequest struct {
	RefreshToken string `json:"refresh_token" example:"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."`
}

type AuthResponse struct {
	AccessToken  string `json:"access_token" example:"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."`
	RefreshToken string `json:"refresh_token" example:"MTQ0NjJkZmQ5OTM2NDE1ZTZjNGZmZjI3..."`
	TokenType    string `json:"token_type" example:"Bearer"`
	ExpiresIn    int64  `json:"expires_in" example:"900"`
}

type RegisterResponse struct {
	ID      int64  `json:"id" example:"1"`
	Message string `json:"message" example:"User registered successfully"`
}

type MeResponse struct {
	UserID string   `json:"user_id" example:"550e8400-e29b-41d4-a716-446655440000"`
	Email  string   `json:"email" example:"joao@example.com"`
	Name   string   `json:"name" example:"João Silva"`
	Roles  []string `json:"roles" example:"admin,user"`
}

type AdminResponse struct {
	Message string `json:"message" example:"Welcome to the admin area!"`
	UserID  string `json:"user_id" example:"550e8400-e29b-41d4-a716-446655440000"`
}

type ErrorResponse struct {
	Error   string `json:"error" example:"invalid credentials"`
	Message string `json:"message,omitempty" example:"Email or password is incorrect"`
}

type AuthHandler struct {
	service *AuthService
}

func NewAuthHandler(JWTSecret string, db *sql.DB) *AuthHandler {
	userService := user.NewUserService(db)
	return &AuthHandler{
		service: &AuthService{
			JWTSecret:   []byte(JWTSecret),
			TTL:         time.Minute * 15,
			UserService: userService,
		},
	}
}

// Register godoc
// @Summary		Register a new user
// @Description	Register a new user account with email and password
// @Tags			auth
// @Accept			json
// @Produce		json
// @Param			user	body		RegisterRequest		true	"User registration data"
// @Success		201		{object}	RegisterResponse	"User registered successfully"
// @Failure		400		{object}	ErrorResponse		"Bad request - invalid input"
// @Failure		409		{object}	ErrorResponse		"Conflict - user already exists"
// @Failure		500		{object}	ErrorResponse		"Internal server error"
// @Router			/auth/register [post]
func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.sendErrorResponse(w, http.StatusBadRequest, "invalid body", "Invalid JSON format")
		return
	}

	if req.Email == "" || req.Password == "" || req.Name == "" {
		h.sendErrorResponse(w, http.StatusBadRequest, "validation failed", "Name, email and password are required")
		return
	}

	existing, err := h.service.UserService.GetUserByEmail(req.Email)
	if err != nil {
		h.sendErrorResponse(w, http.StatusInternalServerError, "server error", "Error checking existing user")
		return
	}
	if existing != nil {
		h.sendErrorResponse(w, http.StatusConflict, "user exists", "A user with this email already exists")
		return
	}

	hash, err := h.service.HashPassword(req.Password)
	if err != nil {
		h.sendErrorResponse(w, http.StatusInternalServerError, "server error", "Error processing password")
		return
	}

	id, err := h.service.UserService.CreateUser(req.Name, req.Email, hash)
	if err != nil {
		h.sendErrorResponse(w, http.StatusInternalServerError, "could not create user", "Error creating user account")
		return
	}

	response := RegisterResponse{
		ID:      id,
		Message: "User registered successfully",
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(response)
}

// Login godoc
// @Summary		User login
// @Description	Authenticate user and return access and refresh tokens
// @Tags			auth
// @Accept			json
// @Produce		json
// @Param			credentials	body		LoginRequest	true	"User login credentials"
// @Success		200			{object}	AuthResponse	"Login successful"
// @Failure		400			{object}	ErrorResponse	"Bad request - invalid input"
// @Failure		401			{object}	ErrorResponse	"Unauthorized - invalid credentials"
// @Failure		500			{object}	ErrorResponse	"Internal server error"
// @Router			/auth/login [post]
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.sendErrorResponse(w, http.StatusBadRequest, "invalid body", "Invalid JSON format")
		return
	}

	if req.Email == "" || req.Password == "" {
		h.sendErrorResponse(w, http.StatusBadRequest, "validation failed", "Email and password are required")
		return
	}

	user, err := h.service.UserService.GetUserByEmail(req.Email)
	if err != nil {
		h.sendErrorResponse(w, http.StatusInternalServerError, "server error", "Error retrieving user")
		return
	}
	if user == nil {
		h.sendErrorResponse(w, http.StatusUnauthorized, "invalid credentials", "Email or password is incorrect")
		return
	}

	// Get user with password for verification
	userWithPassword, err := h.service.UserService.GetUserWithPassword(req.Email)
	if err != nil {
		h.sendErrorResponse(w, http.StatusInternalServerError, "server error", "Error retrieving user credentials")
		return
	}

	if err := h.service.CheckPasswordHash(req.Password, userWithPassword.PasswordHash); err != nil {
		h.sendErrorResponse(w, http.StatusUnauthorized, "invalid credentials", "Email or password is incorrect")
		return
	}

	// Get user roles
	roles, err := h.service.UserService.GetUserRoles(user.ID)
	if err != nil {
		h.sendErrorResponse(w, http.StatusInternalServerError, "server error", "Error retrieving user roles")
		return
	}

	// Generate access token
	accessToken, err := h.service.GenerateJWT(user.ID, roles)
	if err != nil {
		h.sendErrorResponse(w, http.StatusInternalServerError, "server error", "Error generating access token")
		return
	}

	// Generate refresh token
	refreshToken, err := h.service.NewRefreshToken()
	if err != nil {
		h.sendErrorResponse(w, http.StatusInternalServerError, "server error", "Error generating refresh token")
		return
	}

	// Save refresh token (expires in 7 days)
	expiresAt := time.Now().Add(7 * 24 * time.Hour).Format(time.RFC3339)
	if err := h.service.UserService.SaveRefreshToken(user.ID, refreshToken, expiresAt); err != nil {
		h.sendErrorResponse(w, http.StatusInternalServerError, "server error", "Error saving refresh token")
		return
	}

	response := AuthResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int64(h.service.TTL.Seconds()),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// Refresh godoc
// @Summary		Refresh access token
// @Description	Generate new access token using refresh token
// @Tags			auth
// @Accept			json
// @Produce		json
// @Param			refresh	body		RefreshRequest	true	"Refresh token"
// @Success		200		{object}	AuthResponse	"Token refreshed successfully"
// @Failure		400		{object}	ErrorResponse	"Bad request - invalid input"
// @Failure		401		{object}	ErrorResponse	"Unauthorized - invalid refresh token"
// @Failure		500		{object}	ErrorResponse	"Internal server error"
// @Router			/auth/refresh [post]
func (h *AuthHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	var req RefreshRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.sendErrorResponse(w, http.StatusBadRequest, "invalid body", "Invalid JSON format")
		return
	}

	if req.RefreshToken == "" {
		h.sendErrorResponse(w, http.StatusBadRequest, "validation failed", "Refresh token is required")
		return
	}

	// Validate refresh token and get user
	userID, err := h.service.UserService.ValidateRefreshToken(req.RefreshToken)
	if err != nil {
		h.sendErrorResponse(w, http.StatusUnauthorized, "invalid refresh token", "Refresh token is invalid or expired")
		return
	}

	// Get user roles
	roles, err := h.service.UserService.GetUserRoles(userID)
	if err != nil {
		h.sendErrorResponse(w, http.StatusInternalServerError, "server error", "Error retrieving user roles")
		return
	}

	// Generate new access token
	accessToken, err := h.service.GenerateJWT(userID, roles)
	if err != nil {
		h.sendErrorResponse(w, http.StatusInternalServerError, "server error", "Error generating access token")
		return
	}

	// Generate new refresh token
	newRefreshToken, err := h.service.NewRefreshToken()
	if err != nil {
		h.sendErrorResponse(w, http.StatusInternalServerError, "server error", "Error generating refresh token")
		return
	}

	// Save new refresh token
	expiresAt := time.Now().Add(7 * 24 * time.Hour).Format(time.RFC3339)
	if err := h.service.UserService.SaveRefreshToken(userID, newRefreshToken, expiresAt); err != nil {
		h.sendErrorResponse(w, http.StatusInternalServerError, "server error", "Error saving refresh token")
		return
	}

	response := AuthResponse{
		AccessToken:  accessToken,
		RefreshToken: newRefreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int64(h.service.TTL.Seconds()),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// Me godoc
// @Summary		Get current user info
// @Description	Get current authenticated user information and roles
// @Tags			auth
// @Accept			json
// @Produce		json
// @Security		BearerAuth
// @Success		200	{object}	MeResponse		"User information retrieved"
// @Failure		401	{object}	ErrorResponse	"Unauthorized - invalid or missing token"
// @Failure		500	{object}	ErrorResponse	"Internal server error"
// @Router			/auth/me [get]
func (h *AuthHandler) Me(w http.ResponseWriter, r *http.Request) {
	// Try to get claims from context first (if middleware was used)
	claims, err := GetClaimsFromContext(r)
	if err != nil {
		// Fallback to extracting from header directly
		claims, err = h.extractClaims(r)
		if err != nil {
			h.sendErrorResponse(w, http.StatusUnauthorized, "unauthorized", "Invalid or missing authentication token")
			return
		}
	}

	// Get user details
	user, err := h.service.UserService.GetUserByID(claims.UserID)
	if err != nil {
		h.sendErrorResponse(w, http.StatusInternalServerError, "server error", "Error retrieving user information")
		return
	}
	if user == nil {
		h.sendErrorResponse(w, http.StatusUnauthorized, "user not found", "User account no longer exists")
		return
	}

	response := MeResponse{
		UserID: claims.UserID.String(),
		Email:  user.Email,
		Name:   user.Name,
		Roles:  claims.Roles,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// Admin godoc
// @Summary		Admin welcome message
// @Description	Returns a welcome message for admin users only
// @Tags			auth
// @Accept			json
// @Produce		json
// @Security		BearerAuth
// @Success		200	{object}	AdminResponse	"Admin welcome message"
// @Failure		401	{object}	ErrorResponse	"Unauthorized - invalid or missing token"
// @Failure		403	{object}	ErrorResponse	"Forbidden - admin role required"
// @Failure		500	{object}	ErrorResponse	"Internal server error"
// @Router			/auth/admin [get]
func (h *AuthHandler) Admin(w http.ResponseWriter, r *http.Request) {
	// Try to get claims from context first (if middleware was used)
	claims, err := GetClaimsFromContext(r)
	if err != nil {
		// Fallback to extracting from header directly
		claims, err = h.extractClaims(r)
		if err != nil {
			h.sendErrorResponse(w, http.StatusUnauthorized, "unauthorized", "Invalid or missing authentication token")
			return
		}
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
		h.sendErrorResponse(w, http.StatusForbidden, "forbidden", "Admin role required to access this resource")
		return
	}

	response := AdminResponse{
		Message: "Welcome to the admin area! You have administrative privileges.",
		UserID:  claims.UserID.String(),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// Helper methods

func (h *AuthHandler) extractClaims(r *http.Request) (*db.Claims, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return nil, errors.New("missing authorization header")
	}

	bearerToken := strings.Split(authHeader, " ")
	if len(bearerToken) != 2 || bearerToken[0] != "Bearer" {
		return nil, errors.New("invalid authorization header format")
	}

	return h.service.ParseJWT(bearerToken[1])
}

func (h *AuthHandler) sendErrorResponse(w http.ResponseWriter, statusCode int, error string, message string) {
	response := ErrorResponse{
		Error:   error,
		Message: message,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(response)
}