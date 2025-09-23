package routes

import (
	"database/sql"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"

	_ "github.com/hsm-gustavo/auth-go/docs"
	"github.com/hsm-gustavo/auth-go/internal/api/auth"
	"github.com/hsm-gustavo/auth-go/internal/api/health"
	"github.com/hsm-gustavo/auth-go/internal/api/user"
	"github.com/hsm-gustavo/auth-go/internal/config"
	httpSwagger "github.com/swaggo/http-swagger"
)

func SetupRoutes(db *sql.DB) http.Handler {
	r := chi.NewRouter()

	corsMiddleware := cors.New(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: true,
		MaxAge:           300, // max time in seconds for OPTIONS preflight response cache
	})

	r.Use(corsMiddleware.Handler)

	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.StripSlashes)
	r.Use(middleware.Timeout(2 * time.Minute))

	cfg := config.Load()

	// init services & handlers
	userHandler := user.NewHandler(db)
	authHandler := auth.NewAuthHandler(cfg.JWTSecret, db)

	r.Get("/health", health.HealthHandler)

	// public auth routes
	r.Post("/auth/register", authHandler.Register)
	r.Post("/auth/login", authHandler.Login)
	r.Post("/auth/refresh", authHandler.Refresh)

	// protected auth routes
	r.Group(func(r chi.Router) {
		r.Use(authHandler.AuthMiddleware)
		r.Get("/auth/me", authHandler.Me)
		
		// Admin-only routes
		r.Group(func(r chi.Router) {
			r.Use(authHandler.AdminMiddleware)
			r.Get("/auth/admin", authHandler.Admin)
		})
	})

	r.Post("/users", userHandler.CreateUser)
	r.Get("/users", userHandler.GetUserByEmail)
	r.Get("/users/{id}/roles", userHandler.GetUserRoles)

	// init swagger
	r.Get("/docs", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/docs/index.html", http.StatusMovedPermanently)
	})
	r.Get("/docs/*", httpSwagger.WrapHandler)

	return r
}
