package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/hsm-gustavo/auth-go/internal/api/routes"
	"github.com/hsm-gustavo/auth-go/internal/config"
	"github.com/hsm-gustavo/auth-go/internal/db"
)

// @title Authentication API
// @version 1.0
// @description An authentication API
func main() {
	cfg := config.Load()

	database := db.Connect(cfg.Database)

	defer database.Close()

	// Setup routes here:
	router := routes.SetupRoutes(database)
	// End routes

	server := &http.Server{
		Addr: fmt.Sprintf(":%d", cfg.Server.Port),
		Handler: router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// starts server in a goroutine
	go func() {
		log.Printf("Server running on port %d", cfg.Server.Port)
		err := server.ListenAndServe()

		if err != nil && err != http.ErrServerClosed {
			log.Fatalf("Error starting the server: %v", err)
		}
	}()

	// channel to capture quit signals (e.g. CTRL+C)
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<- quit

	log.Println("Shutting down the server...")
	ctx, cancel := context.WithTimeout(context.Background(), 10 * time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		log.Fatalf("Error on server shutdown: %v", err)
	}

	log.Println("Server shut down successfully")
}