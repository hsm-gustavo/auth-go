package db

import (
	"database/sql"
	"fmt"
	"log"

	"github.com/hsm-gustavo/auth-go/internal/config"

	_ "github.com/go-sql-driver/mysql"
)

func Connect(cfg config.DatabaseConfig) *sql.DB {
	// refer to https://github.com/go-sql-driver/mysql/?tab=readme-ov-file#dsn-data-source-name
	//mysql://user:pass@host:port/name?ssl
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?parseTime=true", cfg.User, cfg.Password, cfg.Host, cfg.Port,cfg.Name)

	db, err := sql.Open("mysql", dsn)
	if err != nil {
		log.Fatalf("Unable to open DB connection: %v\n", err)
	}

	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(25)
	db.SetConnMaxLifetime(0)

	if err := db.Ping(); err != nil {
		log.Fatalf("Unable to connect to database: %v\n", err)
	}

	return db
}