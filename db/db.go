package db

import (
	"context"
	"log"

	"github.com/jackc/pgx/v5"
)

func Connect() *pgx.Conn {
	conn, err := pgx.Connect(context.Background(), "host=127.0.0.1 port=5432 user=postgres password=secret dbname=iam sslmode=disable")
	if err != nil {
		log.Fatal("could not connect to database:", err)
	}

	log.Println("connected to database")
	return conn
}

func Migrate(conn *pgx.Conn) {
	_, err := conn.Exec(context.Background(), `
        CREATE TABLE IF NOT EXISTS users (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            email VARCHAR(255) UNIQUE NOT NULL,
            password_hash VARCHAR(255) NOT NULL,
            role VARCHAR(50) NOT NULL DEFAULT 'viewer',
            created_at TIMESTAMP DEFAULT NOW()
        );
        CREATE TABLE clients (
            id          UUID PRIMARY KEY,
            secret_hash TEXT,              -- NULL for public clients
            client_type TEXT NOT NULL,     -- 'confidential' or 'public'
            redirect_uris TEXT[] NOT NULL
        );
    `)
	if err != nil {
		log.Fatal("migration failed:", err)
	}
	log.Println("migrations complete")
}
