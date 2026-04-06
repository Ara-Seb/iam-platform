package db

import (
	"context"
	"log"
	"os"

	"github.com/jackc/pgx/v5"
)

func Connect() *pgx.Conn {
	conn, err := pgx.Connect(context.Background(), os.Getenv("DATABASE_URL"))
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
        CREATE TABLE IF NOT EXISTS clients (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            secret_hash TEXT,              -- NULL for public clients
            client_type TEXT NOT NULL,     -- 'confidential' or 'public'
            redirect_uris TEXT[] NOT NULL,
			owner_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			created_at TIMESTAMP DEFAULT NOW()
        );
		CREATE TABLE IF NOT EXISTS authorization_codes (
    		code        TEXT PRIMARY KEY,
    		client_id   UUID NOT NULL REFERENCES clients(id),
    		user_id     UUID NOT NULL REFERENCES users(id),
    		redirect_uri TEXT NOT NULL,
    		scope       TEXT,
    		expires_at  TIMESTAMP NOT NULL,
    		used        BOOLEAN NOT NULL DEFAULT FALSE,
    		created_at  TIMESTAMP DEFAULT NOW()
		);
    `)
	if err != nil {
		log.Fatal("migration failed:", err)
	}
	log.Println("migrations complete")
}
