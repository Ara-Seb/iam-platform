package main

import (
	"context"
	"log"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/yourname/iam-platform/db"
	"github.com/yourname/iam-platform/handler"
)

func main() {
	conn := db.Connect()
	defer conn.Close(context.Background())
	db.Migrate(conn)

	authHandler := &handler.AuthHandler{DB: conn}

	r := chi.NewRouter()
	r.Post("/register", authHandler.Register)
	r.Post("/login", authHandler.Login)
	r.Post("/token", authHandler.Token)

	log.Println("server running on :8080")
	http.ListenAndServe(":8080", r)
}
