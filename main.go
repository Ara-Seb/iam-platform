package main

import (
	"context"
	"log"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/yourname/iam-platform/db"
	"github.com/yourname/iam-platform/handler"
	"github.com/yourname/iam-platform/keys"
	"github.com/yourname/iam-platform/repository"
	"github.com/yourname/iam-platform/service"
)

func main() {
	conn := db.Connect()
	defer conn.Close(context.Background())
	db.Migrate(conn)

	keys, err := keys.LoadKeys("keys/private.pem", "keys/public.pem")
	if err != nil {
		log.Fatal(err)
	}

	userRepo := repository.NewUserRepository(conn)
	clientRepo := repository.NewClientRepository(conn)
	tokenService := service.NewTokenService(keys)
	authService := service.NewAuthService(userRepo, tokenService)
	authHandler := handler.NewAuthHandler(clientRepo, authService)
	clientService := service.NewClientService(clientRepo)
	clientHandler := handler.NewClientHandler(clientService)

	r := chi.NewRouter()
	r.Post("/register", authHandler.Register)
	r.Post("/login", authHandler.Login)
	r.Post("/token", authHandler.Token)
	r.Post("/clients", clientHandler.RegisterClient)

	log.Println("server running on :8080")
	if err := http.ListenAndServe(":8080", r); err != nil {
		log.Fatal(err)
	}
}
