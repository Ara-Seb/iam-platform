package main

import (
	"context"
	"log"
	"net/http"
	"os"

	"github.com/go-chi/chi/v5"
	"github.com/joho/godotenv"
	"github.com/yourname/iam-platform/db"
	"github.com/yourname/iam-platform/handler"
	"github.com/yourname/iam-platform/keys"
	"github.com/yourname/iam-platform/repository"
	"github.com/yourname/iam-platform/service"
)

func main() {
	if err := godotenv.Load(); err != nil {
		log.Fatal("error loading .env file")
	}
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

	r.Route("/clients", func(r chi.Router) {
		r.Use(handler.AuthMiddleware(tokenService))
		r.With(handler.RequireAdmin).Post("/", clientHandler.RegisterClient)
		r.Get("/{id}", clientHandler.GetClient)
		r.Delete("/{id}", clientHandler.DeleteClient)
		r.Patch("/{id}", clientHandler.UpdateClient)
	})

	port := os.Getenv("PORT")
	log.Println("server running on :" + port)
	if err := http.ListenAndServe(":"+port, r); err != nil {
		log.Fatal(err)
	}
}
