package main

import (
	"context"
	"encoding/base64"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/joho/godotenv"
	"github.com/yourname/iam-platform/db"
	"github.com/yourname/iam-platform/handler"
	"github.com/yourname/iam-platform/keys"
	"github.com/yourname/iam-platform/repository"
	"github.com/yourname/iam-platform/service"
	"github.com/yourname/iam-platform/session"
	"github.com/yourname/iam-platform/store"
)

func main() {
	if err := godotenv.Load(); err != nil {
		log.Println("no .env file found, using environment variables directly")
	}
	port := os.Getenv("PORT")
	if port == "" {
		log.Fatal("PORT environment variable is not set")
	}
	hashKey := os.Getenv("SESSION_HASH_KEY")
	hashKeyBytes, err := base64.StdEncoding.DecodeString(hashKey)
	if err != nil || len(hashKeyBytes) != 32 {
		log.Fatal("invalid SESSION_HASH_KEY")
	}
	blockKey := os.Getenv("SESSION_BLOCK_KEY")
	blockKeyBytes, err := base64.StdEncoding.DecodeString(blockKey)
	if err != nil || (len(blockKeyBytes) != 16 && len(blockKeyBytes) != 24 && len(blockKeyBytes) != 32) {
		log.Fatal("invalid SESSION_BLOCK_KEY")
	}

	conn := db.Connect()
	defer conn.Close(context.Background())
	db.Migrate(conn)
	userRepo := repository.NewUserRepository(conn)
	clientRepo := repository.NewClientRepository(conn)

	keys, err := keys.LoadKeys("keys/private.pem", "keys/public.pem")
	if err != nil {
		log.Fatal(err)
	}
	tokenService := service.NewTokenService(keys)
	sessionStore := session.NewSessionStore(hashKeyBytes, blockKeyBytes)
	authService := service.NewAuthService(userRepo, tokenService)
	authCodeStore := store.NewAuthCodeStore()
	refreshTokenStore := store.NewRefreshTokenStore()
	clientService := service.NewClientService(clientRepo)
	authHandler := handler.NewAuthHandler(clientService, authService, sessionStore, authCodeStore, refreshTokenStore, tokenService)
	clientHandler := handler.NewClientHandler(clientService)

	r := chi.NewRouter()
	r.Post("/register", authHandler.Register)
	r.Post("/login", authHandler.LoginPost)
	r.Get("/login", authHandler.LoginGet)
	r.Post("/token", authHandler.Token)
	r.Get("/authorize", authHandler.Authorize)

	r.Route("/clients", func(r chi.Router) {
		r.Use(handler.AuthMiddleware(tokenService))
		r.With(handler.RequireAdmin).Post("/", clientHandler.RegisterClient)
		r.Get("/{id}", clientHandler.GetClient)
		r.Delete("/{id}", clientHandler.DeleteClient)
		r.Patch("/{id}", clientHandler.UpdateClient)
	})

	server := &http.Server{
		Addr:    ":" + port,
		Handler: r,
	}
	serverErr := make(chan error, 1)
	go func() {
		serverErr <- server.ListenAndServe()
	}()

	log.Println("server running on :" + port)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	select {
	case err := <-serverErr:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("server error: %v", err)
		}
	case sig := <-sigChan:
		log.Printf("received signal: %v, shutting down...", sig)

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		if err := server.Shutdown(ctx); err != nil {
			log.Fatalf("graceful shutdown failed: %v", err)
		}
		cancel()
		log.Printf("server gracefully stopped")
	}
}
