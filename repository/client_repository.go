package repository

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/yourname/iam-platform/models"
)

type ClientRepository struct {
	DB *pgx.Conn
}

func NewClientRepository(db *pgx.Conn) *ClientRepository {
	return &ClientRepository{DB: db}
}

func (r *ClientRepository) Create(ctx context.Context, client *models.Client) error {
	err := r.DB.QueryRow(ctx, `
		INSERT INTO clients (client_type, secret_hash, redirect_uris)
		VALUES ($1, $2, $3)
		RETURNING id, created_at
	`, client.ClientType, client.SecretHash, client.RedirectURIs).Scan(&client.ID, &client.CreatedAt)
	return err
}

func (r *ClientRepository) FindByID(ctx context.Context, id string) (*models.Client, error) {
	var client models.Client
	err := r.DB.QueryRow(ctx, `
		SELECT id, secret_hash, client_type, redirect_uris, created_at
		FROM clients
		WHERE id = $1
	`, id).Scan(&client.ID, &client.SecretHash, &client.ClientType, &client.RedirectURIs, &client.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &client, nil
}

func (r *ClientRepository) Delete(ctx context.Context, id string) error {
	cmdTag, err := r.DB.Exec(ctx, `
		DELETE FROM clients
		WHERE id = $1
	`, id)
	if err != nil {
		return err
	}
	if cmdTag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (r *ClientRepository) Update(ctx context.Context, id string, redirectURIs []string) error {
	cmdTag, err := r.DB.Exec(ctx, `
		UPDATE clients
		SET redirect_uris = $1
		WHERE id = $2
	`, redirectURIs, id)
	if err != nil {
		return err
	}
	if cmdTag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
