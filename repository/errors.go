package repository

import "errors"

const PgUniqueViolation = "23505"

var ErrEmailAlreadyExists = errors.New("email already exists")
var ErrNotFound = errors.New("not found")
