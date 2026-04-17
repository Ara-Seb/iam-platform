package store

import "errors"

var ErrCodeNotFound = errors.New("authorization code not found")
var ErrCodeExpired = errors.New("authorization code expired")
