package service

import "errors"

var ErrEmailAlreadyExists = errors.New("email already exists")
var ErrInvalidCredentials = errors.New("invalid credentials")
var ErrInvalidClientSecret = errors.New("invalid client secret")
