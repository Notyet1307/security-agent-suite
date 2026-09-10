package domain

import "errors"

var (
	ErrInputTooLarge   = errors.New("input exceeds configured limit")
	ErrRequestTooLarge = errors.New("request exceeds configured limit")
	ErrNotFound        = errors.New("not found")
	ErrAlreadyExists   = errors.New("already exists")
	ErrInvalidRequest  = errors.New("invalid request")
	ErrConflict        = errors.New("conflict")
	ErrUnauthorized    = errors.New("unauthorized")
	ErrForbidden       = errors.New("forbidden")
)
