package domain

import "errors"

var (
	// ErrEmailExists indicates another account already owns the supplied email address.
	ErrEmailExists = errors.New("email already registered")
	// ErrInvalidCreds indicates the credentials were incorrect or missing.
	ErrInvalidCreds = errors.New("invalid credentials")
	// ErrInvalidToken indicates the supplied token is malformed or invalid.
	ErrInvalidToken = errors.New("invalid token")
	// ErrInvalidAudience indicates the supplied audience is missing or not allowed.
	ErrInvalidAudience = errors.New("invalid audience")
	// ErrInvalidTenant indicates the supplied tenant is missing or not allowed.
	ErrInvalidTenant = errors.New("invalid tenant")
	// ErrUnauthorizedScope indicates the requested scopes are not permitted.
	ErrUnauthorizedScope = errors.New("unauthorized scopes")
	// ErrInvalidArgument indicates request payload validation failed.
	ErrInvalidArgument = errors.New("invalid argument")
	// ErrNotFound is returned when a user cannot be located in storage.
	ErrNotFound = errors.New("user not found")
	// ErrInvalidOob signals that the out-of-band code is unknown or expired.
	ErrInvalidOob = errors.New("invalid or expired code")
)
