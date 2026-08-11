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
	// ErrRoleConflict preserves an existing role whose immutable definition differs.
	ErrRoleConflict = errors.New("role already exists with different permissions")
	// ErrRoleNotFound indicates that an exact tenant role does not exist.
	ErrRoleNotFound = errors.New("role not found")
	// ErrMembershipNotFound indicates that an exact tenant assignment does not exist.
	ErrMembershipNotFound = errors.New("membership not found")
	// ErrMembershipConflict preserves an immutable membership definition or legacy shadow.
	ErrMembershipConflict = errors.New("membership already exists with a different definition")
	// ErrMembershipPageStale requires the caller to restart exact pagination.
	ErrMembershipPageStale = errors.New("membership page changed; restart pagination")
	// ErrNotFound is returned when a user cannot be located in storage.
	ErrNotFound = errors.New("user not found")
	// ErrInvalidOob signals that the out-of-band code is unknown or expired.
	ErrInvalidOob = errors.New("invalid or expired code")
	// ErrWorkloadTokenInvalid indicates a projected workload token failed
	// cryptographic or Kubernetes identity validation.
	ErrWorkloadTokenInvalid = errors.New("invalid workload token")
	// ErrWorkloadBindingDenied indicates that the verified workload subject is
	// not authorized for the requested tenant, audience, and scopes.
	ErrWorkloadBindingDenied = errors.New("workload binding denied")
	// ErrWorkloadIdentityUnavailable indicates a transient verifier, storage, or
	// signing failure. It must not include token material.
	ErrWorkloadIdentityUnavailable = errors.New("workload identity unavailable")
)
