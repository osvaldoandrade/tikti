package utils

import (
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
)

type argon2idParameters struct {
	memory      uint32
	iterations  uint32
	parallelism uint8
	salt        []byte
	hash        []byte
}

// ValidatePasswordHash accepts Tikti's native bcrypt hashes and the bounded
// Argon2id PHC format used by the Code Foundry production bootstrap.
func ValidatePasswordHash(encoded string) error {
	encoded = strings.TrimSpace(encoded)
	if strings.HasPrefix(encoded, "$argon2id$") {
		_, err := parseArgon2idHash(encoded)
		return err
	}
	cost, err := bcrypt.Cost([]byte(encoded))
	if err != nil {
		return errors.New("unsupported password hash")
	}
	if cost < bcrypt.DefaultCost || cost > 16 {
		return fmt.Errorf("bcrypt cost must be between %d and 16", bcrypt.DefaultCost)
	}
	return nil
}

// VerifyPassword compares a password against a supported bounded hash.
func VerifyPassword(encoded string, password string) bool {
	encoded = strings.TrimSpace(encoded)
	if strings.HasPrefix(encoded, "$argon2id$") {
		parameters, err := parseArgon2idHash(encoded)
		if err != nil {
			return false
		}
		candidate := argon2.IDKey(
			[]byte(password),
			parameters.salt,
			parameters.iterations,
			parameters.memory,
			parameters.parallelism,
			// #nosec G115 -- parseArgon2idHash constrains the hash to 32..64 bytes.
			uint32(len(parameters.hash)),
		)
		return subtle.ConstantTimeCompare(candidate, parameters.hash) == 1
	}
	return bcrypt.CompareHashAndPassword([]byte(encoded), []byte(password)) == nil
}

func parseArgon2idHash(encoded string) (argon2idParameters, error) {
	parts := strings.Split(strings.TrimSpace(encoded), "$")
	if len(parts) != 6 || parts[1] != "argon2id" || parts[2] != "v=19" {
		return argon2idParameters{}, errors.New("invalid Argon2id PHC format")
	}
	var parameters argon2idParameters
	if _, err := fmt.Sscanf(
		parts[3],
		"m=%d,t=%d,p=%d",
		&parameters.memory,
		&parameters.iterations,
		&parameters.parallelism,
	); err != nil || parameters.memory < 64*1024 || parameters.memory > 1024*1024 ||
		parameters.iterations < 3 || parameters.iterations > 10 ||
		parameters.parallelism < 4 || parameters.parallelism > 16 {
		return argon2idParameters{}, errors.New("unsafe Argon2id parameters")
	}
	var err error
	parameters.salt, err = base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(parameters.salt) < 16 || len(parameters.salt) > 64 {
		return argon2idParameters{}, errors.New("invalid Argon2id salt")
	}
	parameters.hash, err = base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(parameters.hash) < 32 || len(parameters.hash) > 64 {
		return argon2idParameters{}, errors.New("invalid Argon2id hash")
	}
	return parameters, nil
}
