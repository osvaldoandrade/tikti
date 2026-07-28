package utils

import (
	"encoding/base64"
	"strings"
	"testing"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
)

func TestVerifyPasswordSupportsBcryptAndBoundedArgon2id(t *testing.T) {
	bcryptHash, err := bcrypt.GenerateFromPassword([]byte("correct-password"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("bcrypt: %v", err)
	}
	salt := []byte("0123456789abcdef")
	argonHash := argon2.IDKey([]byte("correct-password"), salt, 3, 64*1024, 4, 32)
	argonEncoded := "$argon2id$v=19$m=65536,t=3,p=4$" +
		base64.RawStdEncoding.EncodeToString(salt) + "$" +
		base64.RawStdEncoding.EncodeToString(argonHash)

	for name, encoded := range map[string]string{
		"bcrypt":   string(bcryptHash),
		"argon2id": argonEncoded,
	} {
		t.Run(name, func(t *testing.T) {
			if err := ValidatePasswordHash(encoded); err != nil {
				t.Fatalf("validate hash: %v", err)
			}
			if !VerifyPassword(encoded, "correct-password") {
				t.Fatal("correct password rejected")
			}
			if VerifyPassword(encoded, "wrong-password") {
				t.Fatal("wrong password accepted")
			}
		})
	}
}

func TestValidatePasswordHashRejectsUnsafeInputs(t *testing.T) {
	tests := []string{
		"",
		"plain-text",
		"$argon2id$v=19$m=1024,t=1,p=1$bad$bad",
		"$argon2id$v=19$m=65536,t=3,p=4$" +
			base64.RawStdEncoding.EncodeToString([]byte("short")) + "$" +
			base64.RawStdEncoding.EncodeToString(make([]byte, 32)),
		strings.Replace(validArgon2idHash(), "m=65536", "m=1048577", 1),
	}
	for _, encoded := range tests {
		if err := ValidatePasswordHash(encoded); err == nil {
			t.Fatalf("expected hash rejection: %q", encoded)
		}
	}
}

func validArgon2idHash() string {
	salt := []byte("0123456789abcdef")
	hash := argon2.IDKey([]byte("password"), salt, 3, 64*1024, 4, 32)
	return "$argon2id$v=19$m=65536,t=3,p=4$" +
		base64.RawStdEncoding.EncodeToString(salt) + "$" +
		base64.RawStdEncoding.EncodeToString(hash)
}
