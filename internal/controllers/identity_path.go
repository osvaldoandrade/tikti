package controllers

import (
	"strings"

	"github.com/osvaldoandrade/tikti/pkg/domain"
)

func canonicalTenantIDPath(value string) bool {
	if value == domain.RetiredDefaultTenantID {
		return false
	}
	if len(value) < 1 || len(value) > 63 || value[0] == '-' || value[len(value)-1] == '-' {
		return false
	}
	for _, character := range []byte(value) {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
			return false
		}
	}
	return true
}

func canonicalDirectoryIDPath(value string) bool {
	if value == "." || value == ".." || len(value) < 1 || len(value) > 128 {
		return false
	}
	for _, character := range []byte(value) {
		if !strings.ContainsRune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:-", rune(character)) {
			return false
		}
	}
	return true
}
