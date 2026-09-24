package repository

import "testing"

func TestDecodeLegacyUserKeepsIdentifierForTokenSubject(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  string
	}{
		{"legacy Go fields", `{"Id":"global-admin-id","Email":"admin@codecompany.com.br","Password":"hash","Role":"ADMIN","Status":"ACTIVE"}`},
		{"canonical fields", `{"localId":"global-admin-id","email":"admin@codecompany.com.br","password":"hash","role":"ADMIN","status":"ACTIVE"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			user, err := decodeLegacyUser(tc.raw)
			if err != nil {
				t.Fatal(err)
			}
			if user.Id != "global-admin-id" || user.Email != "admin@codecompany.com.br" || user.Role != "ADMIN" || user.Status != "ACTIVE" {
				t.Fatalf("legacy user did not retain its identity: id=%q email=%q role=%q status=%q", user.Id, user.Email, user.Role, user.Status)
			}
		})
	}
}
