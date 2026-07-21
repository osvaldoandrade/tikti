package domain

import (
	"strings"
	"testing"
)

func TestParseWorkloadSubject(t *testing.T) {
	tests := []struct {
		name    string
		subject string
		valid   bool
	}{
		{name: "service account", subject: "system:serviceaccount:code-admin:queue-controller", valid: true},
		{name: "dotted service account", subject: "system:serviceaccount:code-admin:queue.controller", valid: true},
		{name: "missing prefix", subject: "code-admin:queue-controller", valid: false},
		{name: "uppercase", subject: "system:serviceaccount:Code-Admin:queue-controller", valid: false},
		{name: "empty label", subject: "system:serviceaccount:code-admin:queue..controller", valid: false},
		{name: "namespace too long", subject: "system:serviceaccount:" + strings.Repeat("a", 64) + ":queue", valid: false},
		{name: "service account too long", subject: "system:serviceaccount:code-admin:" + strings.Repeat("a", 254), valid: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			subject, valid := ParseWorkloadSubject(test.subject)
			if valid != test.valid {
				t.Fatalf("ParseWorkloadSubject(%q) valid = %v", test.subject, valid)
			}
			if valid && subject.Subject != test.subject {
				t.Fatalf("ParseWorkloadSubject(%q) = %#v", test.subject, subject)
			}
		})
	}
}
