package migrations

import (
	"errors"
	"testing"
)

func TestIsAlreadyExistsError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "nil", err: nil, want: false},
		{name: "already exists text", err: errors.New("relation already exists"), want: true},
		{name: "duplicate text", err: errors.New("duplicate key value violates unique constraint"), want: true},
		{name: "postgres duplicate object code", err: errors.New("pq: ERROR: duplicate_object (SQLSTATE 42710)"), want: true},
		{name: "postgres duplicate table code", err: errors.New("pq: ERROR: relation exists (SQLSTATE 42P07)"), want: true},
		{name: "unrelated error", err: errors.New("permission denied"), want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isAlreadyExistsError(tt.err); got != tt.want {
				t.Fatalf("isAlreadyExistsError(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

func TestDeferredMigrationErrorImplementsError(t *testing.T) {
	err := deferredMigrationError{reason: "deferred for manual cleanup"}
	if got := err.Error(); got != "deferred for manual cleanup" {
		t.Fatalf("deferredMigrationError.Error() = %q, want %q", got, "deferred for manual cleanup")
	}
}

func TestMissingRequiredTables(t *testing.T) {
	hasTables := map[string]bool{
		"users":          true,
		"refresh_tokens": false,
	}

	got := missingRequiredTables([]string{"users", "refresh_tokens", ""}, func(table string) bool {
		return hasTables[table]
	})

	if len(got) != 1 || got[0] != "refresh_tokens" {
		t.Fatalf("missingRequiredTables() = %v, want [refresh_tokens]", got)
	}
}

func TestMissingRuntimeSchemaObjects(t *testing.T) {
	hasTables := map[string]bool{
		"refresh_tokens":    true,
		"access_token_jtis": false,
	}
	hasColumns := map[string]map[string]bool{
		"refresh_tokens": {
			"created_at":   true,
			"updated_at":   true,
			"token_hash":   true,
			"last_used_at": true,
			"expires_at":   true,
			"auth_time":    false,
			"client_ip":    true,
			"user_agent":   true,
			"device_name":  true,
			"country":      true,
			"region":       true,
			"city":         true,
			"session_type": true,
		},
	}

	got := missingRuntimeSchemaObjects(func(table string) bool {
		return hasTables[table]
	}, func(table string, column string) bool {
		return hasColumns[table][column]
	})

	want := []string{"refresh_tokens.auth_time", "access_token_jtis"}
	if len(got) != len(want) {
		t.Fatalf("missingRuntimeSchemaObjects() len = %d, want %d (%v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("missingRuntimeSchemaObjects()[%d] = %q, want %q (full=%v)", i, got[i], want[i], got)
		}
	}
}
