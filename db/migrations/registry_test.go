package migrations

import "testing"

func TestMigrationRegistryInvariants(t *testing.T) {
	requiredIDs := map[string]bool{
		migrationAuthSessionSchemaID:                false,
		"20260402_001_refresh_token_hash_backfill":  false,
		migrationRefreshTokenPlaintextCleanupID:     false,
		migrationUserEmailCaseInsensitiveUniqueID:   false,
		migrationUserEmailNormalizedTrimmedUniqueID: false,
		migrationFido2DisplayNameUserScopedUniqueID: false,
	}
	seen := make(map[string]struct{}, len(migrations))

	if len(migrations) == 0 {
		t.Fatal("migrations registry is empty")
	}

	for i, migration := range migrations {
		if migration.ID == "" {
			t.Fatalf("migration[%d] has empty ID", i)
		}
		if migration.Desc == "" {
			t.Fatalf("migration[%s] has empty description", migration.ID)
		}
		if migration.Up == nil {
			t.Fatalf("migration[%s] has nil Up func", migration.ID)
		}
		for _, table := range migration.Requires {
			if table == "" {
				t.Fatalf("migration[%s] has empty prerequisite table name", migration.ID)
			}
		}
		if _, exists := seen[migration.ID]; exists {
			t.Fatalf("duplicate migration ID %q", migration.ID)
		}
		seen[migration.ID] = struct{}{}
		if _, required := requiredIDs[migration.ID]; required {
			requiredIDs[migration.ID] = true
		}
	}

	for id, present := range requiredIDs {
		if !present {
			t.Fatalf("required migration %q missing from registry", id)
		}
	}
}
