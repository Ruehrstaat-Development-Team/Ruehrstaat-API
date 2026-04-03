## Ruehrstaat-API Alignment And Hardening Plan

This plan aligns `Ruehrstaat-API` with the shared production hardening patterns already implemented in `mtn-backend`, while preserving Ruehrstaat-specific domain behavior.

Current baseline after the latest production fixes:
- Startup can run tracked migrations without `DB_AUTOMIGRATE=true`, while failing fast if the required auth/session runtime schema is still missing.
- The repo has focused unit and handler smoke tests around auth/session issuance and origin checks, token generation and helper behavior, migration registry behavior, redirect validation, AES key parsing, and security audit logging.
- CI runs `go test ./...`, `go vet ./...`, and `go build ./...`, but it does not provision Postgres or Redis for end-to-end auth/session integration coverage.

Status legend:
- [ ] pending
- [x] completed

## Goals

- [x] Upgrade the module to Go `1.26`.
- [x] Align shared dependency versions with `mtn-backend` where the libraries overlap.
- [x] Replace the current refresh-token flow with the MTN-style session model.
- [x] Stop storing sensitive one-time tokens and secrets in plaintext where avoidable.
- [x] Add tracked database migrations instead of relying only on unconditional `AutoMigrate`.
- [x] Improve `.env.example` readability and document the new required and optional environment variables.
- [x] Add baseline automated tests and CI smoke validation for the highest-risk auth and migration paths.

## Constraints

- [x] Keep changes limited to `Ruehrstaat-API`.
- [x] Preserve Ruehrstaat-specific routes, DTOs, and entity fields unless a hardening change requires schema updates.
- [x] Avoid editing `.env`; only update `.env.example`.
- [x] Prefer the smallest correct port of MTN improvements instead of wholesale copying unrelated MTN features.

## Phase 1: Planning And Baseline

- [x] Review `Ruehrstaat-API` against `mtn-backend` and identify gaps in auth, secrets, DB bootstrap, migrations, tests, and dependencies.
- [x] Snapshot the current Ruehrstaat API surface and auth flow assumptions from the existing code.
- [x] Create and maintain this plan file as the canonical task list for the migration.

## Phase 2: Toolchain And Dependency Alignment

- [x] Update `go.mod` from Go `1.22` to `1.26`.
- [x] Align overlapping dependency versions to the current `mtn-backend` versions, including at minimum:
  - [x] `github.com/getsentry/sentry-go`
  - [x] `github.com/getsentry/sentry-go/gin`
  - [x] `github.com/gin-gonic/gin`
  - [x] `github.com/go-playground/validator/v10`
  - [x] `github.com/go-webauthn/webauthn`
  - [x] `github.com/golang-jwt/jwt/v5`
  - [x] `github.com/lib/pq`
  - [x] `github.com/lindell/go-burner-email-providers`
  - [x] `github.com/pquerna/otp`
  - [x] `github.com/redis/go-redis/v9`
  - [x] `golang.org/x/crypto`
  - [x] `golang.org/x/oauth2`
  - [x] `gorm.io/driver/postgres`
  - [x] `gorm.io/gorm`
- [x] Run `go mod tidy` and keep only necessary direct dependencies.
- [x] Fix compile breaks caused by upgraded libraries before moving on.

## Phase 3: Core Auth Session Model

- [x] Replace the current refresh token persistence with a session-backed model.
- [x] Expand `entities.RefreshToken` to support:
  - [x] `TokenHash`
  - [x] `CreatedAt`
  - [x] `UpdatedAt`
  - [x] `LastUsedAt`
  - [x] `ExpiresAt`
  - [x] `AuthTime`
  - [x] `ClientIP`
  - [x] `UserAgent`
  - [x] `DeviceName`
  - [x] `Country`
  - [x] `Region`
  - [x] `City`
  - [x] `SessionType`
- [x] Add `entities.AccessTokenJTI` for access-token allowlisting.
- [x] Add helper functions for:
  - [x] creating sessions
  - [x] rotating refresh tokens
  - [x] revoking one session
  - [x] revoking all sessions for a user
  - [x] checking access-token JTI allowlist
- [x] Change login to:
  - [x] create a session row
  - [x] store only a hashed refresh token
  - [x] issue access tokens with `sid` and `jti`
  - [x] stop relying on plaintext persisted refresh tokens for new sessions
- [x] Change refresh to:
  - [x] look up by hashed refresh token first
  - [x] temporarily support legacy plaintext rows during migration until tracked backfill/cleanup removes them
  - [x] use row locking during token rotation
  - [x] revoke all sessions if refresh-token reuse is detected
- [x] Change logout to:
  - [x] support expired refresh tokens for revocation
  - [x] revoke one session or all sessions cleanly
- [x] Change token extraction to enforce JTI allowlisting when `jti` and `sid` are present.
- [x] Ensure login no longer issues an untracked refresh token.

## Phase 4: JWT And Secret Hardening

- [x] Remove insecure fallback secrets from JWT generation.
- [x] Enforce minimum secret lengths for:
  - [x] `JWT_IDENTITY_SECRET`
  - [x] `JWT_REFRESH_SECRET`
- [x] Update token decoding to validate the expected audience.
- [x] Add a dedicated identity-token generator that includes `sid` and returns the generated `jti`.
- [x] Add a generic token hashing helper for non-password token storage.

## Phase 5: User Security Hardening

- [x] Add password strength validation consistent with MTN.
- [x] Add explicit bcrypt cost constant and use it for newly created hashes.
- [x] Add transparent password rehash on successful login when older hashes are detected.
- [x] Normalize emails with `strings.ToLower(strings.TrimSpace(...))`.
- [x] Use normalized email lookup paths for login, registration, and email change.
- [x] Add normalized email locking to avoid duplicate-registration and duplicate-email-change races.
- [x] Change activation, password-reset, and email-change flows to:
  - [x] store hashed one-time tokens
  - [x] send plaintext tokens by email only
  - [x] compare hashed values during validation
- [x] Add infra secret hashing with a legacy plaintext migration path.
- [x] Keep existing API token hashing behavior intact and validate it still works after dependency upgrades.

## Phase 6: OTP And FIDO Hardening

- [x] Add OTP encryption helpers with transparent backward-compatible decryption.
- [x] Add FIDO credential encryption helpers with transparent backward-compatible decryption.
- [x] Update TOTP setup and verification flow to store encrypted secrets when encryption is enabled.
- [x] Update backup-code storage and consumption so backup codes can be stored encrypted while still accepting legacy plaintext entries.
- [x] Update FIDO registration to encrypt stored credential payloads when enabled.
- [x] Update FIDO login to decrypt stored credentials before validation.
- [x] Harden FIDO user-handle parsing so malformed input returns errors instead of panicking.

## Phase 7: Rate Limiting And Audit Logging

- [x] Add Redis/cache-backed rate limiting for:
  - [x] login attempts
  - [x] OTP attempts
  - [x] password reset requests
  - [x] registration attempts
- [x] Add structured security audit logging.
- [x] Initialize security audit logging during startup.
- [x] Log at least the key events ported from MTN where they apply:
  - [x] login success/failure/rate limit
  - [x] registration success/failure/rate limit
  - [x] password reset and password change
  - [x] account activation
  - [x] 2FA failures and backup-code usage
  - [x] logout and session revocation

## Phase 8: DB Bootstrap And Migration Framework

- [x] Add DB connection pool configuration.
- [x] Add a tracked migration framework with a `db_migrations` table.
- [x] Add advisory locking for migration execution in Postgres.
- [x] Gate `AutoMigrate` behind environment flags instead of always running it.
- [x] Run tracked migrations/backfills through the new migration framework.
- [x] Keep tracked migrations runnable without `DB_AUTOMIGRATE=true`, while deferring them safely when prerequisite tables are missing and failing fast if runtime auth/session schema would still be broken.
- [x] Add targeted migrations for:
  - [x] case-insensitive and trimmed email index support
  - [x] legacy refresh-token hash backfill that `AutoMigrate` cannot express
- [x] Decide whether DB-backed cache fallback is needed.
  - [ ] If it is low-risk and justified, port it.
  - [x] Otherwise leave general cache storage Redis-only for now and document the decision, while keeping frontend email-link references self-contained and durable.

## Phase 9: Environment Documentation

- [x] Restructure `.env.example` into logical sections.
- [x] Add comments describing each section and notable variables.
- [x] Document newly introduced variables, including at minimum:
  - [x] `JWT_IDENTITY_SECRET`
  - [x] `JWT_REFRESH_SECRET`
  - [x] `DB_AUTOMIGRATE`
  - [x] `DB_RUN_TRACKED_MIGRATIONS`
  - [x] `OTP_ENC_KEY`
  - [x] `FIDO_ENC_KEY`
  - [x] `SECURITY_AUDIT_LOG_PATH`
  - [x] any Sentry sampling variable used by the ported code

## Phase 10: Tests And CI

- [x] Add focused unit and smoke tests for auth and migration behavior.
- [x] Add at least:
  - [x] auth helper and handler smoke tests
  - [x] password strength tests
  - [x] token generation and claim-shape tests
  - [x] migration registry and related helper smoke tests where practical
  - [x] encryption helper and security audit log smoke tests
- [x] Add CI workflow(s) for:
  - [x] `go test ./...`
  - [x] `go vet ./...`
  - [x] `go build ./...`
- [x] Keep the existing Docker publishing workflow intact unless a minimal adjustment is required.
- [x] Keep coverage claims narrow: current CI exercises focused package-level unit and handler smoke coverage plus compile/static-analysis baselines, not a full integration test suite.

## Phase 11: Validation

- [x] Run `go fmt ./...`.
- [x] Run `go test ./...`.
- [x] Run `go vet ./...`.
- [x] Run `go build ./...`.
- [x] Check for any `.env.example` or docs mismatches introduced by the migration.

## Phase 12: Independent Review Loop

- [x] Run at least one independent code review agent against the changed Ruehrstaat API files.
- [x] Fix every substantive issue the review finds.
- [x] Re-run validation after fixes.
- [x] Run a second independent review pass.
- [x] Repeat until the review comes back clean or only contains acceptable residual risks.

## Notes And Decisions

- Decision: upgrade to Go `1.26` immediately.
- Decision: adopt the MTN multi-session model rather than preserving single-session behavior.
- Decision: introduce the new environment variables in `.env.example` and improve readability there.
- Decision: add and preserve MTN-style row locking around user write paths, including the lookup/select phase before mutation, to reduce simultaneous-write races.
- Decision: keep general cache storage Redis-only for now; do not port DB-backed cache fallback in this pass. Frontend email-link references now use self-contained encrypted values instead of Redis-backed cache state.
- Decision: allow tracked migrations to run independently of `DB_AUTOMIGRATE`, but fail startup when the required auth/session runtime schema is still missing so production cannot silently boot against a broken schema.
- Decision: OTP and FIDO encrypted payload handling must fail closed when encryption keys are missing or malformed; those features now require valid `OTP_ENC_KEY` and `FIDO_ENC_KEY` values.
- Decision: the refresh-token plaintext compatibility path was transitional only; after the tracked backfill/cleanup migration runs, runtime matching relies on hashed tokens rather than legacy plaintext rows.
