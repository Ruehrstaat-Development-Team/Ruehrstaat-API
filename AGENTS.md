# AGENTS.md

Guidance for coding agents working in `/mnt/devdrive/Ruehrstaat/Ruehrstaat-API`.

## Scope
- This repository is a single Go module: `ruehrstaat-backend`.
- The app entrypoint is `main.go`.
- API routes are mounted from `api/index.go` under `/v1`.
- Core stack: Gin, GORM, Postgres, Redis, Sentry.
- There was no pre-existing `AGENTS.md` to preserve.

## Repo-Specific Rule Files
- No `.cursorrules` file exists.
- No `.cursor/rules/` directory exists.
- No `.github/copilot-instructions.md` file exists.
- Do not assume hidden Cursor or Copilot instructions beyond this file.

## Repository Layout
- `api/`: HTTP handlers, route registration, request DTOs.
- `auth/`: authentication, authorization, tokens, FIDO2, Discord login.
- `db/`: database bootstrap and GORM wiring.
- `db/entities/`: persistent models such as `User`, `Carrier`, and token models.
- `cache/`: Redis-backed temporary state and locking helpers.
- `serialize/`: response serializers and JSON shaping helpers.
- `services/`: domain and external-service integrations.
- `mailer/`: email generation and SMTP logic.
- `errors/`: application error type and response helpers.
- `logging/`: package logger wrapper.
- `util/`: small shared helpers.

## Environment And Runtime
- The service expects `.env` at repo root.
- Use `.env.example` as the reference for required variables.
- Do not edit `.env` directly; the user manages environment files.
- The app listens on `:8000`.
- Health check: `GET /v1/health`.
- Local Postgres and Redis are defined in `docker-compose.yml`.
- Startup initializes Sentry, database, Redis cache, and optional Moria integration.

## Build, Run, Test, And Lint
- Start local dependencies: `docker compose up db redis`
- Run the API: `go run .`
- Full build: `go build ./...`
- Docker image build: `docker build -t ruehrstaat-api .`
- The Dockerfile builds with `go build -o .bin/app`.
- Format code: `go fmt ./...`
- Formatting check only: `gofmt -l $(git ls-files '*.go')`
- Static analysis: `go vet ./...`
- Full test pass: `go test ./...`
- Current repo status: there are no `*_test.go` files, so `go test ./...` is a compile-level smoke test and reports `[no test files]`.
- Run one package test pass: `go test ./api/users`
- Replace `./api/users` with the package you changed.
- Run one named test when tests exist: `go test ./path/to/package -run TestName`
- Run one subtest when tests exist: `go test ./path/to/package -run 'TestName/subcase'`
- Safe validation sequence after code changes: `go fmt ./...`, `go vet ./...`, `go test ./...`, `go build ./...`

## Coding Style
- Follow the existing code more closely than generic Go style advice.
- Prefer the smallest correct change over cleanup-driven refactors.
- Keep logic local unless there is a clear reuse boundary already present in the code.
- Preserve package boundaries; do not invent new layers without a concrete need.

## Imports And Formatting
- Let `gofmt` govern formatting.
- Prefer `go fmt ./...` for repository-wide formatting.
- Keep imports clean and unused-import free.
- Existing files commonly group standard library imports, module-local imports, and third-party imports.
- Use module-local imports with the `ruehrstaat-backend/...` prefix.
- Only add import aliases when they improve readability or match existing usage.
- Pragmatic aliases already exist, for example `jsoniter`.
- Keep comments sparse and useful.
- Match surrounding capitalization, spacing, and file-local style.

## Naming
- Exported identifiers use PascalCase.
- Unexported identifiers use lowerCamelCase.
- Route registration functions are typically named `RegisterRoutes`.
- Package loggers are commonly `var log = logging.Logger{Package: "..."}`.
- DTO names often end in `Body`, `Dto`, or `DTO` depending on the file.
- Match the nearby file's acronym style instead of normalizing everything.
- Existing naming examples include `CmdrName`, `Otp`, `Dto`, and `Fido2`.
- JSON keys use camelCase such as `cmdrName`, `isAdmin`, and `newEmail`.

## Types, DTOs, And Serializers
- Persistent GORM models live in `db/entities` and are usually exported singular types.
- Preserve existing GORM tag style when editing entity fields.
- Optional request fields commonly use pointers so handlers can distinguish omitted from zero values.
- This is already used in DTOs such as `IsAdmin *bool` and `Otp *string`.
- Keep DTOs near the handlers that use them unless a shared type already exists.
- Reuse serializer types in `serialize/` instead of building large ad-hoc JSON payloads inline.
- If a response field changes for an entity, update the relevant serializer instead of scattering shape changes across handlers.
- Prefer existing `serialize.JsonObj` and serializer helpers when they already cover the response shape.

## HTTP And Gin Conventions
- Register routes in the package that owns the route group.
- Use `api.Group(...)` to mirror existing route structure.
- Bind request bodies with `c.ShouldBindJSON(...)`.
- Read path params with `c.Param(...)` and query params with `c.Query(...)`.
- Existing auth flows use cookies; keep `c.SetCookie(...)` when working in those paths.
- Successful responses are usually `c.JSON(status, gin.H{...})` or serializer output.
- Simple success responses commonly use a `message` field in `gin.H`.
- Keep handlers straightforward; avoid introducing a central mega-handler file.
- `auth/authorization.go` helpers may already write the HTTP response; respect their boolean return value.
- User and token data are commonly pulled from Gin context through the auth helpers.

## Error Handling
- Expected application errors use `*errors.RstError` from `errors/error.go`.
- Return application errors with `errors.ReturnWithError(c, err)`.
- On JSON bind failures, existing handlers usually call `c.Error(err)` and then return `dtoerr.InvalidDTO`.
- When the surrounding code records errors with `c.Error(...)`, keep doing that so the middleware logger and Sentry capture context.
- Follow the local pattern of checking well-known sentinel errors explicitly before falling back to a generic server error.
- Do not replace established `RstError` flows with arbitrary raw strings unless the surrounding code already does that.
- Unexpected infrastructure failures are often escalated with `panic(err)`.
- Panics are recovered in `main.go`, logged, and reported to Sentry.

## Logging
- Use the custom logger from `logging/logger.go` for package-scoped logging.
- Keep the package label short and aligned with nearby files.
- Prefer `log.Println`, `log.Printf`, or `log.Fatal*` through that wrapper.
- Do not introduce an additional logging framework.

## Database And Persistence
- Use the shared global `db.DB` handle.
- Database initialization and `AutoMigrate` live in `db/db.go`.
- UUID primary keys use `uuid_generate_v4()`.
- Follow existing GORM patterns such as `Model`, `Where`, `Count`, `Updates`, `Preload`, and hooks.
- Use `db.DB.Transaction(...)` when a change spans multiple writes that must succeed together.
- Entity hooks are already used and are acceptable when they fit the existing model.
- Keep database-facing logic close to the existing service or entity patterns rather than adding a repository layer.

## Testing Guidance For New Work
- There are no tests today, so use standard Go `testing` when adding new coverage.
- Put tests in `*_test.go` files next to the package they cover.
- For HTTP handlers, prefer `net/http/httptest` with Gin.
- Table-driven tests are a good default if you add coverage for service or utility packages.
- After adding tests, run the narrowest useful package command first, then `go test ./...`.
- After adding tests, document the most specific command that runs the new test.

## Agent Expectations
- Make the smallest correct change.
- Do not edit environment files directly.
- Avoid new frameworks, generators, or infrastructure unless the task requires them.
- Validate meaningful code changes with at least `go test ./...` and `go build ./...` before handing off.
