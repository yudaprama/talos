# Makefile for Ory Talos

# Variables
BINARY_NAME=talos
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT ?= $(shell git rev-parse HEAD 2>/dev/null || echo "unknown")
BUILD_TIME ?= $(shell date -u '+%Y-%m-%d_%H:%M:%S')
LDFLAGS := -ldflags="-w -s -X github.com/ory/talos/internal/version.Version=$(VERSION) -X github.com/ory/talos/internal/version.Commit=$(COMMIT) -X github.com/ory/talos/internal/version.BuildTime=$(BUILD_TIME)"

# Tools (run from go.mod)
OPENAPI_GENERATOR_VERSION := v2.28.0
ORY_CLI_VERSION := v1.2.0
# Pin prettier so fmt/fmt-check are deterministic. An unpinned `npx prettier`
# resolves whatever version is latest at run time, so a new release could flip
# fmt-check red with no code change.
PRETTIER_VERSION := 3.8.3

.PHONY: help
help: ## Show this help
	@echo "Ory Talos"
	@echo ""
	@echo "Usage: make <target>"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'
	@echo ""

# ============================================================================
# Development
# ============================================================================

.PHONY: build
build: ## Build binary (use TAGS=commercial for commercial build)
	@echo "Building binary..."
	CGO_ENABLED=0 go build $(LDFLAGS) $(if $(TAGS),-tags $(TAGS)) -o .bin/$(BINARY_NAME) .

.PHONY: build-commercial
build-commercial: ## Build commercial binary
	@$(MAKE) build TAGS=commercial BINARY_NAME=talos-commercial

.PHONY: test
test: test-db-check ## Run tests (use TAGS=commercial or PKG=./internal/crypto or ARGS=-v)
	TEST_POSTGRES_DSN='postgres://postgres:secret@localhost:5433/talos_test?sslmode=disable&pool_mode=standard' \
		TEST_MYSQL_DSN='mysql://root:secret@tcp(localhost:3307)/talos_test?parseTime=true&multiStatements=true&maxAllowedPacket=67108864&timeout=30s&readTimeout=30s&writeTimeout=30s' \
		TEST_COCKROACH_DSN='cockroach://root@localhost:26258/talos_test?sslmode=disable&pool_mode=standard' \
		go test -race -timeout 2m $(if $(TAGS),-tags $(TAGS)) $(if $(PKG),$(PKG),./...) $(ARGS)

.PHONY: coverage
coverage: test-db-check ## Run tests with coverage report
	@rm -f coverage*.out coverage*.html
	TEST_POSTGRES_DSN='postgres://postgres:secret@localhost:5433/talos_test?sslmode=disable&pool_mode=standard' \
		TEST_MYSQL_DSN='mysql://root:secret@tcp(localhost:3307)/talos_test?parseTime=true&multiStatements=true&maxAllowedPacket=67108864&timeout=30s&readTimeout=30s&writeTimeout=30s' \
		TEST_COCKROACH_DSN='cockroach://root@localhost:26258/talos_test?sslmode=disable&pool_mode=standard' \
		go test -race -count=1 -timeout 2m -coverpkg=$(if $(PKG),$(PKG),./...) -coverprofile=coverage$(if $(TAGS),-$(TAGS)).out -covermode=atomic $(if $(TAGS),-tags $(TAGS)) $(if $(PKG),$(PKG),./...) $(ARGS)
	@echo ""
	@echo "Coverage: $$(go tool cover -func=coverage$(if $(TAGS),-$(TAGS)).out | tail -1 | awk '{print $$NF}')"
	@go tool cover -html=coverage$(if $(TAGS),-$(TAGS)).out -o coverage$(if $(TAGS),-$(TAGS)).html
	@echo "Report: coverage$(if $(TAGS),-$(TAGS)).html"

.PHONY: lint
lint: ## Run linters (use FIX=1 to auto-fix, TAGS=commercial for commercial build)
	@go tool golangci-lint run $(if $(FIX),--fix) $(if $(TAGS),--build-tags $(TAGS)) --timeout 5m

# Paths to format/check: every top-level entry except the vendored oryx/ module
# (synced from github.com/ory/x). Pass directories (not an explicit file list) so
# gofumpt/goimports keep their built-in skip of generated files and dot-dirs;
# talos tooling must never reformat vendored or generated code.
FMT_GO_PATHS = $(wildcard *.go) $(shell find . -maxdepth 1 -mindepth 1 -type d -not -name oryx -not -name '.*')

.PHONY: fmt format
format: fmt ## Alias per Ory convention
fmt: ## Format code
	@go tool gofumpt -w $(FMT_GO_PATHS)
	@go tool goimports -w -local github.com/ory $(FMT_GO_PATHS)
	@go fix ./...
	@go mod tidy
	@npx prettier@$(PRETTIER_VERSION) --write "**/*.{js,jsx,ts,tsx,md,mdx}" --log-level warn

.PHONY: fmt-check
fmt-check: fmt-check-gofumpt fmt-check-goimports fmt-check-gomod fmt-check-prettier ## Check code formatting without rewriting files
	@echo "✓ Formatting check passed"

# fail-if-output: run "$2" and fail (with hint "$1") if it errors or prints anything.
# Prints stdout in either case so the user sees what's wrong (e.g. file list, mod diff).
define fail-if-output
	@out=$$($2); rc=$$?; if [ -n "$$out" ] || [ $$rc -ne 0 ]; then [ -n "$$out" ] && echo "$$out"; echo "Run '$1' to fix."; exit 1; fi
endef

.PHONY: fmt-check-gofumpt
fmt-check-gofumpt:
	$(call fail-if-output,make fmt,go tool gofumpt -l $(FMT_GO_PATHS))

.PHONY: fmt-check-goimports
fmt-check-goimports:
	$(call fail-if-output,make fmt,go tool goimports -l -local github.com/ory $(FMT_GO_PATHS))

.PHONY: fmt-check-gomod
fmt-check-gomod:
	$(call fail-if-output,go mod tidy,go mod tidy -diff)

.PHONY: fmt-check-prettier
fmt-check-prettier:
	@npx prettier@$(PRETTIER_VERSION) --check "**/*.{js,jsx,ts,tsx,md,mdx}" --log-level warn

.PHONY: generate-openapi
generate-openapi: .bin/ory ## Rename generated OpenAPI v2 spec and produce OpenAPI v3 spec with patches applied
	@echo "Renaming OpenAPI v2 spec..."
	@mv api/talos.swagger.json api/talos.openapi-v2.json
	@echo "Generating OpenAPI v3 spec and applying patches..."
	@.bin/ory dev openapi migrate \
		-p file://.schema/openapi/patches/responses.yaml \
		-p file://.schema/openapi/patches/jwks.yaml \
		api/talos.openapi-v2.json api/talos.openapi-v3.json
	@printf '\n' >> api/talos.openapi-v3.json

.PHONY: generate-sdk
generate-sdk: ## Generate Go HTTP client from OpenAPI spec
	@echo "Generating Go HTTP client from OpenAPI spec..."
	@rm -rf internal/client/generated
	@npx -y @openapitools/openapi-generator-cli@$(OPENAPI_GENERATOR_VERSION) generate \
		-i api/talos.openapi-v3.json \
		-g go \
		-o internal/client/generated \
		-c api/sdk/go.yaml
	@echo "Cleaning up generated client..."
	@rm -f internal/client/generated/go.mod internal/client/generated/go.sum
	@rm -rf internal/client/generated/.openapi-generator internal/client/generated/test
	@rm -f internal/client/generated/.travis.yml internal/client/generated/git_push.sh

.PHONY: generate
generate: ## Generate code (proto, sqlc, client, docs, cli docs, ts client)
	@echo "Generating protobuf code and API documentation..."
	@go tool buf generate
	@echo "Migrating OpenAPI spec to v3 and applying patches..."
	@$(MAKE) generate-openapi
	@echo "Generating HTTP SDKs..."
	@$(MAKE) generate-sdk
	@echo "Generating SQL queries (SQLite - OSS)..."
	@go tool sqlc generate -f internal/persistence/sqlc/sqlc.yaml
	@if [ -f commercial/persistence/sqlc/sqlc.yaml ]; then \
		echo "Generating SQL queries (PostgreSQL + MySQL - Commercial)..."; \
		go tool sqlc generate -f commercial/persistence/sqlc/sqlc.yaml; \
	else \
		echo "Skipping commercial SQL queries (commercial/ not present - OSS build)"; \
	fi
	@echo "Generating CLI documentation..."
	@go run ./cmd/clidoc ./docs/reference/cli
	@echo "Syncing documentation code blocks from source..."
	@go run ./tools/doctest --sync docs/integrate/sdk/go.md
	@echo "Generating API reference docs from OpenAPI spec..."
	@$(MAKE) build-api-doc
	@echo "Generating configuration reference..."
	@$(MAKE) build-config-doc
	@echo "Generating error codes reference..."
	@$(MAKE) build-error-codes-doc
	@echo "Generating events reference..."
	@$(MAKE) build-events-doc
	@echo "Formatting output..."
	@$(MAKE) fmt
	@echo ""
	@echo "Code generation complete"
	@echo "  - Go protobuf: pkg/"
	@echo "  - OpenAPI v2 spec: api/talos.openapi-v2.json"
	@echo "  - OpenAPI v3 spec: api/talos.openapi-v3.json"
	@echo "  - Go HTTP client: internal/client/generated/"
	@echo "  - API reference: docs/reference/api/"
	@echo "  - Config reference: docs/reference/config.md"
	@echo "  - Error codes reference: docs/reference/error-codes.md"
	@echo "  - CLI docs: docs/reference/cli/"
	@echo "  - SQL queries (SQLite): internal/persistence/sqlc/"
	@echo "  - SQL queries (PostgreSQL): commercial/persistence/sqlc/postgres/"
	@echo "  - SQL queries (MySQL): commercial/persistence/sqlc/mysql/"
	@echo "  - Doc test tool: .bin/doctest"

# ============================================================================
# OSS sync manifest (monorepo-only; not synced to github.com/ory/talos)
# ============================================================================

.PHONY: update-go-modules go-mod-tidy
update-go-modules: go-mod-tidy
go-mod-tidy:
	@go mod tidy
	@$(MAKE) generate-oss-manifest

.PHONY: generate-oss-manifest
generate-oss-manifest: ## Regenerate the cloudlib-free .oss/{go.mod,go.sum} for the OSS sync
	@bash .oss/generate.sh

.PHONY: check-oss-manifest
check-oss-manifest: ## Fail if .oss/{go.mod,go.sum} drift from a fresh generation
	@tmp=$$(mktemp -d); trap 'rm -rf "$$tmp"' EXIT; \
		bash .oss/generate.sh "$$tmp" >/dev/null; \
		if ! diff -u .oss/go.mod "$$tmp/go.mod" || ! diff -u .oss/go.sum "$$tmp/go.sum"; then \
			echo "OSS manifest is stale. Run 'make generate-oss-manifest' and commit."; exit 1; \
		fi; \
		echo "✓ OSS manifest up to date"

.PHONY: check-oss-sync-contract
check-oss-sync-contract: ## Fail if .oss/generate.sh and copy.bara.sky drift (list parity + transform coupling)
	@bash .oss/check-sync-contract.sh

# ============================================================================
# Database
# ============================================================================

.PHONY: migrate
migrate: build ## Run migrations (use CMD=up|down|status, DSN='sqlite3://db.db')
	@.bin/$(BINARY_NAME) migrate $(or $(CMD),up) $(if $(DSN),--database $(DSN))

# Test database management
.PHONY: test-db-start
test-db-start: ## Start test databases (Postgres, MySQL, CockroachDB)
	@echo "Checking test databases..."
	@if docker ps --format '{{.Names}}' | grep -q '^ory-talos-postgres-test$$'; then \
		echo "✓ PostgreSQL container already running"; \
	else \
		echo "Starting PostgreSQL container..."; \
		docker compose -f docker-compose.test.yml up -d postgres-test; \
	fi
	@if docker ps --format '{{.Names}}' | grep -q '^ory-talos-mysql-test$$'; then \
		echo "✓ MySQL container already running"; \
	else \
		echo "Starting MySQL container..."; \
		docker compose -f docker-compose.test.yml up -d mysql-test; \
	fi
	@if docker ps --format '{{.Names}}' | grep -q '^ory-talos-cockroach-test$$'; then \
		echo "✓ CockroachDB container already running"; \
	else \
		echo "Starting CockroachDB container..."; \
		docker compose -f docker-compose.test.yml up -d cockroach-test; \
	fi
	@echo "Waiting for databases to be healthy..."
	@for i in 1 2 3 4 5; do \
		if docker inspect --format='{{.State.Health.Status}}' ory-talos-postgres-test 2>/dev/null | grep -q healthy && \
		   docker inspect --format='{{.State.Health.Status}}' ory-talos-mysql-test 2>/dev/null | grep -q healthy && \
		   docker inspect --format='{{.State.Health.Status}}' ory-talos-cockroach-test 2>/dev/null | grep -q healthy; then \
			echo "✓ All databases healthy"; \
			break; \
		fi; \
		echo "Waiting for health checks... ($$i/5)"; \
		sleep 2; \
	done
	@echo "Ensuring CockroachDB test database exists..."
	@docker exec ory-talos-cockroach-test ./cockroach sql --insecure -e "CREATE DATABASE IF NOT EXISTS talos_test;" 2>&1 || echo "Warning: could not create CockroachDB test database (container may still be starting)"

.PHONY: test-db-stop
test-db-stop: ## Stop test databases (keeps data)
	@echo "Stopping test databases..."
	@docker compose -f docker-compose.test.yml down

.PHONY: test-db-clean
test-db-clean: ## Stop and remove test databases (including volumes)
	@echo "Removing test databases and volumes..."
	@docker compose -f docker-compose.test.yml down -v

.PHONY: test-db-logs
test-db-logs: ## Show test database logs (use DB=postgres|mysql|cockroach)
	@docker compose -f docker-compose.test.yml logs -f $(if $(DB),$(DB)-test)

# Helper to check if test DBs are running (starts if not)
.PHONY: test-db-check
test-db-check:
	@$(MAKE) test-db-start > /dev/null 2>&1 || true

# ============================================================================
# Quality
# ============================================================================

.PHONY: build-config-doc
build-config-doc: ## Generate config reference doc from JSON Schema
	@go run ./tools/config-doc-gen > docs/reference/config.md

.PHONY: build-error-codes-doc
build-error-codes-doc: ## Generate error codes reference doc from source
	@go run ./tools/error-codes-gen > docs/reference/error-codes.md

.PHONY: build-events-doc
build-events-doc: ## Generate audit events reference doc from source
	@go run ./tools/events-gen > docs/reference/events.md

.PHONY: build-api-doc
build-api-doc: ## Generate API reference docs from OpenAPI spec
	@if [ -d website/node_modules ]; then cd website && npx docusaurus clean-api-docs talos 2>/dev/null; npx docusaurus gen-api-docs talos; else echo "Skipping API doc generation (website/node_modules not found)"; fi

.PHONY: docs-lint
docs-lint: ## Lint documentation (frontmatter, length, placeholders)
	@./tools/docs-lint/lint.sh

.PHONY: docs-test
docs-test: docs-exec-test ## Test documentation examples with doctest

.PHONY: docs-drift
docs-drift: ## Check docs for drift against proto, swagger, config schema
	@echo "Checking docs for drift..."
	@go run ./tools/docs-drift-check docs

.PHONY: docs-sync
docs-sync: ## Sync doc code blocks from source file regions
	@echo "Syncing documentation code blocks..."
	@go run ./tools/doctest --sync docs/integrate/sdk/go.md

.PHONY: docs-exec-test
docs-exec-test: ## Test docs executable examples
	@echo "Testing documentation (executable code blocks)..."
	@find docs -path "docs/.deprecated" -prune -o -name "*.md" -print | \
		xargs grep -l "doctest:" | \
		xargs -I{} go run ./tools/doctest {}

.PHONY: docs-build
docs-build: ## Build Docusaurus docs site
	@cd website && npm ci && npm run build

.PHONY: docs-serve
docs-serve: ## Serve docs site locally
	@cd website && npm start

.PHONY: lint-sql
lint-sql: ## Fail on `SELECT *` or `RETURNING *` in sqlc query files
	@bad=$$(awk ' \
		BEGIN { RS=";"; bad=0 } \
		{ \
			s=$$0; \
			gsub(/--[^\n]*/, " ", s); \
			gsub(/[ \t\r\n]+/, " ", s); \
			if (match(s, /([^[:alnum:]_]|^)(SELECT|RETURNING)[ ]+\*/)) { \
				printf "%s: %s\n", FILENAME, s; \
				bad=1 \
			} \
		} \
		END { exit bad }' \
		internal/persistence/sqlc/queries.sql \
		commercial/persistence/sqlc/postgres/queries.sql \
		commercial/persistence/sqlc/mysql/queries.sql \
		2>/dev/null); \
	if [ -n "$$bad" ]; then \
		echo "lint-sql: forbidden SELECT */RETURNING * found:" >&2; \
		echo "$$bad" >&2; \
		echo "Replace with an explicit column list (AGENTS.md: Database Architecture Rules → Column selection)." >&2; \
		exit 1; \
	fi

.PHONY: verify
verify: fmt lint lint-sql coverage build docs-lint docs-test docs-drift ## Run all checks (pre-commit)
	@echo ""
	@echo "✓ All checks passed"

.PHONY: verify-ci
verify-ci: fmt-check lint coverage build docs-lint docs-test docs-drift ## Run CI-safe checks without rewriting files
	@echo ""
	@echo "✓ All CI checks passed"

.PHONY: bench
bench: ## Run benchmarks (use TAGS=commercial or PKG=./internal/verifier/...)
	go test -run='^$$' -bench=. -benchmem -timeout 5m $(if $(TAGS),-tags $(TAGS)) $(if $(PKG),$(PKG),./...)

.PHONY: load-test
load-test: ## Run k6 load tests with full setup (use SKIP_DOCKER=true if Postgres is already running)
	@if ! command -v k6 >/dev/null 2>&1; then \
		echo "Error: k6 is not installed. Install with: brew install k6"; \
		exit 1; \
	fi
	bash test/load/run.sh

.PHONY: clean
clean: ## Clean build artifacts
	@rm -rf .bin/* coverage*.out coverage*.html mocks/ .db/*.db

# ============================================================================
# Docker
# ============================================================================

.PHONY: docker
docker: ## Start dev environment (use CMD=up|down)
	docker compose -f deployments/docker/compose.yaml $(or $(CMD),up -d)

# ============================================================================
# Setup
# ============================================================================

.PHONY: deps
deps: ## Download dependencies
	@go mod download
	@go mod verify

.bin/ory: Makefile
	@mkdir -p .bin
	@curl --retry 7 --retry-connrefused https://raw.githubusercontent.com/ory/meta/master/install.sh | bash -s -- -b .bin ory $(ORY_CLI_VERSION)
	@touch -a -m .bin/ory

.PHONY: docs
docs: ## Serve documentation (use CMD=build|start)
	@cd website && npm $(or $(CMD),start)

.DEFAULT_GOAL := help
