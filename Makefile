.PHONY: help run build test test-coverage check-coverage lint dev-up dev-down migrate-up migrate-down generate clean hooks-install hooks-uninstall hooks-pre-commit hooks-pre-push

SERVER_DIR := apps/server
BINARY_NAME := phantom
GOLANGCI_LINT_VERSION := v1.64.8

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

# -- Dev Environment -----------------------------------------------------------

dev-up: ## Start local dependencies (PostgreSQL, Redis)
	docker compose up -d
	@echo "Waiting for services to be ready..."
	@sleep 2
	@docker compose ps

dev-down: ## Stop local dependencies
	docker compose down

dev-logs: ## Follow logs from all services
	docker compose logs -f

# -- Server -------------------------------------------------------------------

run: ## Run server with hot reload (requires: go install github.com/air-verse/air@latest)
	@cd $(SERVER_DIR) && set -a && . ./.env && set +a && air

run-plain: ## Run server without hot reload
	@cd $(SERVER_DIR) && set -a && . ./.env && set +a && go run ./cmd/api

build: ## Build production binary
	@cd $(SERVER_DIR) && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
		go build -ldflags="-w -s" -o bin/$(BINARY_NAME) ./cmd/api
	@echo "Binary built: $(SERVER_DIR)/bin/$(BINARY_NAME)"

# -- Tests --------------------------------------------------------------------

test: ## Run all tests
	@cd $(SERVER_DIR) && go test ./... -race -timeout 60s

test-unit: ## Run unit tests only
	@cd $(SERVER_DIR) && go test ./... -run Unit -race -short

test-integration: ## Run integration tests only
	@cd $(SERVER_DIR) && go test ./tests/integration/... -race -timeout 120s

test-coverage: ## Run tests and open coverage report
	@cd $(SERVER_DIR) && go test ./... -race -coverprofile=coverage.out -covermode=atomic
	@cd $(SERVER_DIR) && go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: $(SERVER_DIR)/coverage.html"
	@open $(SERVER_DIR)/coverage.html 2>/dev/null || xdg-open $(SERVER_DIR)/coverage.html 2>/dev/null || true

check-coverage: ## Check the non-bootstrap coverage threshold
	@sh ./scripts/check-coverage.sh

# -- Code Quality -------------------------------------------------------------

lint: ## Run golangci-lint
	@cd $(SERVER_DIR) && golangci-lint run ./...

vet: ## Run go vet
	@cd $(SERVER_DIR) && go vet ./...

fmt: ## Format all Go code
	@cd $(SERVER_DIR) && gofmt -w .
	@cd $(SERVER_DIR) && goimports -w .

security: ## Run vulnerability scanner
	@cd $(SERVER_DIR) && govulncheck ./...

# -- Database -----------------------------------------------------------------

migrate-up: ## Run all pending migrations
	@cd $(SERVER_DIR) && go run ./cmd/migrate up

migrate-down: ## Rollback last migration
	@cd $(SERVER_DIR) && go run ./cmd/migrate down

migrate-create: ## Create new migration (usage: make migrate-create NAME=add_users_table)
	@cd $(SERVER_DIR) && \
		num=$$(ls migrations/*.sql 2>/dev/null | wc -l | tr -d ' '); \
		next=$$(printf "%03d" $$((num + 1))); \
		touch migrations/$${next}_$(NAME).up.sql migrations/$${next}_$(NAME).down.sql; \
		echo "Created: migrations/$${next}_$(NAME).{up,down}.sql"

# -- Code Generation ----------------------------------------------------------

generate: ## Generate mocks and protobuf
	@cd $(SERVER_DIR) && go generate ./...
	@cd packages/proto && buf generate

# -- Cleanup ------------------------------------------------------------------

clean: ## Remove build artifacts
	@rm -rf $(SERVER_DIR)/bin $(SERVER_DIR)/coverage.out $(SERVER_DIR)/coverage.filtered.out $(SERVER_DIR)/coverage.html
	@echo "Cleaned"

# -- Setup (first time) -------------------------------------------------------

setup: ## Install all dev tools
	go install github.com/air-verse/air@latest
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)
	go install golang.org/x/vuln/cmd/govulncheck@latest
	go install golang.org/x/tools/cmd/goimports@latest
	go install go.uber.org/mock/mockgen@latest
	@echo "All tools installed"

# -- Git Hooks ----------------------------------------------------------------

hooks-install: ## Configure git to use the repository hooks
	git config core.hooksPath .githooks
	@chmod +x .githooks/pre-commit .githooks/pre-push scripts/hooks/*.sh
	@echo "Git hooks installed from .githooks"

hooks-uninstall: ## Remove repository-managed git hooks
	git config --unset core.hooksPath || true
	@echo "Git hooks uninstalled"

hooks-pre-commit: ## Run the same checks as the pre-commit hook
	@./scripts/hooks/pre-commit.sh

hooks-pre-push: ## Run the same checks as the pre-push hook
	@./scripts/hooks/pre-push.sh
