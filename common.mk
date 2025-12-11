# This file is the core of the build system.  You should generally try to avoid
# modifying this file, instead preferring to put project-specific changes in
# Makefile and user-specific changes in local.mk.  Doing so should help minimize
# merge conflicts in the build system, making it easier to pull in changes from
# the sample project.

APP?=cli-extension-secrets

ARCH?=$(shell go env GOARCH)
CIRCLE_PROJECT_REPONAME?=${APP}
CIRCLE_SHA1?=dev
CIRCLE_WORKFLOW_ID?=dev
CONTAINER_REGISTRY?=us-docker.pkg.dev/polaris-gcp-gar/polaris
GO_BIN?=$(shell pwd)/.bin/go
NODE_BIN?=$(shell pwd)/node_modules/.bin
PYTHON_PATH?=$(shell pwd)/.bin/python
OS?=$(shell go env GOOS)

export PYTHONPATH=$(PYTHON_PATH)
SHELL:=env PATH=$(GO_BIN):$(NODE_BIN):$(PYTHON_PATH)/bin:$(PATH) $(SHELL)

# Tooling versions as served by CircleCI cimg/go convenience image
# https://github.com/CircleCI-Public/cimg-go/blob/main/1.23/Dockerfile#L27-L28
GOTESTSUM_V?=1.12.0
GOCI_LINT_V?=v2.7.2
PRE_COMMIT_V?=v3.8

.DEFAULT_GOAL:=help

.PHONY: configure
configure: ## Configure local development setup
	git config --global --replace-all url."git@github.com:snyk".insteadOf "https://github.com/snyk"
	go env -w GOPRIVATE=github.com/snyk
	helm repo add polaris-charts http://polaris-charts.infra
	pre-commit install --hook-type commit-msg --hook-type pre-commit
	test -f config.local.json || echo '{}' >> config.local.json

.PHONY: cover
cover: test ## Generate coverage profile and display it in a web browser
	go tool cover -html=test/results/cover.out -o test/results/cover.html
ifndef CI
	open test/results/cover.html
endif

.PHONY: docker-build
docker-build: ## Build the docker image for the service
	docker build \
		--build-arg APP=${APP} \
		--secret id=gh_token,env=GITHUB_PRIVATE_TOKEN \
		-t ${CIRCLE_PROJECT_REPONAME}:${CIRCLE_WORKFLOW_ID} \
		-t ${CONTAINER_REGISTRY}/${APP}:${CIRCLE_SHA1} .

.PHONY: docker-run
docker-run: docker-build ## Run the docker image for the service
	docker run -t \
		-e SERVICE_ENV=dev \
		-p 8080:8080 ${CONTAINER_REGISTRY}/${APP}:${CIRCLE_SHA1}

.PHONY: download
download: ## Download dependencies to local cache
	go mod download

.PHONY: format
format: ## Format source code based on golangci and prettier configuration
	golangci-lint run --fix -v ./...
	prettier --write .

.PHONY: generate
generate:  ## Run commands described by //go:generate directives within source code
	go generate ./... 


.PHONY: helm-deps-build
helm-deps-build: ## Pull locally the helm dependencies from the Chart.lock
	pushd helm/ && helm dependency build && popd

.PHONY: helm-deps-update
helm-deps-update: ## Update the on-disk helm dependencies to mirror Chart.yaml
	pushd helm/ && helm dependency update && popd

.PHONY: help
help:
	@grep -hE '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

.PHONY: install-tools
install-tools: ## Install golangci-lint, gotestsum, code formatters, and tooling defined in tools.go
	mkdir -p ${GO_BIN}
	@cat tools.go | grep _ | awk -F'"' '{print $$2}' | xargs -tI % sh -c 'GOBIN=${GO_BIN} go install %'
ifndef CI
	curl -sSfL 'https://raw.githubusercontent.com/golangci/golangci-lint/${GOCI_LINT_V}/install.sh' | sh -s -- -b ${GO_BIN} ${GOCI_LINT_V}
	curl -sSfL 'https://github.com/gotestyourself/gotestsum/releases/download/v${GOTESTSUM_V}/gotestsum_${GOTESTSUM_V}_${OS}_${ARCH}.tar.gz' | tar -xz -C ${GO_BIN} gotestsum
	pip3 install --target=${PYTHON_PATH} pre-commit==${PRE_COMMIT_V}
endif
	npm clean-install

.PHONY: lint
lint: lint-go lint-secrets ## Run all linters

.PHONY: lint-go
lint-go: ## Run golangci linters
ifdef CI
	mkdir -p test/results
	golangci-lint run --out-format junit-xml ./... > test/results/lint-tests.xml
else
	golangci-lint run -v ./...
endif

.PHONY: lint-secrets
lint-secrets: ## Run gitleaks
	gitleaks detect -v --redact


.PHONY: test
test: ## Run unit tests
	mkdir -p test/results
	gotestsum --junitfile test/results/unit-tests.xml -- -race -coverprofile=test/results/cover.out -v ./...

.PHONY: test-integration
test-integration: ## Run integration tests
	mkdir -p test/results
	gotestsum --junitfile test/results/integration-tests.xml -- -count=1 -tags integration -v ./test/...

.PHONY: update-deps
update-deps: ## Update all dependencies to newer minor or patch releases
	go get -d -u ./...
	go mod tidy
