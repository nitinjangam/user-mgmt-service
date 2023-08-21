GOBIN := $(or $(GOBIN),$(shell pwd)/bin)

# Dependency versions
MOCKERY_VERSION ?= v2.14.0
OAPI_CODEGEN_VERSION ?= v1.12.4
GOLANGCI_LINT_VERSION ?= v1.50.1

export GOPRIVATE=https://github.com/nitinjangam
export GOPROXY=direct

install-deps:
	echo "Checking dependencies"

	# Mockery
	command -v ${GOBIN}/mockery --version >/dev/null 2>&1 || echo "Installing mockery $(MOCKERY_VERSION)" && GOBIN=$(GOBIN) go install github.com/vektra/mockery/v2@$(MOCKERY_VERSION) && echo "verify mockery installation" ${GOBIN}/mockery --version

	# oapi-codegen
	command -v ${GOBIN}/oapi-codegen --version >/dev/null 2>&1 || echo "Installing oapi-codegen $(OAPI_CODEGEN_VERSION)" && GOBIN=$(GOBIN) go install github.com/deepmap/oapi-codegen/cmd/oapi-codegen@$(OAPI_CODEGEN_VERSION) && echo "verify oapi-codegen installation" ${GOBIN}/oapi-codegen --version

generate: install-deps
	PATH=$(PATH):$(GOBIN) go generate -x ./...
