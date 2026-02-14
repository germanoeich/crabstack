GO_MODULE_DIRS := integration lib/types projects/crab-gateway projects/crab-cli

.PHONY: fmt vet test check

fmt:
	@set -eu; \
	for dir in $(GO_MODULE_DIRS); do \
		echo "==> $$dir: go fmt ./..."; \
		( cd $$dir && go fmt ./... ); \
	done

vet:
	@set -eu; \
	for dir in $(GO_MODULE_DIRS); do \
		echo "==> $$dir: go vet ./..."; \
		( cd $$dir && go vet ./... ); \
	done

test:
	@set -eu; \
	for dir in $(GO_MODULE_DIRS); do \
		echo "==> $$dir: go test ./..."; \
		( cd $$dir && go test ./... ); \
	done

check: fmt vet test
