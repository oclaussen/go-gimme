all: test lint

.PHONY: fmt
fmt:
	go fmt ./...

.PHONY: lint
lint:
	golangci-lint run --enable-all

.PHONY: test
test:
	go test -cover ./...
