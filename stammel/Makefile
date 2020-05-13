OUT_DIR := bin
PROG := stammel_go

GOOS ?= $(shell go env GOOS)
GOARCH ?= $(shell go env GOARCH)

ifeq ($(GOOS),windows)
	BIN_SUFFIX := ".dll"
endif

.PHONY: build
build:
	go build -trimpath -mod=vendor -buildmode=c-shared -ldflags "-s -w -X main.goversion=1.14" -o $(OUT_DIR)/$(PROG)$(BIN_SUFFIX) ./

.PHONY: dep
clean:
	go clean -ldflags "-s -w -X main.goversion=1.14"
dep:
	dep ensure

.PHONY: test
test:
	go test -race ./...

.PHONY: check
check:
	gofmt -l -s -d pkg/ cmd/
	go tool vet pkg/ cmd/

.PHONY: integration
integration:
ifeq ($(GOOS),windows)
else
	hack/integration.sh
endif
