.PHONY: build test clean

BINARY=keytwig

build:
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o bin/$(BINARY) ./cmd/keytwig

test:
	CGO_ENABLED=0 go test ./...

clean:
	rm -rf bin/
