.PHONY: build test test-race check clean

BINARY=keytwig

build:
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o bin/$(BINARY) ./cmd/keytwig

test:
	CGO_ENABLED=0 go test ./...

test-race:
	go test -race -count=1 ./...

check:
	go vet ./...
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build ./...
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build ./...
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build ./...

clean:
	rm -rf bin/
