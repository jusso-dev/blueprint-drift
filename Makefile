BINARY := blueprint-drift

.PHONY: build test lint style clean

build:
	CGO_ENABLED=0 go build -o bin/$(BINARY) ./cmd/blueprint-drift

test:
	go test -race -v ./...

lint:
	@test -z "$$(gofmt -s -l .)" || (echo "Unformatted Go files:"; gofmt -s -l .; exit 1)
	go vet ./...

style:
	python3 scripts/style-check.py

clean:
	rm -rf bin/ dist/
