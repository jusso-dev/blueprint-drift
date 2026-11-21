BINARY := blueprint-drift

.PHONY: build test lint style validate clean

build:
	CGO_ENABLED=0 go build -o bin/$(BINARY) ./cmd/blueprint-drift

test:
	go test -race -v ./...

lint:
	@test -z "$$(gofmt -s -l .)" || (echo "Unformatted Go files:"; gofmt -s -l .; exit 1)
	go vet ./...

validate:
	python3 -m json.tool blueprint/schema/settings.schema.json > /dev/null
	go run ./cmd/blueprint-drift validate --blueprint blueprint/settings

style:
	python3 scripts/style-check.py

clean:
	rm -rf bin/ dist/
