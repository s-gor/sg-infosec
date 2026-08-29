.PHONY: fmt-check test race vet build check clean

fmt-check:
	@test -z "$$(gofmt -l cmd internal)" || { echo "gofmt required:"; gofmt -l cmd internal; exit 1; }

test:
	go test ./...

race:
	go test -race ./...

vet:
	go vet ./...

build:
	mkdir -p bin
	go build -o bin/sg-infosecd ./cmd/sg-infosecd
	go build -o bin/sg-infosecctl ./cmd/sg-infosecctl

check: fmt-check vet test race build

clean:
	rm -rf bin coverage.out
