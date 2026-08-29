.PHONY: fmt-check test race vet build check kernel-smoke resource-smoke smoke clean

fmt-check:
	@test -z "$$(gofmt -l cmd internal pkg tests)" || { echo "gofmt required:"; gofmt -l cmd internal pkg tests; exit 1; }

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
	go build -o bin/sg-infosec-enforcerd ./cmd/sg-infosec-enforcerd

check: fmt-check vet test race build

kernel-smoke:
	bash scripts/smoke-kernel-netns.sh

resource-smoke:
	bash scripts/smoke-resource.sh

smoke: check kernel-smoke resource-smoke

clean:
	rm -rf bin coverage.out
