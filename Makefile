BINARY  := arca
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

# Hardened, reproducible build: pure Go (no cgo), trimmed paths, stripped, no buildid.
export CGO_ENABLED := 0
GOFLAGS := -trimpath
LDFLAGS := -s -w -buildid= -X main.version=$(VERSION)

.PHONY: all build test vet vuln sbom tidy verify clean

all: verify build

build:
	go build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o $(BINARY) .

test:
	go test -race ./...

vet:
	go vet ./...

# Official Go vulnerability scanner.
vuln:
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...

# CycloneDX SBOM of the module (with licenses).
sbom:
	go run github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@latest mod -licenses -json -output arca.cdx.json
	@echo "wrote arca.cdx.json"

tidy:
	go mod tidy

verify: vet test
	go mod verify

clean:
	rm -f $(BINARY) arca.cdx.json
	rm -rf dist
