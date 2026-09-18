GO ?= go
GORELEASER ?= goreleaser
VERSION ?= dev
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build test vet lint verify verify-third-party-notices docker-build integration release-check release-snapshot package-lint package-smoke

build:
	mkdir -p bin
	$(GO) build -trimpath -ldflags "$(LDFLAGS)" -o bin/quordon ./cmd/quordon

test:
	$(GO) test ./...
	cd third_party/go-sql-driver/mysql && $(GO) test -run '^(TestReadPacketRejectsOversizedBodyFromHeader|TestConnectionDeadlineCapsConfiguredIOTimeouts|TestOperationDeadlineSurvivesPacketErrorClassification)$$' ./
	cd third_party/go-yaml && $(GO) test ./...

vet:
	$(GO) vet ./...

lint:
	vacuum lint -d openapi/openapi.yaml
	vacuum lint -d openapi/aggregate.yaml
	vacuum lint -d openapi/query-shapes.yaml
	vacuum lint -d openapi/table-statistics.yaml
	vacuum lint -d openapi/keyset-pagination.yaml

verify: test vet lint verify-third-party-notices

verify-third-party-notices:
	./scripts/verify-third-party-notices.sh

docker-build:
	docker build --build-arg VERSION=$(VERSION) -t quordon:$(VERSION) .

integration:
	./scripts/integration-test.sh

release-check:
	$(GORELEASER) check

release-snapshot:
	$(GORELEASER) release --snapshot --clean

package-lint:
	lintian dist/*.deb

package-smoke: release-snapshot
	./scripts/package-smoke-test.sh
