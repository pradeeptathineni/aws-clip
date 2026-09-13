.PHONY: build check clean

GOCACHE ?= $(CURDIR)/.cache/go-build
export GOCACHE

build:
	mkdir -p bin
	go build -o bin/aws-clip ./cmd/aws-clip

check:
	@unformatted="$$(gofmt -l .)"; \
	if [ -n "$$unformatted" ]; then \
		echo "gofmt required for:"; \
		echo "$$unformatted"; \
		exit 1; \
	fi
	go vet ./...
	go test ./...

clean:
	rm -f bin/aws-clip
