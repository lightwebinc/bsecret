export GOWORK := off

.PHONY: test vet fmt-check deps-check vectors vectors-check verify

test:
	go test -race -count=2 ./...

vet:
	go vet ./...

fmt-check:
	@out=$$(gofmt -l .); if [ -n "$$out" ]; then echo "gofmt:"; echo "$$out"; exit 1; fi

# The direct dependencies are exactly go-sdk v1.5.2 and bcommon, nothing is
# replaced, and go.mod is tidy.
deps-check:
	@test "$$(go list -m -f '{{.Version}}' github.com/bsv-blockchain/go-sdk)" = v1.5.2 || { echo "go-sdk is not v1.5.2"; exit 1; }
	@test -z "$$(go list -m -f '{{if .Replace}}{{.Path}}{{end}}' all)" || { echo "a module is replaced"; exit 1; }
	@test "$$(go list -m -f '{{if not .Indirect}}{{.Path}}{{end}}' all | grep -v '^github.com/lightwebinc/bsecret$$' | sort | tr '\n' ' ')" = "github.com/bsv-blockchain/go-sdk github.com/lightwebinc/bcommon " || { echo "unexpected direct dependency"; exit 1; }
	@cp go.mod /tmp/bsecret-go.mod.$$$$ && cp go.sum /tmp/bsecret-go.sum.$$$$ && go mod tidy && \
	  if ! cmp -s go.mod /tmp/bsecret-go.mod.$$$$ || ! cmp -s go.sum /tmp/bsecret-go.sum.$$$$; then \
	    cp /tmp/bsecret-go.mod.$$$$ go.mod; cp /tmp/bsecret-go.sum.$$$$ go.sum; rm -f /tmp/bsecret-go.*.$$$$; echo "go.mod is not tidy"; exit 1; fi; \
	  rm -f /tmp/bsecret-go.*.$$$$

vectors:
	go run ./cmd/vectors

vectors-check:
	go run ./cmd/vectors -check

verify: fmt-check vet deps-check vectors-check test
