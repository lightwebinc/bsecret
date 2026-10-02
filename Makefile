# GOWORK=off everywhere on purpose: a workspace would resolve bcommon to a
# local checkout, so a go.mod skew would stay invisible here. What is tested
# is what go.mod pins.
#
# The TypeScript package under host/ needs Node 24 and its dependencies
# installed once (cd host && npm ci). The targets run tsc and node directly,
# so NODE may name a Node 24 binary that is not on PATH:
#
#	make verify NODE=/path/to/node24

.PHONY: verify test go-test ts-test ts-check ts-build node-check vet fmt-check deps-check vectors vectors-check borg-module

NODE ?= node
TSC := $(NODE) node_modules/typescript/bin/tsc

# borg is a private module: the public proxy and checksum database cannot
# see it, and a build with no credentials for its repository cannot fetch
# it. So the tagged module archive is kept under third_party/goproxy and
# served to the go command as a file proxy, ahead of the public one. It is
# not a replace and not a vendor directory: go.mod requires the tag, go.sum
# holds the tag's hashes, and the go command refuses an archive that does
# not match them. Every target below, and CI, resolve borg this way, so
# what is tested is the same bytes everywhere. make borg-module refreshes
# the copy from the repository after go.mod moves to another tag.
BORG := github.com/lightwebinc/borg
export GOPROXY := file://$(CURDIR)/third_party/goproxy,https://proxy.golang.org,direct
export GONOPROXY := none
export GONOSUMDB := $(BORG)

verify: fmt-check vet deps-check ts-check vectors-check test

# Go and TypeScript. The Go tests read the TypeScript-written vectors under
# testdata/ts, and the TypeScript tests read the Go-generated ones under
# testdata/vectors: each side decodes, opens, folds and admits the other's
# bytes.
test: go-test ts-test

go-test:
	GOWORK=off go test -race -count=2 ./...

vet:
	GOWORK=off go vet ./...

fmt-check:
	@test -z "$$(gofmt -l .)" || { echo "gofmt:"; gofmt -l .; exit 1; }

# The direct dependencies, asserted rather than intended:
#  - go.mod and go.sum are tidy, and no module is replaced;
#  - the direct set is exactly go-sdk, bcommon and borg;
#  - go-sdk resolves to exactly v1.5.2, the version bcommon pins and the
#    vectors were made with. Minimal version selection takes the higher of
#    two pins, so a library asking for a later go-sdk would change what
#    bsecret ships without a line changing here.
DEPS_DIRECT := github.com/bsv-blockchain/go-sdk github.com/lightwebinc/bcommon $(BORG)
DEPS_SDK    := github.com/bsv-blockchain/go-sdk v1.5.2

deps-check:
	@set -eu; \
	if ! GOWORK=off go mod tidy -diff >/dev/null; then \
		echo "deps-check: go.mod or go.sum is not tidy; run go mod tidy"; exit 1; \
	fi; \
	replaced=$$(GOWORK=off go list -m -f '{{if .Replace}}{{.Path}}{{end}}' all); \
	if [ -n "$$replaced" ]; then echo "deps-check: no module may be replaced, found: $$replaced"; exit 1; fi; \
	direct=$$(GOWORK=off go list -m -f '{{if not (or .Main .Indirect)}}{{.Path}}{{end}}' all | sed '/^$$/d' | sort); \
	want=$$(printf '%s\n' $(DEPS_DIRECT) | sort); \
	if [ "$$direct" != "$$want" ]; then \
		echo "deps-check: the direct dependencies must be exactly:"; echo "$$want" | sed 's/^/  /'; \
		echo "found:"; echo "$$direct" | sed 's/^/  /'; exit 1; \
	fi; \
	sdk=$$(GOWORK=off go list -m $(firstword $(DEPS_SDK))); \
	if [ "$$sdk" != "$(DEPS_SDK)" ]; then echo "deps-check: go-sdk must resolve to exactly $(lastword $(DEPS_SDK)), found: $$sdk"; exit 1; fi

node-check:
	@$(NODE) -e 'process.exit(process.versions.node.split(".")[0] === "24" ? 0 : 1)' || \
		{ echo "host/ needs Node 24; set NODE=/path/to/node"; exit 1; }

ts-check: node-check
	cd host && $(TSC) --noEmit

ts-build: node-check
	cd host && $(NODE) -e "require('node:fs').rmSync('dist', { recursive: true, force: true })" && $(TSC)

ts-test: ts-build
	cd host && $(NODE) --test "dist/**/*.test.js"

# Write both vector sets: the Go codec's under testdata/vectors, the
# TypeScript codec's under testdata/ts. A change to either is a change to
# the contract's goldens.
vectors: ts-build
	GOWORK=off go run ./cmd/vectors
	cd host && $(NODE) dist/tsvectors.js

# Regenerate both in memory and compare byte for byte; write nothing.
vectors-check: ts-build
	GOWORK=off go run ./cmd/vectors -check
	cd host && $(NODE) dist/tsvectors.js -check

# Copy the borg tag go.mod requires into third_party/goproxy, from borg's
# repository. Needs git credentials for it. The go command checks the
# archive against go.sum, so a tag that moved is refused here.
borg-module:
	@set -eu; v=$$(GOWORK=off go list -m -f '{{.Version}}' $(BORG)); \
	tmp=$$(mktemp -d); trap 'chmod -R u+w "$$tmp"; rm -rf "$$tmp"' EXIT; \
	GOWORK=off GOFLAGS=-mod=mod GOMODCACHE=$$tmp GOPROXY=direct GONOSUMDB=$(BORG) go mod download $(BORG)@$$v; \
	src=$$tmp/cache/download/$(BORG)/@v; dst=third_party/goproxy/$(BORG)/@v; \
	mkdir -p $$dst; cp $$src/$$v.mod $$src/$$v.zip $$dst/; \
	GOWORK=off GOFLAGS=-mod=mod GOMODCACHE=$$tmp GOPROXY=direct GONOSUMDB=$(BORG) go list -m -f '{"Version":"{{.Version}}","Time":"{{.Time.UTC.Format "2006-01-02T15:04:05Z"}}"}' $(BORG)@$$v > $$dst/$$v.info; \
	ls $$dst | sed -n 's/\.zip$$//p' > $$dst/list; \
	echo "borg-module: $$v in $$dst"

