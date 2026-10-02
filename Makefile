# GOWORK=off everywhere on purpose: a workspace would resolve bcommon to a
# local checkout, so a go.mod skew would stay invisible here. What is tested
# is what go.mod pins.
#
# The TypeScript package under host/ needs Node 24 and its dependencies
# installed once (cd host && npm ci). The targets run tsc and node directly,
# so NODE may name a Node 24 binary that is not on PATH:
#
#	make verify NODE=/path/to/node24

.PHONY: verify test go-test ts-test ts-check ts-build module node-check vet fmt-check deps-check licences licences-update vectors vectors-check borg-module e2e e2e-client bsecret devchain borg docker-build docker-build-host docker-smoke docker-smoke-host quickstart-check

NODE ?= node
TSC := $(NODE) node_modules/typescript/bin/tsc

VERSION        ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
IMAGE          ?= ghcr.io/lightwebinc/bsecret
DEVCHAIN_IMAGE ?= ghcr.io/lightwebinc/bsecret-devchain
HOST_IMAGE     ?= ghcr.io/lightwebinc/bsecret-host

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

verify: fmt-check vet deps-check licences ts-check vectors-check test

# Go and TypeScript. The Go tests read the TypeScript-written vectors under
# testdata/ts, and the TypeScript tests read the Go-generated ones under
# testdata/vectors: each side decodes, opens, folds and admits the other's
# bytes. One test takes a vault to 65 tokens, a second page of the
# audit class, which the race detector makes too slow: it is skipped under
# -race and run once without it.
test: go-test ts-test

go-test:
	GOWORK=off go test -race -count=2 ./...
	GOWORK=off go test -count=1 -run 'TestABudgetRunsOutBetweenPages$$' ./cmd/bsecret/

# The e2e build tag is vetted too, so the client end to end compiles.
vet:
	GOWORK=off go vet ./...
	GOWORK=off go vet -tags e2e ./cmd/bsecret/

# The command, and the local chain, into bin/.
bsecret:
	GOWORK=off go build -ldflags "-X main.version=$(VERSION)" -o bin/bsecret ./cmd/bsecret

devchain:
	GOWORK=off go build -o bin/devchain ./cmd/devchain

# The borg command, built from the borg module at the tag go.mod pins: the
# organisation, its members and its groups are borg's, so trying bsecret
# and its end to end need it. Nothing of borg is copied here: the build
# reads the module the go command resolved and verified.
borg:
	GOWORK=off go build -o bin/borg $(BORG)/cmd/borg

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

# LICENSE-THIRD-PARTY is generated from what the binaries link, so a new
# dependency brings its licence obligation into the file rather than
# leaving it undischarged. licences fails when the file is stale.
licences:
	python3 scripts/gen-third-party-licenses.py . --check

licences-update:
	python3 scripts/gen-third-party-licenses.py .

node-check:
	@$(NODE) -e 'process.exit(process.versions.node.split(".")[0] === "24" ? 0 : 1)' || \
		{ echo "host/ needs Node 24; set NODE=/path/to/node"; exit 1; }

ts-check: node-check
	cd host && $(TSC) --noEmit

# tsc into host/dist, then the deployable bundle into host/bundle.
ts-build: node-check
	cd host && $(NODE) -e "require('node:fs').rmSync('dist', { recursive: true, force: true })" && $(TSC) && $(NODE) scripts/bundle.js

# The host module a reference overlay host loads: one file,
# host/bundle/bsecret-module.js, with bcommon inlined and nothing imported
# but @bsv/sdk (the host's own copy) and Node built-ins. It is copied into
# the host's tree and named by absolute path in OVERLAY_MODULES
# (docs/host.md). Its tests (make test) mount that file and run golden
# vectors through it.
module: ts-build

ts-test: ts-build
	cd host && $(NODE) --test "dist/**/*.test.js"

# The module end to end on a local reference overlay host loading the
# bundle, staged beside the host's node_modules as a deployment places it: a
# vault created on a borg group, secrets put and read by each member, a
# member removed, the new epoch acknowledged, a create refused while the
# vault is in debt, the secrets re-keyed, the removed member unable to read
# the new versions, the old ones swept, the audit class paid through its 402
# and its trail verified from headers, a restart and the restored index. Not
# part of verify: it needs Docker (for MySQL) and a reference host directory
# holding its compiled dist/index.js and its node_modules.
#
#	make e2e REFERENCE_HOST=/path/to/reference-host
e2e: ts-build
	@test -n "$(REFERENCE_HOST)" || { echo "set REFERENCE_HOST=/path/to/reference-host"; exit 1; }
	cd host && $(NODE) dist/e2e.js $(abspath $(REFERENCE_HOST))

# The bsecret command end to end against two local reference hosts, each
# loading the borg module and the bsecret module, over a local chain
# (bcommon's testchain) serving the node's API and the header source, with
# the borg command built from the module go.mod pins: an organisation,
# three members and a group (borg); a crypt and a vault on the group; three
# secrets every member reads; a removal, which begins a new epoch; the
# acknowledgement and the re-keying, after which the removed member reads
# the old versions the owner kept and none of the new; a retirement; the
# audit class paid through its 402, the trail verified from headers and the
# exposure window reported, and the payee settling it; both hosts agreeing;
# a host restarted and restored; unicast with a host down and the persisted
# carrier published by the next command; a second removal swept by default.
# Not part of verify: it needs Docker (for MySQL), a reference host
# directory holding its compiled dist/index.js and its node_modules, and
# the borg host module's bundle (make module in a borg checkout at the tag
# go.mod pins).
#
#	make e2e-client REFERENCE_HOST=/path/to/reference-host BORG_MODULE=/path/to/borg-module.js
e2e-client: ts-build borg
	@test -n "$(REFERENCE_HOST)" || { echo "set REFERENCE_HOST=/path/to/reference-host"; exit 1; }
	@test -n "$(BORG_MODULE)" || { echo "set BORG_MODULE=/path/to/borg-module.js (the borg host module's bundle)"; exit 1; }
	BSECRET_E2E_REFERENCE_HOST=$(abspath $(REFERENCE_HOST)) BSECRET_E2E_BORG_MODULE=$(abspath $(BORG_MODULE)) \
		BSECRET_E2E_BORG=$(CURDIR)/bin/borg BSECRET_E2E_NODE=$(NODE) \
		GOWORK=off go test -tags e2e -count=1 -v -run 'TestClientE2E$$' ./cmd/bsecret/

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


# The images, built and tagged locally, each as $(VERSION) and latest.
# Nothing here pushes. docker-build makes the command and the local chain;
# the host image needs borg's host image, which it adds the module to:
#
#	make docker-build-host BORG_HOST_IMAGE=<borg's host image>
docker-build:
	docker build --build-arg VERSION=$(VERSION) -t $(IMAGE):$(VERSION) -t $(IMAGE):latest .
	docker build --build-arg VERSION=$(VERSION) --target devchain -t $(DEVCHAIN_IMAGE):$(VERSION) -t $(DEVCHAIN_IMAGE):latest .
	@docker image ls --format '{{.Repository}}:{{.Tag}}  {{.Size}}' | grep -E '^($(IMAGE)|$(DEVCHAIN_IMAGE)):$(VERSION) '

docker-build-host:
	@test -n "$(BORG_HOST_IMAGE)" || { echo "set BORG_HOST_IMAGE to borg's host image, which the module is added to"; exit 1; }
	docker build -f host/Dockerfile --build-arg BORG_HOST_IMAGE=$(BORG_HOST_IMAGE) -t $(HOST_IMAGE):$(VERSION) -t $(HOST_IMAGE):latest .
	@docker image ls --format '{{.Repository}}:{{.Tag}}  {{.Size}}' | grep -E '^$(HOST_IMAGE):$(VERSION) '

# The command's image with no network at all: the stamped version, help, a
# first run in a fresh named volume mounted where the documentation says,
# and a read with no hosts refused before any request.
docker-smoke: docker-build
	@set -eu; img=$(IMAGE):$(VERSION); id=bsecret-smoke-$$$$; \
	docker volume create $$id-home >/dev/null; trap 'docker volume rm -f $$id-home >/dev/null' EXIT; \
	run() { docker run --rm --network none -v $$id-home:/home/nonroot/.bsecret $$img "$$@"; }; \
	echo "== -version"; out=$$(run -version); echo "$$out"; \
	[ "$$out" = "bsecret $(VERSION)" ] || { echo "docker-smoke: want bsecret $(VERSION)"; exit 1; }; \
	echo "== help"; run help | head -1; \
	echo "== init"; run -network regtest init; \
	echo "== crypt new"; run crypt new smoke | grep -E '^(crypt|topic|host) '; \
	echo "== doctor"; out=$$(run -network regtest doctor); echo "$$out"; \
	echo "$$out" | grep -q '^headers     NOT CONFIGURED' || { echo "docker-smoke: doctor output unexpected"; exit 1; }; \
	echo "== a get with no hosts exits 2 before any request"; \
	rc=0; out=$$(run -header-url http://192.0.2.1 -crypt smoke_abcdefghij -org 02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5 get db/password 2>&1) || rc=$$?; echo "$$out"; \
	[ "$$rc" = 2 ] && echo "$$out" | grep -q 'no overlay host configured' || { echo "docker-smoke: want exit 2 naming hosts, got $$rc"; exit 1; }; \
	echo "docker-smoke: ok ($$img)"

# The host image loads the module with the host's own @bsv/sdk, and refuses
# to start with no crypt configured.
docker-smoke-host:
	@set -eu; img=$(HOST_IMAGE):$(VERSION); \
	echo "== the module imports from the host's node_modules"; \
	docker run --rm --network none --entrypoint node $$img -e \
		"import('/app/modules/bsecret/bsecret-module.js').then(m => { if (typeof m.default !== 'function') process.exit(1); console.log('bsecret module: default export is the factory') })"; \
	echo "== no BSECRET_CRYPTS: exit 64 with the reason"; \
	rc=0; out=$$(docker run --rm --network none $$img 2>&1) || rc=$$?; echo "$$out"; \
	[ "$$rc" = 64 ] && echo "$$out" | grep -q 'BSECRET_CRYPTS is empty' || { echo "docker-smoke-host: want exit 64, got $$rc"; exit 1; }; \
	echo "docker-smoke-host: ok ($$img)"

# QUICKSTART.md, run as written, in the quickstart compose project. Needs
# this repository's three images (docker-build, docker-build-host) and
# borg's command image.
quickstart-check:
	scripts/quickstart-check.sh
