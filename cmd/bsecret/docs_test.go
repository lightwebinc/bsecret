package main

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// The documents that say which bcommon and borg versions bsecret pins say
// what go.mod requires: a bump that leaves one behind fails here.
func TestTheDocumentsNameThePinnedVersions(t *testing.T) {
	read := func(path string) string {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return strings.Join(strings.Fields(string(b)), " ")
	}
	mod, err := os.ReadFile("../../go.mod")
	if err != nil {
		t.Fatal(err)
	}
	pinned := func(module string) string {
		m := regexp.MustCompile(`(?m)^\s*` + regexp.QuoteMeta(module) + ` (v\S+)$`).FindSubmatch(mod)
		if m == nil {
			t.Fatalf("go.mod does not require %s", module)
		}
		return string(m[1])
	}
	sdk, bcommon, borg := pinned("github.com/bsv-blockchain/go-sdk"), pinned("github.com/lightwebinc/bcommon"), pinned("github.com/lightwebinc/borg")
	for path, want := range map[string]string{
		"../../docs/spec.md": "bsecret pins bcommon " + bcommon + " and borg " + borg + ".",
		"../../README.md":    "go-sdk " + sdk + ", bcommon " + bcommon + " and borg " + borg,
	} {
		if !strings.Contains(read(path), want) {
			t.Errorf("%s does not say %q, which is what go.mod requires", path, want)
		}
	}
}
