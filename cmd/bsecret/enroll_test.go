package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeBorg writes a borg command that records its arguments and exits
// with code.
func (h *harness) fakeBorg(code string) (cmd, args string) {
	h.t.Helper()
	args = filepath.Join(h.dir, "borg-args-"+code)
	cmd = filepath.Join(h.dir, "borg-"+code)
	if err := os.WriteFile(cmd, []byte("#!/bin/sh\necho \"$@\" > "+args+"\nexit "+code+"\n"), 0o700); err != nil { //nolint:gosec // a test's own script
		h.t.Fatal(err)
	}
	return cmd, args
}

// A machine asks to join with a key made where it runs, the owner approves
// in one step (borg adds the key to the vault's group), and the machine
// picks up its membership and reads.
func TestEnrollAMachine(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	id := h.vault()
	h.put("db/password", "hunter2")
	key := h.identity("web", false)
	r := h.must("web", "enroll", "request", "-label", "web-1")
	line := strings.TrimSpace(r.stdout)
	if !strings.HasPrefix(line, enrollPrefix) || !strings.Contains(r.stderr, "fingerprint  "+fingerprint(mustHex(key))) {
		t.Fatalf("request:\n%s\n%s", r.stdout, r.stderr)
	}
	// Not yet a member: wait says so, and is incomplete.
	h.want(h.run("web", "", "enroll", "wait", "-timeout", "0"), exitIncomplete, "not a member of group")

	borg, argsFile := h.fakeBorg("0")
	r = h.must("org", "enroll", "approve", line, "-borg-cmd", borg, "-borg-home", "/srv/borg", "-expiry", "720h")
	if !strings.Contains(r.stdout, "fingerprint "+fingerprint(mustHex(key))) || !strings.Contains(r.stdout, "label       web-1 (a claim)") ||
		!strings.Contains(r.stdout, "vault "+id+" ops") || !strings.Contains(r.stdout, "approved") {
		t.Fatalf("approve:\n%s\n%s", r.stdout, r.stderr)
	}
	got, err := os.ReadFile(argsFile) //nolint:gosec // the test's own file
	if err != nil {
		t.Fatal(err)
	}
	if want := "-home /srv/borg -hall " + h.env["BSECRET_HALL"] + " org add " + key + " -group " + h.group + " -expiry 720h\n"; string(got) != want {
		t.Fatalf("borg ran with %q, want %q", got, want)
	}
	// What borg does on that command, the stand-in does here.
	if err := h.borg.Add(h.group, h.keys["web"]); err != nil {
		t.Fatal(err)
	}
	if r := h.must("web", "enroll", "wait", "-timeout", "0"); !strings.Contains(r.stdout, "enrolled    a member of group "+h.group) {
		t.Fatalf("wait:\n%s\n%s", r.stdout, r.stderr)
	}
	if r := h.must("web", "get", "db/password"); r.stdout != "hunter2" {
		t.Fatalf("the enrolled machine reads %q\n%s", r.stdout, r.stderr)
	}
	// A request file, and standard input, are taken as the line is.
	file := h.file("join", line+"\n")
	if r := h.must("org", "enroll", "approve", file, "-print"); !strings.Contains(r.stdout, "run         borg -hall "+h.env["BSECRET_HALL"]+" org add "+key) {
		t.Fatalf("approve -print:\n%s", r.stdout)
	}
	h.mustIn("org", line, "enroll", "approve", "-", "-print")
}

func TestEnrollRefusals(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.vault()
	h.identity("web", false)
	line := strings.TrimSpace(h.must("web", "enroll", "request").stdout)
	// The organization's own home does not ask to join.
	h.want(h.run("org", "", "enroll", "request"), exitUsage, "a machine joins with a key of its own")
	// A request altered on the way: another key, with the same signature.
	raw, _ := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(line, enrollPrefix))
	var req joinRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		t.Fatal(err)
	}
	altered := req
	altered.Key = hex.EncodeToString(h.keys["alice"])
	h.want(h.run("org", "", "enroll", "approve", altered.encode(), "-print"), exitRefused, "does not verify")
	other := req
	other.Label = "\x1b[2Jevil"
	h.want(h.run("org", "", "enroll", "approve", other.encode(), "-print"), exitRefused, "plain text")
	// Approved only in the organization's home, for its own vault, while
	// it is fresh, on its network.
	h.want(h.run("alice", "", "enroll", "approve", line, "-print"), exitRefused, "this home's organization is")
	h.want(h.run("org", "", "enroll", "approve", line, "-print", "-max-age", "1ns"), exitRefused, "outside -max-age")
	h.want(h.run("org", "", "enroll", "approve", "bsecret-join-v1.!!", "-print"), exitRefused, "not a join request")
	h.want(h.run("org", "", "enroll", "approve", "nothing-here"), exitUsage, "the request")
	// A borg that refuses: nothing is approved, and its exit code is ours.
	borg, _ := h.fakeBorg("1")
	h.want(h.run("org", "", "enroll", "approve", line, "-borg-cmd", borg), exitRefused, "borg did not add the key")
	h.want(h.run("org", "", "enroll", "approve", line, "-borg-cmd", filepath.Join(h.dir, "no-such-borg")), exitUsage, "run borg")
	// A home that made no request has nothing to wait for.
	h.want(h.run("alice", "", "enroll", "wait", "-timeout", "0"), exitUsage, "made no join request")
	h.want(h.run("web", "", "enroll"), exitUsage, "enroll request")
	h.want(h.run("web", "", "enroll", "request", "-group", "zz"), exitUsage, "32 hex digits")
}
