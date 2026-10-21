package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/wallet"

	"github.com/lightwebinc/bcommon/termsafe"

	"github.com/lightwebinc/borg/reader"

	"github.com/lightwebinc/bsecret/internal/config"
	"github.com/lightwebinc/bsecret/internal/secrec"
	"github.com/lightwebinc/bsecret/internal/vread"
)

const enrollHelp = `usage: bsecret enroll request [-group G -hall H] [-label L] [-out FILE]
       bsecret enroll approve <REQUEST|FILE|-> [-borg-home DIR] [-borg-cmd PATH] [-expiry DUR] [-max-age DUR] [-print]
       bsecret enroll wait [-timeout DUR] [-poll DUR]

Machine enrollment (docs/usage.md, "Enrolling a machine"): a workload asks
to join a vault's group with a key it made where it runs, the owner
approves the request in one step, and the workload picks up its
membership. No private key travels.

request, in the workload's home (made with a plain 'bsecret init'): writes
a join request naming this home's identity key, the owner (org), and the
vault it reads (the configured one, or -vault; or -group and its hall),
signed by this home's identity key, and
prints it as one line to pass to the owner by any channel. It is not
secret. -label is a name for the machine the owner sees, a claim.

approve, in the owner's home: checks the request (its signature by the key
it names, this home's organization as the owner, the network, its age
within -max-age, 24h by default) and, for a vault, that this home owns it;
prints the key's fingerprint; then runs borg to add the key to the group:

  borg [-home DIR] -hall HALL org add <key> -group <group> [-expiry DUR]

which grants the key a membership and wraps the group's current epoch key
to it. -print prints that command and runs nothing. Approving admits
whoever holds the key: approve a request that reached you through a
channel you trust, and compare the fingerprint with the one the workload
printed.

wait, in the workload's home: reads the group of the request this home
made last, every token checked against this home's headers, until its key
is a member and opens the group's current epoch key; then exits 0. It
exits 3 when -timeout (10m by default; 0 asks once) passes first.`

// enrollProtocol is the derivation a join request is signed under: the
// requester's key, counterparty anyone, so that anyone verifies it from the
// public key the request names.
var enrollProtocol = wallet.Protocol{SecurityLevel: wallet.SecurityLevelEveryApp, Protocol: "bsecret enrollment"}

const (
	enrollKeyID  = "1"
	enrollDomain = "bsecret enrollment request v1\n"
	enrollPrefix = "bsecret-join-v1."
	// enrollFile is where a workload's home keeps the request it made last.
	enrollFile = "enroll.json"
	// maxLabel bounds a machine's label.
	maxLabel = 64
)

// joinRequest is a workload's request to join a group. Its fields are in
// the order they are signed in: the signature is over enrollDomain and the
// JSON of every field but Sig, as encoding/json writes this struct.
type joinRequest struct {
	V       int    `json:"v"`
	Network string `json:"network"`
	Org     string `json:"org"`
	Crypt   string `json:"crypt,omitempty"`
	Vault   string `json:"vault,omitempty"`
	Hall    string `json:"hall,omitempty"`
	Group   string `json:"group,omitempty"`
	Key     string `json:"key"`
	Label   string `json:"label,omitempty"`
	Nonce   string `json:"nonce"`
	At      int64  `json:"at"`
	Sig     string `json:"sig,omitempty"`
}

func (r joinRequest) digest() []byte {
	r.Sig = ""
	b, _ := json.Marshal(r)
	return append([]byte(enrollDomain), b...)
}

// encode is the request as one line.
func (r joinRequest) encode() string {
	b, _ := json.Marshal(r)
	return enrollPrefix + base64.RawURLEncoding.EncodeToString(b)
}

// fingerprint is a short, comparable form of a key: the first 16 hex
// digits of its SHA-256, in groups of four.
func fingerprint(key []byte) string {
	h := sha256.Sum256(key)
	x := hex.EncodeToString(h[:8])
	return x[0:4] + "-" + x[4:8] + "-" + x[8:12] + "-" + x[12:16]
}

// parseJoin decodes a request line and checks its form and its signature.
func parseJoin(line string) (*joinRequest, *ec.PublicKey, error) {
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(line, enrollPrefix) {
		return nil, nil, fmt.Errorf("not a join request: it does not begin %q", enrollPrefix)
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(line, enrollPrefix))
	if err != nil || len(raw) > 4096 {
		return nil, nil, errors.New("not a join request: its body is not base64url of at most 4096 bytes")
	}
	var r joinRequest
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		return nil, nil, fmt.Errorf("not a join request: %v", err)
	}
	if r.V != 1 {
		return nil, nil, fmt.Errorf("a join request of version %d; this bsecret reads version 1", r.V)
	}
	key, err := parseKey("the request's key", r.Key)
	if err != nil {
		return nil, nil, err
	}
	if _, err := parseKey("the request's org", r.Org); err != nil {
		return nil, nil, err
	}
	switch {
	case r.Vault != "" && (!config.IsHex32(r.Vault) || r.Crypt == "" || secrec.CheckCrypt(r.Crypt) != nil):
		return nil, nil, errors.New("the request names a vault that is not 64 hex digits, or no crypt")
	case r.Vault == "" && (r.Group == "" || r.Hall == ""):
		return nil, nil, errors.New("the request names neither a vault nor a group and its hall")
	case r.Group != "":
		if _, err := reader.ParseGroup(r.Group); err != nil {
			return nil, nil, fmt.Errorf("the request's group: %v", err)
		}
	}
	if len(r.Label) > maxLabel || !utf8.ValidString(r.Label) || termsafe.Text(r.Label) != r.Label {
		return nil, nil, fmt.Errorf("the request's label is not one line of plain text of at most %d bytes", maxLabel)
	}
	if n, err := hex.DecodeString(r.Nonce); err != nil || len(n) != 16 {
		return nil, nil, errors.New("the request's nonce is not 32 hex digits")
	}
	sig, err := hex.DecodeString(r.Sig)
	if err != nil {
		return nil, nil, errors.New("the request's signature is not hex")
	}
	s, err := ec.FromDER(sig)
	if err != nil {
		return nil, nil, fmt.Errorf("the request's signature: %v", err)
	}
	pub, _ := ec.PublicKeyFromBytes(key)
	anyone, _ := wallet.AnyoneKey()
	v, err := wallet.NewCompletedProtoWallet(anyone)
	if err != nil {
		return nil, nil, err
	}
	res, err := v.VerifySignature(context.Background(), wallet.VerifySignatureArgs{
		EncryptionArgs: wallet.EncryptionArgs{ProtocolID: enrollProtocol, KeyID: enrollKeyID, Counterparty: wallet.Counterparty{Type: wallet.CounterpartyTypeOther, Counterparty: pub}},
		Data:           r.digest(), Signature: s,
	}, "")
	if err != nil || !res.Valid {
		return nil, nil, errors.New("the request's signature does not verify under the key it names: it was altered, or not made by that key")
	}
	return &r, pub, nil
}

func cmdEnroll(ctx context.Context, g *global, args []string) error {
	if len(args) == 0 || isHelp(args[0]) {
		fs := g.flagSet("enroll", enrollHelp)
		fs.Usage()
		if len(args) == 0 {
			return usage("enroll request | enroll approve <REQUEST> | enroll wait")
		}
		return &exitError{exitOK, ""}
	}
	switch args[0] {
	case "request":
		return g.enrollRequest(ctx, args[1:])
	case "approve":
		return g.enrollApprove(ctx, args[1:])
	case "wait":
		return g.enrollWait(ctx, args[1:])
	}
	return usage("enroll request | enroll approve <REQUEST> | enroll wait")
}

func (g *global) enrollRequest(ctx context.Context, args []string) error {
	fs := g.flagSet("enroll request", enrollHelp)
	group := fs.String("group", "", "the group to join, by its identifier (with -hall), when no vault is named")
	hall := fs.String("hall", g.cfg.Hall, "the group's hall")
	label := fs.String("label", "", "a name for this machine the owner sees: a claim")
	out := fs.String("out", "", "also write the request to this file")
	if pos, err := parse(fs, args); err != nil {
		return err
	} else if len(pos) > 0 {
		return usage("enroll request takes no arguments")
	}
	e, err := g.openWallet()
	if err != nil {
		return err
	}
	s := e.Signer()
	if g.cfg.Org == "" {
		return usage("no owner: set org (or -org) to the identity key of the organization whose group this machine joins")
	}
	if g.cfg.Org == s.IdentityHex() {
		return usage("this home's key is the organization's: a machine joins with a key of its own (a plain bsecret init)")
	}
	r := joinRequest{V: 1, Network: g.cfg.Network, Org: g.cfg.Org, Key: s.IdentityHex(), Label: *label, At: time.Now().Unix()}
	if *group != "" {
		if _, err := reader.ParseGroup(*group); err != nil {
			return usage("-group is a group's identifier, 32 hex digits: %v", err)
		}
		if *hall == "" {
			return usage("-group needs the group's hall (-hall, or config key hall)")
		}
		r.Group, r.Hall = *group, *hall
	} else {
		t, err := g.readTarget(ctx, true)
		if err != nil {
			return err
		}
		r.Crypt, r.Vault = t.crypt, t.vaultHex()
	}
	if len(r.Label) > maxLabel || termsafe.Text(r.Label) != r.Label {
		return usage("-label is one line of plain text of at most %d bytes", maxLabel)
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	r.Nonce = hex.EncodeToString(nonce[:])
	res, err := s.CreateSignature(ctx, wallet.CreateSignatureArgs{
		EncryptionArgs: wallet.EncryptionArgs{ProtocolID: enrollProtocol, KeyID: enrollKeyID, Counterparty: wallet.Counterparty{Type: wallet.CounterpartyTypeAnyone}},
		Data:           r.digest(),
	}, s.Originator)
	if err != nil {
		return fmt.Errorf("sign the request: %w", err)
	}
	r.Sig = hex.EncodeToString(res.Signature.Serialize())
	line := r.encode()
	b, _ := json.MarshalIndent(r, "", "  ")
	if err := writeFileAtomic(filepath.Join(g.cfg.Home, enrollFile), append(b, '\n')); err != nil {
		return err
	}
	if *out != "" {
		if err := os.WriteFile(*out, []byte(line+"\n"), 0o600); err != nil {
			return err
		}
	}
	g.say("key          %s", r.Key)
	g.say("fingerprint  %s   (the owner compares this before approving)", fingerprint(mustHex(r.Key)))
	g.say("give the owner the line below; they run: bsecret enroll approve '<line>'; then: bsecret enroll wait")
	fmt.Fprintln(g.stdout, line)
	return nil
}

// writeFileAtomic writes a file of the home at 0600 through a rename.
func writeFileAtomic(path string, b []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (g *global) enrollApprove(ctx context.Context, args []string) error {
	fs := g.flagSet("enroll approve", enrollHelp)
	borgHome := fs.String("borg-home", "", "the organization's borg home (default: borg's own, BORG_HOME or ~/.borg)")
	borgCmd := fs.String("borg-cmd", "borg", "the borg command")
	expiry := fs.String("expiry", "", "when the machine's grant stops being current, as borg's -expiry takes it (default: borg's, one year)")
	maxAge := fs.Duration("max-age", 24*time.Hour, "the oldest request approved")
	printOnly := fs.Bool("print", false, "print the borg command and run nothing")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return usage("enroll approve <REQUEST|FILE|->")
	}
	line := pos[0]
	if !strings.HasPrefix(line, enrollPrefix) {
		var b []byte
		if line == "-" {
			b, err = io.ReadAll(io.LimitReader(g.stdin, 8192))
		} else {
			b, err = os.ReadFile(line) //nolint:gosec // the operator's own path
		}
		if err != nil {
			return usage("the request: %v", err)
		}
		line = string(b)
	}
	r, _, err := parseJoin(line)
	if err != nil {
		return refused("%v", err)
	}
	st := g.peekState()
	if st == nil {
		return usage("approve runs in the organization's bsecret home: there is none at %s", g.cfg.Home)
	}
	if r.Org != st.Identity {
		return refused("the request asks to join a group of %s, and this home's organization is %s", r.Org, st.Identity)
	}
	if r.Key == st.Identity {
		return refused("the request names the organization's own key")
	}
	if r.Network != g.cfg.Network {
		return refused("the request is for network %s, and this home is on %s", termsafe.Abbrev(r.Network), g.cfg.Network)
	}
	at := time.Unix(r.At, 0)
	if age := time.Since(at); age > *maxAge || age < -5*time.Minute {
		return refused("the request was made at %s, outside -max-age %s", at.UTC().Format(time.RFC3339), *maxAge)
	}
	hall, group, what := r.Hall, r.Group, "group "+r.Group
	if r.Vault != "" {
		v := st.VaultByID(r.Vault)
		if v == nil || v.Crypt != r.Crypt {
			return refused("this home owns no vault %s in crypt %s", r.Vault, termsafe.Abbrev(r.Crypt))
		}
		hall, group, what = v.Hall, v.Group, fmt.Sprintf("vault %s %s (group %s)", v.ID, field(v.Name), v.Group)
	}
	label := "(none)"
	if r.Label != "" {
		label = field(r.Label)
	}
	fmt.Fprintf(g.stdout, "request     %s joins %s in hall %s\n", r.Key, what, hall)
	fmt.Fprintf(g.stdout, "fingerprint %s\nlabel       %s (a claim)\nmade        %s\n", fingerprint(mustHex(r.Key)), label, at.UTC().Format(time.RFC3339))
	argv := []string{}
	if *borgHome != "" {
		argv = append(argv, "-home", *borgHome)
	}
	argv = append(argv, "-hall", hall, "org", "add", r.Key, "-group", group)
	if *expiry != "" {
		argv = append(argv, "-expiry", *expiry)
	}
	if *printOnly {
		fmt.Fprintf(g.stdout, "run         %s %s\n", *borgCmd, strings.Join(argv, " "))
		return nil
	}
	fmt.Fprintf(g.stdout, "running     %s %s\n", *borgCmd, strings.Join(argv, " "))
	cmd := exec.CommandContext(ctx, *borgCmd, argv...) //nolint:gosec // the operator's own command, and checked arguments
	cmd.Stdout, cmd.Stderr = g.stdout, g.stderr
	if err := cmd.Run(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return &exitError{ee.ExitCode(), fmt.Sprintf("borg did not add the key (exit %d); nothing was approved", ee.ExitCode())}
		}
		return usage("run borg (-borg-cmd %s): %v", *borgCmd, err)
	}
	fmt.Fprintf(g.stdout, "approved    the machine picks up its membership with: bsecret enroll wait\n")
	return nil
}

func (g *global) enrollWait(ctx context.Context, args []string) error {
	fs := g.flagSet("enroll wait", enrollHelp)
	timeout := fs.Duration("timeout", 10*time.Minute, "how long to wait; 0 asks once")
	every := fs.Duration("poll", 10*time.Second, "how often the group is read again")
	if pos, err := parse(fs, args); err != nil {
		return err
	} else if len(pos) > 0 {
		return usage("enroll wait takes no arguments")
	}
	if *every < 10*time.Millisecond {
		return usage("-poll is at least 10ms")
	}
	b, err := os.ReadFile(filepath.Join(g.cfg.Home, enrollFile))
	if err != nil {
		return usage("this home has made no join request (bsecret enroll request): %v", err)
	}
	var r joinRequest
	if err := json.Unmarshal(b, &r); err != nil {
		return fmt.Errorf("%s: %w", enrollFile, err)
	}
	e, err := g.openWallet()
	if err != nil {
		return err
	}
	s := e.Signer()
	if r.Key != s.IdentityHex() {
		return usage("the request this home kept names %s, not this home's key %s", r.Key, s.IdentityHex())
	}
	org, err := parseKey("org", r.Org)
	if err != nil {
		return err
	}
	me := s.Identity.Compressed()
	end := time.Now().Add(*timeout)
	for {
		ok, why, err := g.enrolled(ctx, r, org, s, me)
		if err != nil {
			return err
		}
		if ok {
			fmt.Fprintln(g.stdout, why)
			return nil
		}
		if !time.Now().Add(*every).Before(end) {
			return incomplete("not enrolled yet: %s", why)
		}
		if g.verbose {
			g.say("waiting     %s", why)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(*every):
		}
	}
}

// enrolled reads the request's group: whether this key is one of its
// members, and opens its current epoch's key.
func (g *global) enrolled(ctx context.Context, r joinRequest, org []byte, w wallet.Interface, me []byte) (bool, string, error) {
	hall, gidHex := r.Hall, r.Group
	if r.Vault != "" {
		g.cfg.Crypt, g.cfg.Org, g.cfg.Vault = r.Crypt, r.Org, r.Vault
		t, err := g.readTarget(ctx, true)
		if err != nil {
			return false, "", err
		}
		cv, err := t.rd.Chain(ctx, t.crypt, t.org, t.vault)
		if err != nil {
			return false, fmt.Sprintf("the vault %s is not answered: %s", vread.Short(r.Vault), firstLine(err.Error())), nil
		}
		head := cv.Head()
		if head == nil {
			return false, "the vault's first token breaks the fold", nil
		}
		hall, gidHex = head.Token.Vault.Hall, reader.GroupHex(head.Token.Vault.Group)
	}
	gid, err := reader.ParseGroup(gidHex)
	if err != nil {
		return false, "", err
	}
	rd, err := g.groups()
	if err != nil {
		return false, "", err
	}
	gr, err := vread.ReadGroup(ctx, rd, hall, org, gid)
	if err != nil {
		var f *vread.Failure
		if errors.As(err, &f) {
			return false, "", failure(err)
		}
		return false, fmt.Sprintf("the group %s is not answered: %s", gidHex, firstLine(err.Error())), nil
	}
	member := false
	for _, m := range gr.Members {
		member = member || bytes.Equal(m, me)
	}
	cur := gr.Current().Epoch
	if !member {
		return false, fmt.Sprintf("this key is not a member of group %s (epoch %d) yet", gidHex, cur), nil
	}
	if _, _, err := vread.OpenEpoch(ctx, rd, w, me, gr, cur); err != nil {
		return false, fmt.Sprintf("a member of group %s, and epoch %d's key does not open yet: %s", gidHex, cur, firstLine(err.Error())), nil
	}
	return true, fmt.Sprintf("enrolled    a member of group %s in hall %s, epoch %d's key opens with this key", gidHex, hall, cur), nil
}
