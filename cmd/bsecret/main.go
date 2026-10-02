// Command bsecret keeps an organisation's secrets on overlay hosts, and
// reads them as a member of the group a vault is keyed to: it creates an
// identity home around a borg organisation's key, creates crypts and
// vaults, writes each version of a secret under a fresh content key wrapped
// to the group's current epoch, acknowledges a new epoch of the group and
// re-keys everything the vault held, retires and retracts, reads a secret
// with every check made in the signed order, audits a vault's trail from
// block headers alone, pays a host's 402 for the priced questions, and
// settles the payments a host accepted as its payee.
//
// Exit codes: 0 done or verified; 1 refused (the evidence contradicts what
// was asked, a check named a culprit, an audit failed, or a payment was
// refused); 2 usage, configuration, local or transport error; 3 incomplete
// (hosts disagree, something is due, or a host held nothing where evidence
// was needed, which proves nothing either way). docs/usage.md is the
// reference.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/lightwebinc/bcommon/headers"
	"github.com/lightwebinc/bcommon/termsafe"

	"github.com/lightwebinc/bsecret/internal/config"
)

// version is stamped by the build; "dev" otherwise.
var version = "dev"

// The exit codes.
const (
	exitOK         = 0
	exitRefused    = 1
	exitUsage      = 2
	exitIncomplete = 3
)

const usageText = `usage: bsecret [global flags] <command> [flags] [arguments]

identity (a home):
  init [-from FILE | -borg DIR] create the home: identity key and coin pool;
                                -borg: around the identity of a borg home
  fund -txid TXID               import a mined payment to the fund address
  fund [-blocks N]              mine coinbase to the fund address (a chain you run)
  crypt new <name>              create a crypt: <name>_<random suffix>, its topic,
                                and the BSECRET_CRYPTS line a host takes
  crypt list                    the crypts this home created
  doctor                        local state, what is owed and reachability; reads only

the owner (this home's identity key is a borg organisation's):
  vault create <group> -name N  a vault keyed to a group of the organisation
                                (-anchor version, the default, or interval)
  put <name>                    write a secret's next version: the value from
                                standard input or -file, listed in the vault's
                                next token
  anchor                        an interval vault: list the versions put -defer
  retire <name>...              retire secrets and retract their versions
  rotate                        acknowledge the group's new epoch and re-key or
                                retire everything the vault held under an earlier
                                one: each secret needs -set, -same or -retire
  sync                          rebuild this home's record from the hosts: chains,
                                versions, names, commitments
  kill -confirm KILL [-yes]     sweep every secret tree: every version retracted

a member, or anyone reading:
  vault list                    the owner's vaults a host answers
  vault show                    a vault's chain, state and set
  get <name>                    read a secret's value, every check in order
  list                          the secrets of a vault this key can open
  due                           what a vault owes: an acknowledgement, re-keying,
                                a rotation its owner scheduled
  audit                         verify a vault's trail from headers and report
                                the exposure windows; -free reads it at no price,
                                -budget bounds what the priced class is paid
  history <name>                a priced question: every version of a secret a
                                host holds
  terms [URL]                   a host's terms document
  fill                          replay to each host what another host answered
                                and it lacks: the chain and the set's carriers

a host's payee:
  payee key -out FILE           write BSECRET_PAYEE_KEY for this home's identity
  payee settle <payments.jsonl>...
                                take every payment a host accepted into the wallet

  version                       print the version

global flags:
  -config PATH        config file (default $BSECRET_HOME/config,
                      $XDG_CONFIG_HOME/bsecret/config, ~/.bsecret/config)
  -home DIR           the identity's home (default ~/.bsecret)
  -crypt CRYPT        the crypt identifier <name>_<suffix>
  -org KEY            the owner a reader reads (default: this home's own)
  -vault VAULT        the vault: its identifier, or its display name
  -hosts URLS         the crypt's overlay hosts, comma separated: every host
                      a reader asks, and in mode unicast every host a
                      publisher submits to
  -hall-hosts URLS    the hosts of the group's hall (default: hosts)
  -header-url SOURCE  header source: a bridge URL, woc:main, woc:test or
                      chaintracks:URL; required to verify, no default
  -mode MODE          plane (submit once to the facade; the default) or
                      unicast (submit to each of hosts)
  -network NET        main, test or regtest (default main)
  -quorum Q           hosts that must hold a carrier for it to count as
                      published: all (default), majority, one or N; tokens
                      and sweeps always need every host
  -timeout DUR        per request (default 15s)
  -v                  verbose
  -version            print the version and exit

Run 'bsecret <command> -h' for a command's flags. Exit codes: 0 done or
verified, 1 refused, 2 usage or transport error, 3 incomplete.
`

// exitError carries an exit code with a message.
type exitError struct {
	code int
	msg  string
}

func (e *exitError) Error() string { return e.msg }

func usage(format string, args ...any) error {
	return &exitError{exitUsage, fmt.Sprintf(format, args...)}
}

func refused(format string, args ...any) error {
	return &exitError{exitRefused, fmt.Sprintf(format, args...)}
}

func incomplete(format string, args ...any) error {
	return &exitError{exitIncomplete, fmt.Sprintf(format, args...)}
}

func isHelp(arg string) bool {
	return arg == "help" || arg == "-h" || arg == "-help" || arg == "--help"
}

// helpOrUsage answers a flag-parsing failure: a help request exits 0 (the
// FlagSet has printed its text), anything else is a usage error.
func helpOrUsage(err error) error {
	if errors.Is(err, flag.ErrHelp) {
		return &exitError{exitOK, ""}
	}
	return &exitError{exitUsage, ""}
}

// global is the resolved configuration and the shared flags.
type global struct {
	cfg     config.Config
	verbose bool
	stdin   io.Reader
	stdout  io.Writer
	stderr  io.Writer
	getenv  func(string) string
	// terminal reports whether standard output is a terminal: a secret's
	// value is never written to one unless asked.
	terminal bool
}

// say writes a note to standard error. A note may quote what a host, a
// node or a record said, which is someone else's text: every note is
// filtered for the terminal.
func (g *global) say(format string, args ...any) {
	fmt.Fprintln(g.stderr, termsafe.Text(fmt.Sprintf(format, args...)))
}

type command func(ctx context.Context, g *global, args []string) error

var commands map[string]command

func init() {
	commands = map[string]command{
		"anchor":  cmdAnchor,
		"audit":   cmdAudit,
		"crypt":   cmdCrypt,
		"doctor":  cmdDoctor,
		"due":     cmdDue,
		"fill":    cmdFill,
		"fund":    cmdFund,
		"get":     cmdGet,
		"history": cmdHistory,
		"init":    cmdInit,
		"kill":    cmdKill,
		"list":    cmdList,
		"payee":   cmdPayee,
		"put":     cmdPut,
		"retire":  cmdRetire,
		"rotate":  cmdRotate,
		"sync":    cmdSync,
		"terms":   cmdTerms,
		"vault":   cmdVault,
	}
}

// isTerminal reports whether w is a character device: a terminal.
func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	st, err := f.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr, os.Getenv)
	stop()
	os.Exit(code)
}

// run is the whole command, with its streams and environment passed in so
// tests drive it in process.
func run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer, getenv func(string) string) int {
	fs := flag.NewFlagSet("bsecret", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, usageText) }
	var (
		cfgPath   = fs.String("config", "", "")
		home      = fs.String("home", "", "")
		crypt     = fs.String("crypt", "", "")
		org       = fs.String("org", "", "")
		vault     = fs.String("vault", "", "")
		hosts     = fs.String("hosts", "", "")
		hallHosts = fs.String("hall-hosts", "", "")
		headerURL = fs.String("header-url", "", "")
		mode      = fs.String("mode", "", "")
		network   = fs.String("network", "", "")
		quorum    = fs.String("quorum", "", "")
		timeout   = fs.String("timeout", "", "")
		verbose   = fs.Bool("v", false, "")
		showVer   = fs.Bool("version", false, "")
	)
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	if *showVer {
		fmt.Fprintln(stdout, "bsecret", version)
		return exitOK
	}
	rest := fs.Args()
	if len(rest) == 0 {
		fs.Usage()
		return exitUsage
	}
	switch {
	case isHelp(rest[0]):
		fmt.Fprint(stdout, usageText)
		return exitOK
	case rest[0] == "version":
		fmt.Fprintln(stdout, "bsecret", version)
		return exitOK
	}
	cmd, ok := commands[rest[0]]
	if !ok {
		fmt.Fprintf(stderr, "bsecret: unknown command %q\n", termsafe.Abbrev(rest[0]))
		fs.Usage()
		return exitUsage
	}
	cfg, err := config.Load(config.Path(*cfgPath, getenv), getenv)
	if err != nil {
		fmt.Fprintln(stderr, "bsecret:", termsafe.Text(err.Error()))
		return exitUsage
	}
	over := map[string]string{}
	for k, v := range map[string]string{"home": *home, "crypt": *crypt, "org": *org, "vault": *vault, "hosts": *hosts,
		"hall_hosts": *hallHosts, "header_url": *headerURL, "mode": *mode, "network": *network, "quorum": *quorum, "timeout": *timeout} {
		if v != "" {
			over[k] = v
		}
	}
	if cfg, err = cfg.Apply(over); err != nil {
		fmt.Fprintln(stderr, "bsecret:", termsafe.Text(err.Error()))
		return exitUsage
	}
	if err := checkHeaderSource(cfg.HeaderURL, cfg.Network); err != nil {
		fmt.Fprintln(stderr, "bsecret:", termsafe.Text(err.Error()))
		return exitUsage
	}
	g := &global{cfg: cfg, verbose: *verbose, stdin: stdin, stdout: stdout, stderr: stderr, getenv: getenv, terminal: isTerminal(stdout)}
	err = cmd(ctx, g, rest[1:])
	var ee *exitError
	switch {
	case err == nil:
		return exitOK
	case errors.As(err, &ee):
		if ee.msg != "" {
			fmt.Fprintln(stderr, "bsecret:", termsafe.Text(ee.msg))
		}
		return ee.code
	default:
		fmt.Fprintln(stderr, "bsecret:", termsafe.Text(err.Error()))
		return exitUsage
	}
}

// checkHeaderSource refuses a header source that does not parse, or a
// WhatsOnChain source for another network than the configured one.
func checkHeaderSource(spec, network string) error {
	if spec == "" {
		return nil
	}
	kind, _, implied, err := headers.Parse(spec)
	if err != nil {
		return err
	}
	if kind == headers.WhatsOnChain && implied != network {
		return fmt.Errorf("header source %s is the %s network but network is %s", spec, implied, network)
	}
	return nil
}

// headerClient is the configured header source, held to the network's
// proof-of-work floor when it serves header fields.
func (g *global) headerClient() (*headers.Client, error) {
	if g.cfg.HeaderURL == "" {
		return nil, usage("no header source: set header_url (or -header-url); a token or a record is only as good as the headers it is checked against")
	}
	c := headers.New(g.cfg.HeaderURL)
	if c.Kind != headers.Native {
		c.Network = g.cfg.Network
	}
	c.Timeout = g.cfg.Timeout
	return c, nil
}

// flagSet is a command's FlagSet, printing its help text on -h.
func (g *global) flagSet(name, help string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(g.stderr)
	fs.BoolVar(&g.verbose, "v", g.verbose, "verbose (also a global flag)")
	fs.Usage = func() {
		fmt.Fprintln(g.stderr, strings.TrimSpace(help))
		fmt.Fprintln(g.stderr, "\nflags:")
		fs.PrintDefaults()
	}
	return fs
}

// parse parses a command's flags, allowing them after its positional
// arguments too, and returns the positionals.
func parse(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, helpOrUsage(err)
		}
		args = fs.Args()
		if len(args) == 0 {
			return pos, nil
		}
		if args[0] == "--" {
			return append(pos, args[1:]...), nil
		}
		pos = append(pos, args[0])
		args = args[1:]
	}
}

// listFlag collects a repeatable flag.
type listFlag []string

func (l *listFlag) String() string     { return strings.Join(*l, ",") }
func (l *listFlag) Set(v string) error { *l = append(*l, v); return nil }
