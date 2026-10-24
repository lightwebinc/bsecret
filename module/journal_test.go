package module

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// The rows journal's group commit (BSECRET_JOURNAL_SYNC_MS): lines in the
// file at once and in order, fsynced together off the caller's path, a
// process crash losing nothing, Close flushing, a failed fsync tried again.
// The bytes are TestJournalFile's.

const jCrypt = "example_crypt_hmqzvtkwrx"

func tLine(i int) Line {
	return Line{K: "t", Txid: fmt.Sprintf("%064x", i), Vout: i64(int64(i % 7)), Crypt: jCrypt, At: i64(int64(1_700_000_000 + i))}
}

// same compares two lines by their bytes (Line holds pointers).
func same(t *testing.T, a, b Line) bool {
	t.Helper()
	x, err := a.encode()
	if err != nil {
		t.Fatal(err)
	}
	y, err := b.encode()
	if err != nil {
		t.Fatal(err)
	}
	return string(x) == string(y)
}

// countingSyncs makes j count its fsyncs, each still a real one.
func countingSyncs(j *FileJournal) *atomic.Int64 {
	var n atomic.Int64
	j.fsync = func(f *os.File) error {
		n.Add(1)
		return f.Sync()
	}
	return &n
}

func loadAll(t *testing.T, d string) []Line {
	t.Helper()
	lines, err := (&FileJournal{Path: filepath.Join(d, JournalFile)}).Load()
	if err != nil {
		t.Fatal(err)
	}
	return lines
}

func TestJournalEveryLine(t *testing.T) {
	d := t.TempDir()
	j, _ := NewFileJournal(d)
	syncs := countingSyncs(j)
	for i := range 5 {
		if err := j.Append(tLine(i)); err != nil {
			t.Fatal(err)
		}
		if got := syncs.Load(); got != int64(i+1) {
			t.Fatalf("line %d: %d fsyncs, want one a line before Append returns", i, got)
		}
	}
	if j.armed || j.pending != 0 {
		t.Fatal("a window armed with SyncEvery zero")
	}
	_ = j.Close()
	if got := loadAll(t, d); len(got) != 5 {
		t.Fatalf("%d lines", len(got))
	}
}

func TestJournalGroupCommitOrder(t *testing.T) {
	d := t.TempDir()
	j, _ := NewFileJournal(d)
	j.SyncEvery = 2 * time.Millisecond
	syncs := countingSyncs(j)
	var covered atomic.Int64
	j.OnSync = func(lines int, _ time.Duration, err error) {
		if err != nil {
			t.Error(err)
		}
		covered.Add(int64(lines))
	}
	const n = 2000
	for i := range n {
		if err := j.Append(tLine(i)); err != nil {
			t.Fatal(err)
		}
		if i%250 == 0 {
			time.Sleep(3 * time.Millisecond)
		}
	}
	got := loadAll(t, d)
	if len(got) != n {
		t.Fatalf("%d lines in the file, want %d", len(got), n)
	}
	for i, l := range got {
		if !same(t, l, tLine(i)) {
			t.Fatalf("line %d is %+v", i, l)
		}
	}
	deadline := time.Now().Add(2 * time.Second)
	for covered.Load() < n && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if covered.Load() != n {
		t.Fatalf("timed fsyncs covered %d of %d lines", covered.Load(), n)
	}
	if s := syncs.Load(); s < 1 || s >= n/4 {
		t.Fatalf("%d fsyncs for %d lines: not grouped", s, n)
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
}

// The append path never waits for a timed fsync.
func TestJournalAppendDoesNotWaitForSync(t *testing.T) {
	d := t.TempDir()
	j, _ := NewFileJournal(d)
	j.SyncEvery = time.Millisecond
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	j.fsync = func(f *os.File) error {
		once.Do(func() { close(entered) })
		<-release
		return f.Sync()
	}
	if err := j.Append(tLine(0)); err != nil {
		t.Fatal(err)
	}
	<-entered
	done := make(chan error, 1)
	go func() { done <- j.Append(tLine(1)) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Append waited for the fsync in flight")
	}
	close(release)
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	if got := loadAll(t, d); len(got) != 2 || !same(t, got[1], tLine(1)) {
		t.Fatalf("%+v", got)
	}
}

// A process that dies with lines still waiting for their fsync loses none
// of them. The child is this test binary, killed by SIGKILL mid-window.
func TestJournalCrashKeepsWrittenLines(t *testing.T) {
	if d := os.Getenv("BSECRET_JOURNAL_CRASH_DIR"); d != "" {
		j, _ := NewFileJournal(d)
		j.SyncEvery = time.Hour
		j.fsync = func(*os.File) error { return errors.New("no fsync in the crash child") }
		for i := range 300 {
			if err := j.Append(tLine(i)); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(3)
			}
		}
		_ = syscall.Kill(os.Getpid(), syscall.SIGKILL)
		time.Sleep(time.Minute)
		os.Exit(4)
	}
	d := t.TempDir()
	cmd := exec.Command(os.Args[0], "-test.run=^TestJournalCrashKeepsWrittenLines$", "-test.count=1")
	cmd.Env = append(os.Environ(), "BSECRET_JOURNAL_CRASH_DIR="+d)
	out, err := cmd.CombinedOutput()
	var ee *exec.ExitError
	if !errors.As(err, &ee) {
		t.Fatalf("the child was not killed: %v %s", err, out)
	}
	if ws, ok := ee.Sys().(syscall.WaitStatus); !ok || !ws.Signaled() || ws.Signal() != syscall.SIGKILL {
		t.Fatalf("the child ended %v: %s", err, out)
	}
	got := loadAll(t, d)
	if len(got) != 300 {
		t.Fatalf("%d lines survived the crash, want 300", len(got))
	}
	for i, l := range got {
		if !same(t, l, tLine(i)) {
			t.Fatalf("line %d is %+v", i, l)
		}
	}
}

func TestJournalCloseFlushes(t *testing.T) {
	d := t.TempDir()
	j, _ := NewFileJournal(d)
	j.SyncEvery = time.Hour
	syncs := countingSyncs(j)
	var timed atomic.Int64
	j.OnSync = func(int, time.Duration, error) { timed.Add(1) }
	for i := range 4 {
		if err := j.Append(tLine(i)); err != nil {
			t.Fatal(err)
		}
	}
	if syncs.Load() != 0 || !j.armed || j.pending != 4 {
		t.Fatalf("fsyncs %d armed %v pending %d", syncs.Load(), j.armed, j.pending)
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	if syncs.Load() != 1 || j.pending != 0 || j.armed || j.timer != nil || j.f != nil {
		t.Fatalf("fsyncs %d pending %d armed %v", syncs.Load(), j.pending, j.armed)
	}
	if err := j.Close(); err != nil || syncs.Load() != 1 {
		t.Fatal(err, syncs.Load())
	}
	j.timedSync()
	if timed.Load() != 0 {
		t.Fatal("a timed fsync after Close")
	}
	if err := j.Append(tLine(4)); err != nil {
		t.Fatal(err)
	}
	if err := j.Close(); err != nil || syncs.Load() != 2 {
		t.Fatal(err, syncs.Load())
	}
	if got := loadAll(t, d); len(got) != 5 {
		t.Fatalf("%d lines", len(got))
	}
}

func TestJournalFailedSyncTriedAgain(t *testing.T) {
	d := t.TempDir()
	j, _ := NewFileJournal(d)
	j.SyncEvery = time.Hour
	boom := errors.New("disk full")
	var fail atomic.Bool
	fail.Store(true)
	j.fsync = func(f *os.File) error {
		if fail.Load() {
			return boom
		}
		return f.Sync()
	}
	var errs, oks atomic.Int64
	j.OnSync = func(_ int, _ time.Duration, err error) {
		if err != nil {
			errs.Add(1)
		} else {
			oks.Add(1)
		}
	}
	_ = j.Append(tLine(0))
	_ = j.Append(tLine(1))
	j.timedSync()
	if errs.Load() != 1 || j.pending != 2 || !j.armed {
		t.Fatalf("errors %d pending %d armed %v: the lines are not left for the next window", errs.Load(), j.pending, j.armed)
	}
	if err := j.Append(tLine(2)); err == nil || !errors.Is(err, boom) {
		t.Fatalf("%v", err)
	}
	if err := j.Append(tLine(3)); err != nil {
		t.Fatalf("reported twice: %v", err)
	}
	fail.Store(false)
	j.timedSync()
	if oks.Load() != 1 || j.pending != 0 {
		t.Fatalf("oks %d pending %d", oks.Load(), j.pending)
	}
	_ = j.Close()
	if got := loadAll(t, d); len(got) != 4 {
		t.Fatalf("%d lines", len(got))
	}
}

// Appends from several goroutines with a sync now and then and a 1 ms
// window, for the race detector: no torn or lost line, every goroutine's
// lines in its order.
func TestJournalConcurrent(t *testing.T) {
	d := t.TempDir()
	j, _ := NewFileJournal(d)
	j.SyncEvery = time.Millisecond
	j.OnSync = func(_ int, _ time.Duration, err error) {
		if err != nil {
			t.Error(err)
		}
	}
	const writers, each = 4, 400
	var wg sync.WaitGroup
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-stop:
				return
			case <-time.After(5 * time.Millisecond):
			}
			if err := j.Sync(); err != nil {
				t.Error(err)
			}
		}
	}()
	for w := range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range each {
				if err := j.Append(tLine(w*100_000 + i)); err != nil {
					t.Error(err)
					return
				}
			}
		}()
	}
	wg.Wait()
	close(stop)
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	got := loadAll(t, d)
	if len(got) != writers*each {
		t.Fatalf("%d lines, want %d", len(got), writers*each)
	}
	next := make([]int, writers)
	for _, l := range got {
		var n int
		if _, err := fmt.Sscanf(l.Txid, "%x", &n); err != nil {
			t.Fatal(err)
		}
		w, i := n/100_000, n%100_000
		if i != next[w] {
			t.Fatalf("writer %d: line %d after %d", w, i, next[w]-1)
		}
		next[w]++
	}
}

func TestParseJournalSync(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	base := map[string]string{"BSECRET_CRYPTS": jCrypt, "BSECRET_STATE_DIR": "/var/lib/bsecret", "BSECRET_HEADERS_URL": "http://127.0.0.1:9178"}
	with := func(v string) map[string]string {
		m := map[string]string{"BSECRET_JOURNAL_SYNC_MS": v}
		for k, x := range base {
			m[k] = x
		}
		return m
	}
	if c, err := ParseConfig(env(base)); err != nil || c.JournalSync != 100*time.Millisecond {
		t.Fatal(c, err)
	}
	for v, want := range map[string]time.Duration{"0": 0, "5": 5 * time.Millisecond, "60000": time.Minute} {
		if c, err := ParseConfig(env(with(v))); err != nil || c.JournalSync != want {
			t.Fatal(v, c, err)
		}
	}
	for _, bad := range []string{"60001", "-1", "1.5", "x", "100ms"} {
		if _, err := ParseConfig(env(with(bad))); err == nil || !strings.Contains(err.Error(), "BSECRET_JOURNAL_SYNC_MS") {
			t.Errorf("%q: %v", bad, err)
		}
	}
}

// Mount gives the state directory's journal the configured window,
// presets and keeps the journal counters, logs a run of failed fsyncs once,
// and Start closes the journal when its context ends.
func TestMountJournal(t *testing.T) {
	f, h := readTx(t)
	d := t.TempDir()
	host := newFakeHost()
	c := &Config{Crypts: []string{f.Crypt}, StateDir: d, HeadersURL: "http://127.0.0.1:1", RetentionDays: FloorDays, UnheldHours: FloorUnheldHours,
		MaxBEEF: f.MaxBEEF, MaxSweepInputs: f.MaxSweepInputs, SpendTable: MinSpendTable, Prices: map[string]uint64{}, JournalSync: 7 * time.Millisecond}
	m, err := Mount(host, c, []string{f.Topic}, nil, h, nil)
	if err != nil {
		t.Fatal(err)
	}
	fj, ok := m.journal.(*FileJournal)
	if !ok || fj.SyncEvery != 7*time.Millisecond || fj.OnSync == nil {
		t.Fatalf("%T %+v", m.journal, fj)
	}
	for _, name := range []string{"bsecret_journal_lines_total", "bsecret_journal_wait_seconds_total", "bsecret_journal_sync_seconds_total",
		`bsecret_journal_syncs_total{result="ok"}`, `bsecret_journal_syncs_total{result="error"}`} {
		host.mu.Lock()
		_, ok := host.counters[name]
		host.mu.Unlock()
		if !ok {
			t.Errorf("%s is not preset", name)
		}
	}
	m.LS.mu.Lock()
	m.LS.write(tLine(1))
	m.LS.mu.Unlock()
	if host.count("bsecret_journal_lines_total", nil) != 1 || host.count("bsecret_journal_wait_seconds_total", nil) <= 0 {
		t.Fatal("the write is not counted")
	}
	deadline := time.Now().Add(2 * time.Second)
	for host.count("bsecret_journal_syncs_total", map[string]string{"result": "ok"}) < 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if host.count("bsecret_journal_syncs_total", map[string]string{"result": "ok"}) != 1 {
		t.Fatal("the timed fsync is not counted")
	}
	on := fj.OnSync
	on(3, time.Millisecond, errors.New("eio"))
	on(3, time.Millisecond, errors.New("eio"))
	on(4, time.Millisecond, nil)
	n := 0
	host.mu.Lock()
	for _, l := range host.lines {
		if strings.HasPrefix(l, "ls_bsecret could not sync the journal") || l == "ls_bsecret journal synced again" {
			n++
		}
	}
	host.mu.Unlock()
	if n != 2 || host.count("bsecret_journal_syncs_total", map[string]string{"result": "error"}) != 2 {
		t.Fatalf("%d log lines", n)
	}
	m.LS.mu.Lock()
	m.LS.write(tLine(2))
	m.LS.mu.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- m.Start(ctx) }()
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	fj.mu.Lock()
	open, pending := fj.f != nil, fj.pending
	fj.mu.Unlock()
	if open || pending != 0 {
		t.Fatalf("after Start: open %v pending %d", open, pending)
	}
	if got := loadAll(t, d); len(got) != 2 {
		t.Fatalf("%d lines", len(got))
	}
}
