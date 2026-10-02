package vread

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// Store is where ciphertexts that are not carried in their records are
// kept (docs/spec.md section 5.4): directories and http(s) base URLs, each
// holding a ciphertext in a file named by the lowercase hex of its SHA-256.
// The owner publishes a directory under BRC-26, where its locator is the
// uhrp:// form of the same hash; this is the reader's and the writer's end
// of it and speaks no advertisement protocol.
type Store struct {
	// Sources are directories and http(s) base URLs, tried in order.
	Sources []string
	// Max is the most bytes a reader fetches for one ciphertext.
	Max  int
	HTTP *http.Client
}

func isURL(s string) bool {
	return strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://")
}

// Dir is the first directory among the sources: where a writer stores.
func (s *Store) Dir() string {
	for _, src := range s.Sources {
		if !isURL(src) {
			return src
		}
	}
	return ""
}

// Put writes a ciphertext into the first directory source, named by its
// hash, and returns the file's path. A file that exists holds the same
// bytes, so it is left.
func (s *Store) Put(ct []byte) (string, error) {
	dir := s.Dir()
	if dir == "" {
		return "", errors.New("no content directory configured (config key content): a ciphertext too large to be carried is written there, for the owner to serve by its hash")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil { //nolint:gosec // ciphertext is public
		return "", err
	}
	h := sha256.Sum256(ct)
	p := filepath.Join(dir, hex.EncodeToString(h[:]))
	if _, err := os.Stat(p); err == nil {
		return p, nil
	}
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return "", err
	}
	if _, err := tmp.Write(ct); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return "", err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return "", err
	}
	if err := os.Chmod(tmp.Name(), 0o644); err != nil { //nolint:gosec // ciphertext is public
		os.Remove(tmp.Name())
		return "", err
	}
	return p, os.Rename(tmp.Name(), p)
}

// Get fetches the ciphertext of hash, of length bytes, from the first
// source that holds it. A length over the reader's budget is refused before
// anything is fetched, and no source is read past length: a record is a
// fetch instruction, and a reader bounds it. The caller checks the hash.
func (s *Store) Get(ctx context.Context, hash [32]byte, length uint64) ([]byte, error) {
	if s == nil || len(s.Sources) == 0 {
		return nil, fmt.Errorf("%w: none is configured (config key content)", ErrUnavailable)
	}
	if s.Max > 0 && length > uint64(s.Max) {
		return nil, fmt.Errorf("the record names a ciphertext of %d bytes, over this reader's fetch budget of %d (config key max_fetch)", length, s.Max)
	}
	name := hex.EncodeToString(hash[:])
	var last error
	for _, src := range s.Sources {
		var b []byte
		var err error
		if isURL(src) {
			b, err = s.fetch(ctx, strings.TrimRight(src, "/")+"/"+name, length)
		} else {
			b, err = readBounded(filepath.Join(src, name), length)
		}
		if err == nil {
			return b, nil
		}
		last = err
	}
	return nil, fmt.Errorf("%w: %v", ErrUnavailable, last)
}

func readBounded(path string, length uint64) ([]byte, error) {
	f, err := os.Open(path) //nolint:gosec // a configured content directory
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, int64(length)+1)) //nolint:gosec // bounded by the record bound
}

func (s *Store) fetch(ctx context.Context, url string, length uint64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	hc := s.HTTP
	if hc == nil {
		hc = http.DefaultClient
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: status %d", url, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, int64(length)+1)) //nolint:gosec // bounded by the record bound
}
