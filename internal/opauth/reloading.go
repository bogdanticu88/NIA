package opauth

import (
	"context"
	"log"
	"os"
	"sync"
	"time"
)

// ReloadingStore re-reads the token file when it changes on disk, which
// is what turns "edit the file and restart the process" into something
// closer to revocation.
//
// This package's own doc comment used to name that as an open gap: a
// leaked operator token could only be retired by editing the source
// file and restarting, with no equivalent of credentials.Store.Revoke.
// Removing a line from the file now takes effect within reloadInterval
// on every process reading it, no restart and no coordination between
// replicas beyond them sharing the file.
//
// It is deliberately not a database-backed store with a Revoke method.
// That would need an issuance API, a schema, and a way to bootstrap the
// first token, and the thing actually being asked for here is "make a
// leaked token stop working soon, without a deploy." A file every
// process already reads does that.
//
// Two decisions worth stating because they are the ones that could bite.
// The file is only re-read when its modification time or size changes,
// so a Verify in the hot path costs a stat, not a parse. And a reload
// that fails to parse keeps the previous good set rather than dropping
// every token: a half-saved file or a stray comma during an edit must
// not lock every operator out of the control plane at once, which is a
// worse outcome than a stale token surviving a few more seconds.
type ReloadingStore struct {
	path     string
	interval time.Duration

	mu        sync.RWMutex
	current   *StaticStore
	lastMod   time.Time
	lastSize  int64
	lastCheck time.Time

	now func() time.Time
	// onError is called when a reload fails. Swappable so tests can
	// assert the failure path without reading log output.
	onError func(error)
}

// reloadInterval is how often a Verify will stat the file at most. Two
// seconds is far below how fast anyone can respond to a leaked token
// anyway, and far above the rate at which statting one file matters.
const reloadInterval = 2 * time.Second

// NewReloadingStore loads path immediately, so a bad file is a startup
// error rather than a surprise on the first request, and re-reads it on
// demand afterwards.
func NewReloadingStore(path string) (*ReloadingStore, error) {
	s := &ReloadingStore{
		path:     path,
		interval: reloadInterval,
		now:      time.Now,
		onError: func(err error) {
			log.Printf("opauth: reloading %s failed, keeping the previously loaded tokens: %v", path, err)
		},
	}
	store, mod, size, err := loadTokenFile(path)
	if err != nil {
		return nil, err
	}
	s.current, s.lastMod, s.lastSize = store, mod, size
	s.lastCheck = s.now()
	return s, nil
}

func (s *ReloadingStore) Verify(ctx context.Context, token string) (Operator, error) {
	s.maybeReload()
	s.mu.RLock()
	current := s.current
	s.mu.RUnlock()
	return current.Verify(ctx, token)
}

// maybeReload stats the file at most once per interval and reloads only
// when it looks different. Modification time and size together rather
// than time alone: a file rewritten within the same filesystem
// timestamp granularity is common when a script edits it, and catching
// the size change covers most of that.
func (s *ReloadingStore) maybeReload() {
	s.mu.Lock()
	if s.now().Sub(s.lastCheck) < s.interval {
		s.mu.Unlock()
		return
	}
	s.lastCheck = s.now()
	path, lastMod, lastSize := s.path, s.lastMod, s.lastSize
	s.mu.Unlock()

	info, err := os.Stat(path)
	if err != nil {
		s.onError(err)
		return
	}
	if info.ModTime().Equal(lastMod) && info.Size() == lastSize {
		return
	}

	store, mod, size, err := loadTokenFile(path)
	if err != nil {
		s.onError(err)
		return
	}
	s.mu.Lock()
	s.current, s.lastMod, s.lastSize = store, mod, size
	s.mu.Unlock()
}

var _ Store = (*ReloadingStore)(nil)
