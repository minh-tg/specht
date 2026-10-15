package cvedetail

import (
	"context"
	"sync"
	"time"
)

// memStore is an in-memory Store with the same lease rules as the SQL.
type memStore struct {
	mu      sync.Mutex
	rows    map[string]CacheEntry
	states  map[string]ProviderState
	leases  int
	denyAll bool
}

func newMemStore() *memStore {
	return &memStore{rows: map[string]CacheEntry{}, states: map[string]ProviderState{}}
}

func key(provider, cve string) string { return provider + "|" + cve }

func (m *memStore) ListCached(_ context.Context, cve string) ([]CacheEntry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []CacheEntry
	for _, e := range m.rows {
		if e.CVEID == cve {
			out = append(out, e)
		}
	}
	return out, nil
}

func (m *memStore) AcquireLease(_ context.Context, provider, cve string, now, until time.Time) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.denyAll {
		return false, nil
	}
	e, ok := m.rows[key(provider, cve)]
	if !ok {
		m.rows[key(provider, cve)] = CacheEntry{Provider: provider, CVEID: cve, Status: StatusPending, FetchedAt: now, ExpiresAt: now, LeaseUntil: &until}
		m.leases++
		return true, nil
	}
	if e.LeaseUntil != nil && e.LeaseUntil.After(now) {
		return false, nil
	}
	if e.Status != StatusPending && e.ExpiresAt.After(now) {
		return false, nil
	}
	e.LeaseUntil = &until
	m.rows[key(provider, cve)] = e
	m.leases++
	return true, nil
}

func (m *memStore) StoreAnswer(_ context.Context, e CacheEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	e.LeaseUntil = nil
	m.rows[key(e.Provider, e.CVEID)] = e
	return nil
}

func (m *memStore) ReleaseLease(_ context.Context, provider, cve string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.rows[key(provider, cve)]
	if !ok {
		return nil
	}
	if e.Status == StatusPending {
		delete(m.rows, key(provider, cve))
		return nil
	}
	e.LeaseUntil = nil
	m.rows[key(provider, cve)] = e
	return nil
}

func (m *memStore) RecordSuccess(_ context.Context, provider string, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.states[provider]
	s.Provider = provider
	s.LastSuccessAt = &at
	m.states[provider] = s
	return nil
}

func (m *memStore) RecordError(_ context.Context, provider, kind string, at, backoff time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.states[provider]
	s.Provider = provider
	s.LastErrorAt = &at
	s.LastError = kind
	if s.BackoffUntil == nil || backoff.After(*s.BackoffUntil) {
		s.BackoffUntil = &backoff
	}
	m.states[provider] = s
	return nil
}

func (m *memStore) ListProviderStates(context.Context) ([]ProviderState, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []ProviderState
	for _, s := range m.states {
		out = append(out, s)
	}
	return out, nil
}

func (m *memStore) Sweep(_ context.Context, cutoff time.Time) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var n int64
	for k, e := range m.rows {
		if e.ExpiresAt.Before(cutoff) {
			delete(m.rows, k)
			n++
		}
	}
	return n, nil
}

func (m *memStore) row(provider, cve string) (CacheEntry, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.rows[key(provider, cve)]
	return e, ok
}
