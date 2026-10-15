package cvedetail

import (
	"context"
	"sync"
)

// Fake is an in-memory Provider for tests. It answers from Records, returns
// Errs[cve] when set, and ErrNotFound otherwise. It records every lookup.
type Fake struct {
	ProviderName string

	mu      sync.Mutex
	records map[string]Record
	errs    map[string]error
	calls   []string
	// block, when set, holds every Lookup until it is closed.
	block chan struct{}
}

// NewFake returns an empty fake named name.
func NewFake(name string) *Fake {
	return &Fake{ProviderName: name, records: map[string]Record{}, errs: map[string]error{}}
}

// Name implements Provider.
func (f *Fake) Name() string { return f.ProviderName }

// Set arms a record for its CVE.
func (f *Fake) Set(rec Record) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.records[rec.CVEID] = rec
}

// Fail makes lookups for cve return err.
func (f *Fake) Fail(cve string, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.errs[cve] = err
}

// Block makes every Lookup wait until the returned function is called.
func (f *Fake) Block() (release func()) {
	ch := make(chan struct{})
	f.mu.Lock()
	f.block = ch
	f.mu.Unlock()
	var once sync.Once
	return func() { once.Do(func() { close(ch) }) }
}

// Calls returns the CVEs looked up so far, in order.
func (f *Fake) Calls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

// Lookup implements Provider.
func (f *Fake) Lookup(ctx context.Context, cveID string) (Record, error) {
	f.mu.Lock()
	f.calls = append(f.calls, cveID)
	block := f.block
	rec, found := f.records[cveID]
	err := f.errs[cveID]
	f.mu.Unlock()
	if block != nil {
		select {
		case <-block:
		case <-ctx.Done():
			return Record{}, ctx.Err()
		}
	}
	if err != nil {
		return Record{}, err
	}
	if !found {
		return Record{}, ErrNotFound
	}
	return rec, nil
}
