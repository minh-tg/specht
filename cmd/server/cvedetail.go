package main

import (
	"context"
	"log/slog"

	"github.com/minh-tg/specht/internal/config"
	"github.com/minh-tg/specht/internal/cvedetail"
	"github.com/minh-tg/specht/internal/repo"
	"github.com/minh-tg/specht/internal/usecase"
)

// buildCVEDetail wires the CVE detail read: the occurrence reader and cache
// store over PostgreSQL, the provider resolver, and the intel lookup. With no
// provider configured the resolver is empty and nothing is fetched.
func buildCVEDetail(c config.CVEDetailConfig, store *repo.CVEDetailStore, intelStore usecase.IntelStore) (usecase.CVEDetailDeps, *cvedetail.Resolver) {
	client := cvedetail.NewHTTPClient(c.Timeout, c.AllowPrivateMirror)
	var providers []cvedetail.Provider
	for _, name := range c.Providers {
		switch name {
		case config.CVEProviderNVD:
			providers = append(providers, &cvedetail.NVD{BaseURL: c.NVDBaseURL, APIKey: c.NVDAPIKey, Client: client})
		case config.CVEProviderVulnCheck:
			providers = append(providers, &cvedetail.VulnCheck{BaseURL: c.VulnCheckBaseURL, APIKey: c.VulnCheckAPIKey, Client: client})
		case config.CVEProviderOSV:
			providers = append(providers, &cvedetail.OSV{BaseURL: c.OSVBaseURL, Client: client})
		}
	}
	if len(providers) > 0 {
		// LogValue reports key presence only.
		slog.Info("cve detail providers enabled; only CVE identifiers are sent", "cve_detail", c)
	}
	resolver := cvedetail.NewResolver(store, cvedetail.Config{
		TTL:         c.TTL,
		NegativeTTL: c.NegativeTTL,
		// A fetch holds its lease for one request at most, so a few
		// timeouts leave room for slow answers before another replica
		// may take over.
		LeaseTTL: max(cvedetail.DefaultLeaseTTL, 3*c.Timeout),
		Rates:    c.RPS,
	}, providers...)
	return usecase.CVEDetailDeps{
		Occurrences: store,
		Providers:   resolver,
		Intel:       intelLookup{store: intelStore},
	}, resolver
}

// startCVEDetail runs the provider fetch workers and the cache sweep until
// ctx ends.
func startCVEDetail(ctx context.Context, resolver *cvedetail.Resolver, store *repo.CVEDetailStore, cfg *config.Server) {
	resolver.Start(ctx)
	exitOnError("start cve detail cache sweep", cvedetail.RunSweeper(ctx, store, cfg.SweepInterval, slog.Default()))
}

// intelLookup adapts the intel store to the CVE detail read. It only reads
// the cache; the finding read already schedules refreshes.
type intelLookup struct {
	store usecase.IntelStore
}

func (l intelLookup) LookupIntel(cveID string) (usecase.IntelRecord, bool) {
	if l.store == nil {
		return usecase.IntelRecord{}, false
	}
	rec, _, ok := l.store.Lookup(cveID)
	if !ok {
		return usecase.IntelRecord{}, false
	}
	out := usecase.IntelRecord{
		EPSSDate:       rec.EPSSDate,
		EPSSPercentile: rec.EPSSPercentile,
		KEV:            rec.KEV,
		KEVDateAdded:   rec.KEVAdded,
		KEVDueDate:     rec.KEVDueDate,
		KEVRansomware:  rec.KEVRansomware,
		FetchedAt:      rec.FetchedAt,
	}
	if rec.EPSS != nil {
		out.EPSS = *rec.EPSS
	}
	return out, true
}
