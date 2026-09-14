package repo

import (
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/xMinhx/specht/internal/db/sqlc"
	"github.com/xMinhx/specht/internal/port"
)

// NewPortStores builds the neutral port aggregate over the existing
// PostgreSQL repositories. The inner *Repos values remain the sqlc/pgx
// implementations; the returned stores expose only the port contracts so
// use cases, lifecycle, and watcher never see pgtype/sqlc types.
func NewPortStores(pool *pgxpool.Pool) *port.Stores {
	q := sqlc.New(pool)
	repos := NewRepos(pool)

	return &port.Stores{
		Projects:      &pgProjectPort{q: q},
		Users:         &pgUserPort{q: q},
		RefreshTokens: &pgRefreshTokenPort{q: q},
		APIKeys:       &pgAPIKeyPort{q: q},
		Environments:  &pgEnvironmentPort{q: q},
		Targets:       &pgTargetPort{q: q},
		Artifacts:     &pgArtifactPort{q: q},
		Waivers:       &pgWaiverPort{inner: repos.Waivers.(*pgWaiverRepo)},
		Findings:      newFindingPort(repos.Findings.(*pgFindingRepo)),
		Evidence:      &pgEvidencePort{q: q},
		Reachability:  &pgReachabilityPort{q: q},
		Signoffs:      &pgSignoffPort{q: q},
		Reports:       newReportPort(repos.Reports.(*pgReportRepo)),
		Inventory:     &pgInventoryPort{inner: repos.Inventory.(*pgInventoryRepo)},
		Stats:         &pgStatsPort{inner: repos.Stats},
		Watcher:       &pgWatcherPort{inner: repos.Watcher},
		Admin:         &pgAdminPort{q: q},
	}
}

// PortStoresFromRepos adapts an existing *Repos aggregate to the port
// Stores, sharing the same underlying pool/queries. Useful for callers that
// already constructed a *Repos (composition roots) and want the port view
// without a second pool.
func PortStoresFromRepos(repos *Repos, q *sqlc.Queries) *port.Stores {
	return &port.Stores{
		Projects:      &pgProjectPort{q: q},
		Users:         &pgUserPort{q: q},
		RefreshTokens: &pgRefreshTokenPort{q: q},
		APIKeys:       &pgAPIKeyPort{q: q},
		Environments:  &pgEnvironmentPort{q: q},
		Targets:       &pgTargetPort{q: q},
		Artifacts:     &pgArtifactPort{q: q},
		Waivers:       &pgWaiverPort{inner: repos.Waivers.(*pgWaiverRepo)},
		Findings:      newFindingPort(repos.Findings.(*pgFindingRepo)),
		Evidence:      &pgEvidencePort{q: q},
		Reachability:  &pgReachabilityPort{q: q},
		Signoffs:      &pgSignoffPort{q: q},
		Reports:       newReportPort(repos.Reports.(*pgReportRepo)),
		Inventory:     &pgInventoryPort{inner: repos.Inventory.(*pgInventoryRepo)},
		Stats:         &pgStatsPort{inner: repos.Stats},
		Watcher:       &pgWatcherPort{inner: repos.Watcher},
		Admin:         &pgAdminPort{q: q},
	}
}
