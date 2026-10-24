package repo

import (
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/minh-tg/specht/internal/db/sqlc"
	"github.com/minh-tg/specht/internal/port"
)

// NewPortStores builds the neutral port aggregate over the existing
// PostgreSQL repositories. The inner *Repos values remain the sqlc/pgx
// implementations; the returned stores expose only the port contracts so
// use cases, lifecycle, and watcher never see pgtype/sqlc types.
func NewPortStores(pool *pgxpool.Pool) *port.Stores {
	return PortStoresFromRepos(NewRepos(pool), sqlc.New(pool))
}

// PortStoresFromRepos adapts existing repositories without opening another pool.
func PortStoresFromRepos(repos *Repos, q *sqlc.Queries) *port.Stores {
	stores := &port.Stores{
		Projects:        &pgProjectPort{q: q, withTx: repos.WithTx},
		Users:           &pgUserPort{q: q, withTx: repos.WithTx},
		Invites:         &pgInvitePort{q: q, withTx: repos.WithTx},
		PasswordReset:   &pgPasswordResetPort{withTx: repos.WithTx},
		InstanceSecrets: &pgInstanceSecretPort{q: q},
		RefreshTokens:   &pgRefreshTokenPort{q: q, withTx: repos.WithTx},
		APIKeys:         &pgAPIKeyPort{q: q, withTx: repos.WithTx},
		Environments:    &pgEnvironmentPort{q: q},
		Targets:         &pgTargetPort{q: q},
		Artifacts:       &pgArtifactPort{q: q},
		Waivers:         &pgWaiverPort{inner: repos.Waivers.(*pgWaiverRepo)},
		Findings:        newFindingPort(repos.Findings.(*pgFindingRepo)),
		Evidence:        &pgEvidencePort{q: q},
		Reachability:    &pgReachabilityPort{q: q},
		Signoffs:        &pgSignoffPort{q: q},
		Reports:         newReportPort(repos.Reports.(*pgReportRepo)),
		Inventory:       &pgInventoryPort{inner: repos.Inventory.(*pgInventoryRepo)},
		Stats:           &pgStatsPort{inner: repos.Stats},
		Watcher:         &pgWatcherPort{inner: repos.Watcher},
		Policy:          &pgPolicyPort{q: q},
		Teams:           &pgTeamPort{q: q},
		Admin:           &pgAdminPort{q: q},
		Identities:      &pgIdentityPort{q: q, withTx: repos.WithTx},
		SSOCodes:        &pgSSOCodePort{q: q},
	}
	stores.Ingest = &pgIngestTransaction{pool: repos.pool, stores: stores}
	return stores
}
