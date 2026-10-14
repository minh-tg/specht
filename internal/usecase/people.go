package usecase

import (
	"context"
	"log/slog"

	"github.com/minh-tg/specht/internal/auth"
)

// peopleLabels returns the name to show for each user id, for lists that
// belong to a project (waivers, their history, a finding's history). The label
// is the display name, or the email address when the person never set one;
// project members already see both in the member roster. The seeded system
// account, which automated actions are filed under, reads as "System".
//
// It is a convenience and never fails a read: an API key gets no names, a
// missing user store or a failed lookup returns no names, and blank or
// repeated ids cost nothing. All ids are resolved in one query.
func (u *Usecases) peopleLabels(ctx context.Context, ids []string) map[string]string {
	ident := auth.ContextIdentity(ctx)
	if (ident != nil && ident.IsAPIKey) || u.deps.Stores == nil || u.deps.Stores.Users == nil {
		return nil
	}
	seen := make(map[string]struct{}, len(ids))
	unique := make([]string, 0, len(ids))
	for _, id := range ids {
		if id == "" {
			continue
		}
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		unique = append(unique, id)
	}
	if len(unique) == 0 {
		return nil
	}
	users, err := u.deps.Stores.Users.ListByIDs(ctx, unique)
	if err != nil {
		slog.Warn("look up people for a list", "error", err)
		return nil
	}
	labels := make(map[string]string, len(users))
	for _, user := range users {
		switch {
		case isSystemAccount(user.Email):
			labels[user.ID] = "System"
		case user.DisplayName != nil && *user.DisplayName != "":
			labels[user.ID] = *user.DisplayName
		default:
			labels[user.ID] = user.Email
		}
	}
	return labels
}

// nameWaiverPeople fills in who requested and who decided each waiver.
func (u *Usecases) nameWaiverPeople(ctx context.Context, waivers []WaiverResponse) {
	ids := make([]string, 0, len(waivers)*2)
	for _, w := range waivers {
		if w.RequestedBy != nil {
			ids = append(ids, *w.RequestedBy)
		}
		if w.DecidedBy != nil {
			ids = append(ids, *w.DecidedBy)
		}
	}
	labels := u.peopleLabels(ctx, ids)
	if len(labels) == 0 {
		return
	}
	for i := range waivers {
		if waivers[i].RequestedBy != nil {
			waivers[i].RequestedByName = labels[*waivers[i].RequestedBy]
		}
		if waivers[i].DecidedBy != nil {
			waivers[i].DecidedByName = labels[*waivers[i].DecidedBy]
		}
	}
}
