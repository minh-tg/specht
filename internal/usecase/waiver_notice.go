package usecase

import (
	"context"
	"log/slog"
	"strings"
	"time"
)

// Waiver events a notifier receives.
const (
	WaiverEventRequested = "waiver.requested"
	WaiverEventApproved  = "waiver.approved"
	WaiverEventRejected  = "waiver.rejected"
	WaiverEventExpiring  = "waiver.expiring"
	WaiverEventExpired   = "waiver.expired"
)

// WaiverExpiryWarning is how long before its end an approved waiver is announced.
const WaiverExpiryWarning = 7 * 24 * time.Hour

// WaiverNotice is one change to a waiver that someone is waiting on. Specht sends
// no email, so without this a request sits until somebody opens the Waivers page,
// and a lapsing waiver turns a pipeline red with no warning.
type WaiverNotice struct {
	Event       string
	ProjectSlug string
	ProjectName string
	Title       string
	// Detail is the requester's reason or the reviewer's note.
	Detail string
	// Actor names who did it.
	Actor string
}

// WaiverNotifier delivers a notice. It never fails the caller: delivery problems
// are the channel's to log.
type WaiverNotifier interface {
	NotifyWaiver(ctx context.Context, notice WaiverNotice)
}

// waiverNoticeTimeout bounds a delivery that runs after the response was sent.
const waiverNoticeTimeout = 30 * time.Second

// sendWaiverNotice delivers a notice without making the request wait for a slow
// webhook. It uses its own context because the request's ends with the response.
func (u *Usecases) sendWaiverNotice(notice WaiverNotice) {
	if u.deps.WaiverNotifier == nil {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), waiverNoticeTimeout)
		defer cancel()
		defer func() {
			if r := recover(); r != nil {
				slog.Error("waiver notification panicked", "event", notice.Event, "panic", r)
			}
		}()
		u.deps.WaiverNotifier.NotifyWaiver(ctx, notice)
	}()
}

// waiverNoticeTitle reads a waiver's display name without the prefix requests carry.
func waiverNoticeTitle(name string) string {
	return strings.TrimPrefix(name, "Waiver request: ")
}

// waiverActorName names the signed-in person for a notice, by display name when
// they have one.
func (u *Usecases) waiverActorName(ctx context.Context, userID string) string {
	if u.deps.WaiverNotifier == nil || u.deps.Stores.Users == nil {
		return ""
	}
	user, err := u.deps.Stores.Users.GetByID(ctx, userID)
	if err != nil {
		return ""
	}
	if user.DisplayName != nil && *user.DisplayName != "" {
		return *user.DisplayName
	}
	return user.Email
}
