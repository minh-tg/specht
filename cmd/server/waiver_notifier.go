package main

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/minh-tg/specht/internal/lifecycle"
	"github.com/minh-tg/specht/internal/port"
	"github.com/minh-tg/specht/internal/usecase"
	"github.com/minh-tg/specht/internal/watcher"
)

// waiverNoticeSender delivers waiver changes over the notification channels the
// server already has. Specht sends no email, so these are the only way a waiver
// request reaches an approver who is not looking at the page.
type waiverNoticeSender struct {
	channels watcher.Notifier
	baseURL  string
	projects port.ProjectStore
}

var waiverHeadings = map[string]string{
	usecase.WaiverEventRequested: "Waiver requested",
	usecase.WaiverEventApproved:  "Waiver approved",
	usecase.WaiverEventRejected:  "Waiver rejected",
	usecase.WaiverEventExpiring:  "Waiver ends within a week, then its findings block again",
	usecase.WaiverEventExpired:   "Waiver ended, so its findings block again",
}

// NotifyWaiver implements usecase.WaiverNotifier.
func (s *waiverNoticeSender) NotifyWaiver(ctx context.Context, notice usecase.WaiverNotice) {
	heading := waiverHeadings[notice.Event]
	if notice.Actor != "" {
		heading = fmt.Sprintf("%s by %s", heading, notice.Actor)
	}
	title := notice.Title
	if notice.Detail != "" {
		title = fmt.Sprintf("%s: %s", title, notice.Detail)
	}
	link := ""
	if s.baseURL != "" && notice.ProjectSlug != "" {
		link = strings.TrimRight(s.baseURL, "/") + "/" + notice.ProjectSlug + "/waivers"
	}
	if err := s.channels.Notify(ctx, []watcher.Notification{{
		Title:   title,
		Project: notice.ProjectName,
		Link:    link,
		Event:   notice.Event,
		Heading: heading,
	}}); err != nil {
		slog.Warn("waiver notification", "event", notice.Event, "error", err)
	}
}

// WaiversEnding implements lifecycle.WaiverAnnouncer.
func (s *waiverNoticeSender) WaiversEnding(ctx context.Context, waivers []port.Waiver) {
	s.announce(ctx, usecase.WaiverEventExpiring, waivers)
}

// WaiversEnded implements lifecycle.WaiverAnnouncer. A request that outlived its
// expiry was never in force, and it has no findings to start blocking again.
func (s *waiverNoticeSender) WaiversEnded(ctx context.Context, waivers []port.Waiver) {
	approved := make([]port.Waiver, 0, len(waivers))
	for _, w := range waivers {
		if w.Status != usecase.WaiverStatusRejected {
			approved = append(approved, w)
		}
	}
	s.announce(ctx, usecase.WaiverEventExpired, approved)
}

func (s *waiverNoticeSender) announce(ctx context.Context, event string, waivers []port.Waiver) {
	for _, w := range waivers {
		notice := usecase.WaiverNotice{Event: event, Title: strings.TrimPrefix(w.Name, "Waiver request: ")}
		if project, err := s.projects.GetByID(ctx, w.ProjectID); err == nil {
			notice.ProjectSlug, notice.ProjectName = project.Slug, project.Name
		}
		s.NotifyWaiver(ctx, notice)
	}
}

var _ lifecycle.WaiverAnnouncer = (*waiverNoticeSender)(nil)
