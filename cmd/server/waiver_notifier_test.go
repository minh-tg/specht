package main

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/port"
	"github.com/minh-tg/specht/internal/usecase"
	"github.com/minh-tg/specht/internal/watcher"
)

type recordingChannels struct{ sent []watcher.Notification }

func (r *recordingChannels) Notify(_ context.Context, n []watcher.Notification) error {
	r.sent = append(r.sent, n...)
	return nil
}

type oneProject struct{ port.ProjectStore }

func (oneProject) GetByID(_ context.Context, id string) (port.Project, error) {
	if id != "p1" {
		return port.Project{}, fmt.Errorf("no project %s", id)
	}
	return port.Project{ID: "p1", Slug: "checkout", Name: "Checkout API"}, nil
}

func TestNotifyWaiverSaysWhatHappenedAndLinksToIt(t *testing.T) {
	channels := &recordingChannels{}
	sender := &waiverNoticeSender{channels: channels, baseURL: "https://specht.example.com/"}
	sender.NotifyWaiver(context.Background(), usecase.WaiverNotice{
		Event: usecase.WaiverEventRequested, ProjectSlug: "checkout", ProjectName: "Checkout API",
		Title: "lodash", Detail: "not reachable", Actor: "Dev One",
	})
	require.Len(t, channels.sent, 1)
	got := channels.sent[0]
	assert.Equal(t, "Waiver requested by Dev One", got.Heading)
	assert.Equal(t, "lodash: not reachable", got.Title)
	assert.Equal(t, "Checkout API", got.Project)
	assert.Equal(t, "https://specht.example.com/checkout/waivers", got.Link)
	assert.Equal(t, usecase.WaiverEventRequested, got.Event)
}

func TestNotifyWaiverWithoutABaseURLHasNoLink(t *testing.T) {
	channels := &recordingChannels{}
	sender := &waiverNoticeSender{channels: channels}
	sender.NotifyWaiver(context.Background(), usecase.WaiverNotice{Event: usecase.WaiverEventApproved, ProjectSlug: "checkout"})
	assert.Empty(t, channels.sent[0].Link)
}

func TestWaiversEndedSkipsARequestThatWasNeverInForce(t *testing.T) {
	channels := &recordingChannels{}
	sender := &waiverNoticeSender{channels: channels, projects: oneProject{}}
	sender.WaiversEnded(context.Background(), []port.Waiver{
		{ProjectID: "p1", Name: "in force", Status: usecase.WaiverStatusApproved},
		{ProjectID: "p1", Name: "Waiver request: never decided", Status: usecase.WaiverStatusRejected},
	})
	require.Len(t, channels.sent, 1)
	assert.Equal(t, "in force", channels.sent[0].Title)
	assert.Equal(t, usecase.WaiverEventExpired, channels.sent[0].Event)
	assert.Equal(t, "Checkout API", channels.sent[0].Project)
}

func TestWaiversEndingStripsTheRequestPrefix(t *testing.T) {
	channels := &recordingChannels{}
	sender := &waiverNoticeSender{channels: channels, projects: oneProject{}}
	sender.WaiversEnding(context.Background(), []port.Waiver{{ProjectID: "p1", Name: "Waiver request: lodash"}})
	require.Len(t, channels.sent, 1)
	assert.Equal(t, "lodash", channels.sent[0].Title)
	assert.Equal(t, usecase.WaiverEventExpiring, channels.sent[0].Event)
}
