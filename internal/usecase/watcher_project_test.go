package usecase

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/auth"
	"github.com/minh-tg/specht/internal/port"
)

// fakeWatcherStore keeps one project's watcher settings in memory.
type fakeWatcherStore struct {
	port.WatcherStore
	project     port.Project
	lastPoll    *time.Time
	global      port.WatcherState
	globalMiss  bool
	updateErr   error
	updateCalls int
}

func (f *fakeWatcherStore) GetProjectConfig(context.Context, string) (port.Project, error) {
	return f.project, nil
}

func (f *fakeWatcherStore) UpdateProjectConfig(_ context.Context, _ string, enabled *bool, interval *int32) (port.Project, error) {
	f.updateCalls++
	if f.updateErr != nil {
		return port.Project{}, f.updateErr
	}
	if enabled != nil {
		f.project.CveWatcherEnabled = *enabled
	}
	if interval != nil {
		f.project.CveWatcherIntervalSecs = *interval
	}
	return f.project, nil
}

func (f *fakeWatcherStore) GetProjectState(context.Context, string) (port.WatcherProjectState, error) {
	if f.lastPoll == nil {
		return port.WatcherProjectState{}, port.ErrNotFound
	}
	return port.WatcherProjectState{LastSuccessfulPollAt: f.lastPoll}, nil
}

func (f *fakeWatcherStore) GetState(context.Context) (port.WatcherState, error) {
	if f.globalMiss {
		return port.WatcherState{}, port.ErrNotFound
	}
	return f.global, nil
}

func projectWatcherUsecase(role string, settings WatcherSettings, store *fakeWatcherStore) *Usecases {
	pr := &mockProjectRepo{
		getBySlugFn: func(_ context.Context, slug string) (port.Project, error) {
			if slug != "payments" {
				return port.Project{}, port.ErrNotFound
			}
			return port.Project{ID: "00000000-0000-0000-0000-000000000001", Slug: slug}, nil
		},
		effectiveRoleFn: func(context.Context, string, string) (string, error) { return role, nil },
	}
	return New(Deps{Stores: &port.Stores{Projects: pr, Watcher: store}, Watcher: settings})
}

func newWatcherStore() *fakeWatcherStore {
	return &fakeWatcherStore{
		project:    port.Project{ID: "00000000-0000-0000-0000-000000000001", Slug: "payments", CveWatcherEnabled: true, CveWatcherIntervalSecs: 3600},
		globalMiss: true,
	}
}

var serverOn = WatcherSettings{Enabled: true, PollInterval: 6 * time.Hour}

func ptr[T any](v T) *T { return &v }

func TestGetProjectWatcher_ReportsSettingsAndStatus(t *testing.T) {
	now := time.Now().UTC()
	recent := now.Add(-30 * time.Minute)
	old := now.Add(-5 * time.Hour)

	tests := []struct {
		name        string
		settings    WatcherSettings
		mutate      func(*fakeWatcherStore)
		status      string
		effective   bool
		healthy     bool
		hasLastPoll bool
	}{
		{"waiting for the first poll", serverOn, func(f *fakeWatcherStore) {}, WatcherStatusWaiting, true, true, false},
		{"polled recently", serverOn, func(f *fakeWatcherStore) { f.lastPoll = &recent }, WatcherStatusOK, true, true, true},
		{"last poll older than the interval explains", serverOn, func(f *fakeWatcherStore) { f.lastPoll = &old }, WatcherStatusStale, true, false, true},
		{"the watcher's polls are failing", serverOn, func(f *fakeWatcherStore) {
			f.lastPoll = &recent
			f.globalMiss = false
			f.global = port.WatcherState{ConsecutiveFailures: 3}
		}, WatcherStatusFailing, true, false, true},
		{"switched off for the project", serverOn, func(f *fakeWatcherStore) { f.project.CveWatcherEnabled = false }, WatcherStatusDisabled, false, true, false},
		{"the server does not run the watcher", WatcherSettings{Enabled: false, PollInterval: time.Hour}, func(f *fakeWatcherStore) {}, WatcherStatusServerOff, false, true, false},
		{"off for the project and for the server reads as off for the project", WatcherSettings{}, func(f *fakeWatcherStore) { f.project.CveWatcherEnabled = false }, WatcherStatusDisabled, false, true, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			store := newWatcherStore()
			tc.mutate(store)

			resp, err := projectWatcherUsecase(auth.RoleMember, tc.settings, store).GetProjectWatcher(sessionCtx("u1", auth.RoleViewer), "payments")

			require.NoError(t, err)
			assert.Equal(t, tc.status, resp.Status)
			assert.Equal(t, tc.effective, resp.EffectiveEnabled)
			assert.Equal(t, tc.healthy, resp.Healthy)
			assert.Equal(t, tc.hasLastPoll, resp.LastPollAt != "")
			assert.Equal(t, store.project.CveWatcherEnabled, resp.Enabled, "the stored switch is reported as it is")
			assert.EqualValues(t, 3600, resp.IntervalSeconds)
			assert.EqualValues(t, 3600, resp.EffectiveIntervalSeconds)
			assert.EqualValues(t, 3600, resp.DefaultIntervalSeconds)
		})
	}
}

func TestGetProjectWatcher_ReportsTheAcceptedRange(t *testing.T) {
	for name, tc := range map[string]struct {
		settings WatcherSettings
		min      int32
	}{
		"a slow operator cadence never raises the floor above the default": {WatcherSettings{Enabled: true, PollInterval: 6 * time.Hour}, 3600},
		"a faster operator cadence lowers it":                              {WatcherSettings{Enabled: true, PollInterval: 10 * time.Minute}, 600},
		"no configured cadence falls back to the default":                  {WatcherSettings{Enabled: true}, 3600},
	} {
		t.Run(name, func(t *testing.T) {
			resp, err := projectWatcherUsecase(auth.RoleMember, tc.settings, newWatcherStore()).GetProjectWatcher(sessionCtx("u1", auth.RoleViewer), "payments")
			require.NoError(t, err)
			assert.Equal(t, tc.min, resp.MinIntervalSeconds)
			assert.EqualValues(t, 7*24*3600, resp.MaxIntervalSeconds)
		})
	}
}

func TestGetProjectWatcher_NeedsAProjectMember(t *testing.T) {
	uc := projectWatcherUsecase("", serverOn, newWatcherStore())
	uc.deps.Stores.Projects.(*mockProjectRepo).effectiveRoleFn = func(context.Context, string, string) (string, error) {
		return "", port.ErrNotFound
	}
	_, err := uc.GetProjectWatcher(sessionCtx("outsider", auth.RoleViewer), "payments")
	assert.ErrorIs(t, err, ErrProjectAccessDenied)
}

func TestUpdateProjectWatcher_NeedsProjectAdmin(t *testing.T) {
	for name, tc := range map[string]struct {
		role string
		ctx  context.Context
	}{
		"manager":   {auth.RoleManager, sessionCtx("u1", auth.RoleViewer)},
		"member":    {auth.RoleMember, sessionCtx("u1", auth.RoleViewer)},
		"API key":   {auth.RoleAdmin, apiKeyCtx("k1", "00000000-0000-0000-0000-000000000001")},
		"anonymous": {auth.RoleAdmin, context.Background()},
	} {
		t.Run(name, func(t *testing.T) {
			store := newWatcherStore()
			_, err := projectWatcherUsecase(tc.role, serverOn, store).UpdateProjectWatcher(tc.ctx, "payments", WatcherSettingsInput{Enabled: ptr(false)})
			assert.ErrorIs(t, err, ErrProjectAccessDenied)
			assert.Zero(t, store.updateCalls)
		})
	}

	_, err := projectWatcherUsecase(auth.RoleAdmin, serverOn, newWatcherStore()).UpdateProjectWatcher(sessionCtx("u1", auth.RoleViewer), "nope", WatcherSettingsInput{Enabled: ptr(false)})
	assert.ErrorIs(t, err, ErrProjectAccessDenied, "an unknown project looks like no access")
}

func TestUpdateProjectWatcher_ChangesOnlyWhatWasAsked(t *testing.T) {
	store := newWatcherStore()
	uc := projectWatcherUsecase(auth.RoleAdmin, serverOn, store)
	admin := sessionCtx("u1", auth.RoleViewer)

	resp, err := uc.UpdateProjectWatcher(admin, "payments", WatcherSettingsInput{Enabled: ptr(false)})
	require.NoError(t, err)
	assert.False(t, resp.Enabled)
	assert.EqualValues(t, 3600, resp.IntervalSeconds, "the interval is untouched")
	assert.Equal(t, WatcherStatusDisabled, resp.Status)

	resp, err = uc.UpdateProjectWatcher(admin, "payments", WatcherSettingsInput{IntervalSeconds: ptr(int32(7200))})
	require.NoError(t, err)
	assert.False(t, resp.Enabled, "the switch is untouched")
	assert.EqualValues(t, 7200, resp.IntervalSeconds)
	assert.EqualValues(t, 7200, resp.EffectiveIntervalSeconds)
}

func TestUpdateProjectWatcher_ResetReturnsToTheDefault(t *testing.T) {
	store := newWatcherStore()
	store.project.CveWatcherIntervalSecs = 86400
	uc := projectWatcherUsecase(auth.RoleAdmin, serverOn, store)

	resp, err := uc.UpdateProjectWatcher(sessionCtx("u1", auth.RoleViewer), "payments", WatcherSettingsInput{ResetInterval: true})

	require.NoError(t, err)
	assert.EqualValues(t, 3600, resp.IntervalSeconds)
}

func TestUpdateProjectWatcher_EnablingWhileTheServerHasItOffIsStoredButNotInEffect(t *testing.T) {
	store := newWatcherStore()
	store.project.CveWatcherEnabled = false
	uc := projectWatcherUsecase(auth.RoleAdmin, WatcherSettings{Enabled: false, PollInterval: time.Hour}, store)

	resp, err := uc.UpdateProjectWatcher(sessionCtx("u1", auth.RoleViewer), "payments", WatcherSettingsInput{Enabled: ptr(true)})

	require.NoError(t, err)
	assert.True(t, resp.Enabled, "the setting survives turning the server's watcher on")
	assert.False(t, resp.EffectiveEnabled)
	assert.Equal(t, WatcherStatusServerOff, resp.Status)
}

func TestUpdateProjectWatcher_ValidatesTheInterval(t *testing.T) {
	admin := sessionCtx("u1", auth.RoleViewer)
	fast := WatcherSettings{Enabled: true, PollInterval: 10 * time.Minute}

	for name, tc := range map[string]struct {
		settings WatcherSettings
		in       WatcherSettingsInput
		ok       bool
	}{
		"nothing to change":                     {serverOn, WatcherSettingsInput{}, false},
		"interval and reset together":           {serverOn, WatcherSettingsInput{IntervalSeconds: ptr(int32(7200)), ResetInterval: true}, false},
		"below the default under a slow server": {serverOn, WatcherSettingsInput{IntervalSeconds: ptr(int32(600))}, false},
		"at the floor":                          {serverOn, WatcherSettingsInput{IntervalSeconds: ptr(int32(3600))}, true},
		"below a fast server's cadence":         {fast, WatcherSettingsInput{IntervalSeconds: ptr(int32(599))}, false},
		"at a fast server's cadence":            {fast, WatcherSettingsInput{IntervalSeconds: ptr(int32(600))}, true},
		"zero":                                  {fast, WatcherSettingsInput{IntervalSeconds: ptr(int32(0))}, false},
		"negative":                              {fast, WatcherSettingsInput{IntervalSeconds: ptr(int32(-5))}, false},
		"one second past seven days":            {serverOn, WatcherSettingsInput{IntervalSeconds: ptr(int32(7*24*3600 + 1))}, false},
		"exactly seven days":                    {serverOn, WatcherSettingsInput{IntervalSeconds: ptr(int32(7 * 24 * 3600))}, true},
	} {
		t.Run(name, func(t *testing.T) {
			store := newWatcherStore()
			_, err := projectWatcherUsecase(auth.RoleAdmin, tc.settings, store).UpdateProjectWatcher(admin, "payments", tc.in)
			if tc.ok {
				assert.NoError(t, err)
				return
			}
			assert.ErrorIs(t, err, ErrInvalidWatcherSettings)
			assert.Zero(t, store.updateCalls, "a refused change writes nothing")
		})
	}
}

func TestUpdateProjectWatcher_RefusesBeforeLookingUpWhoIsAsking(t *testing.T) {
	// A bad request is a bad request for everyone, so it is reported whether or
	// not the caller may change the project.
	store := newWatcherStore()
	uc := projectWatcherUsecase(auth.RoleMember, serverOn, store)
	_, err := uc.UpdateProjectWatcher(sessionCtx("u1", auth.RoleViewer), "payments", WatcherSettingsInput{})
	assert.ErrorIs(t, err, ErrInvalidWatcherSettings)
}

func TestUpdateProjectWatcher_StoreFailureIsAnError(t *testing.T) {
	store := newWatcherStore()
	store.updateErr = errors.New("db down")
	_, err := projectWatcherUsecase(auth.RoleAdmin, serverOn, store).UpdateProjectWatcher(sessionCtx("u1", auth.RoleViewer), "payments", WatcherSettingsInput{Enabled: ptr(true)})
	require.Error(t, err)
	assert.NotErrorIs(t, err, ErrInvalidWatcherSettings)
}
