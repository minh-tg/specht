package usecase

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/domain"
	"github.com/minh-tg/specht/internal/port"
	"github.com/minh-tg/specht/internal/scanner"
)

type keyedMockScanner struct{ mockScanner }

func (keyedMockScanner) UsesFingerprintKey() bool { return true }

// fakeInstanceSecrets stores the first value for each name, like the real store.
type fakeInstanceSecrets struct {
	mu     sync.Mutex
	calls  int
	values map[string][]byte
	err    error
}

func (f *fakeInstanceSecrets) Ensure(_ context.Context, name string, value []byte) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	if f.values == nil {
		f.values = map[string][]byte{}
	}
	if _, ok := f.values[name]; !ok {
		f.values[name] = append([]byte(nil), value...)
	}
	return f.values[name], nil
}

var errStopAfterParse = errors.New("stop after parse")

// ingestUsecase wires a usecase whose scanner records the key it was given and then stops, so the
// test needs no report or finding stores.
func ingestUsecase(t *testing.T, sc scanner.Scanner, secrets port.InstanceSecretStore) *Usecases {
	t.Helper()
	pr, _, _ := makeTestRepos()
	pr.getBySlugFn = func(context.Context, string) (port.Project, error) { return makeProject(true), nil }
	reg := scanner.NewRegistry()
	require.NoError(t, reg.Register(sc))
	return New(Deps{Stores: &port.Stores{Projects: pr, InstanceSecrets: secrets}, Registry: reg})
}

func ingestOnce(uc *Usecases, name string) error {
	_, err := uc.IngestReport(context.Background(), IngestReportInput{
		ProjectSlug: "my-app", Scanner: name, RawData: json.RawMessage(`{}`),
	})
	return err
}

func TestIngest_HandsTheInstanceKeyToAScannerThatHashesSecrets(t *testing.T) {
	var seen [][]byte
	sc := &keyedMockScanner{mockScanner{name: "keyed", parseFn: func(ctx context.Context, _ []byte) (*domain.NormalizedReport, error) {
		key, ok := scanner.FingerprintKey(ctx)
		require.True(t, ok, "the scanner receives a key")
		seen = append(seen, key)
		return nil, errStopAfterParse
	}}}
	secrets := &fakeInstanceSecrets{}
	uc := ingestUsecase(t, sc, secrets)

	require.ErrorIs(t, ingestOnce(uc, "keyed"), errStopAfterParse)
	require.ErrorIs(t, ingestOnce(uc, "keyed"), errStopAfterParse)

	require.Len(t, seen, 2)
	assert.Len(t, seen[0], 32, "a 256-bit key")
	assert.Equal(t, seen[0], seen[1], "the same key every time")
	assert.Equal(t, 1, secrets.calls, "the store is asked once, then the key is remembered")
}

func TestIngest_TheKeySurvivesARestart(t *testing.T) {
	var keys [][]byte
	newUsecase := func(secrets port.InstanceSecretStore) *Usecases {
		sc := &keyedMockScanner{mockScanner{name: "keyed", parseFn: func(ctx context.Context, _ []byte) (*domain.NormalizedReport, error) {
			key, _ := scanner.FingerprintKey(ctx)
			keys = append(keys, key)
			return nil, errStopAfterParse
		}}}
		return ingestUsecase(t, sc, secrets)
	}
	secrets := &fakeInstanceSecrets{} // the database, which outlives the process

	_ = ingestOnce(newUsecase(secrets), "keyed")
	_ = ingestOnce(newUsecase(secrets), "keyed") // a new process with the same database

	require.Len(t, keys, 2)
	require.NotEmpty(t, keys[0])
	assert.Equal(t, keys[0], keys[1], "a restart does not change what findings are called")
}

func TestIngest_OtherScannersGetNoKeyAndCostNoLookup(t *testing.T) {
	sc := &mockScanner{name: "plain", parseFn: func(ctx context.Context, _ []byte) (*domain.NormalizedReport, error) {
		_, ok := scanner.FingerprintKey(ctx)
		assert.False(t, ok)
		return nil, errStopAfterParse
	}}
	secrets := &fakeInstanceSecrets{}

	require.ErrorIs(t, ingestOnce(ingestUsecase(t, sc, secrets), "plain"), errStopAfterParse)
	assert.Zero(t, secrets.calls)
}

func TestIngest_StopsBeforeParsingWhenTheKeyCannotBeLoaded(t *testing.T) {
	parsed := false
	sc := &keyedMockScanner{mockScanner{name: "keyed", parseFn: func(context.Context, []byte) (*domain.NormalizedReport, error) {
		parsed = true
		return nil, errStopAfterParse
	}}}
	secrets := &fakeInstanceSecrets{err: errors.New("database down")}

	err := ingestOnce(ingestUsecase(t, sc, secrets), "keyed")

	require.Error(t, err)
	assert.NotErrorIs(t, err, errStopAfterParse)
	assert.Contains(t, err.Error(), "instance key")
	assert.False(t, parsed, "a scanner that needs a key is not run without one")
}

func TestIngest_AKeyThatIsTooShortIsRefused(t *testing.T) {
	sc := &keyedMockScanner{mockScanner{name: "keyed", parseFn: func(context.Context, []byte) (*domain.NormalizedReport, error) {
		return nil, errStopAfterParse
	}}}
	secrets := &fakeInstanceSecrets{values: map[string][]byte{"fingerprint-key": []byte("short")}}

	err := ingestOnce(ingestUsecase(t, sc, secrets), "keyed")

	require.Error(t, err)
	assert.NotErrorIs(t, err, errStopAfterParse)
}
