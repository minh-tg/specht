package usecase

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/port"
)

type evidenceURLStore struct {
	port.EvidenceStore
	writes []port.EvidenceInput
}

func (s *evidenceURLStore) Create(_ context.Context, in port.EvidenceInput) (port.Evidence, error) {
	s.writes = append(s.writes, in)
	return port.Evidence{URL: in.URL}, nil
}

func TestCreateEvidenceRequiresHTTPURL(t *testing.T) {
	for _, tc := range []struct {
		url string
		ok  bool
	}{
		{"https://example.test/log#result", true},
		{" http://example.test/log ", true},
		{"javascript:alert(1)", false},
		{"data:text/html,example", false},
		{"ftp://example.test/log", false},
		{"//example.test/log", false},
		{"https:///missing-host", false},
		{"https://", false},
		{"", false},
	} {
		t.Run(tc.url, func(t *testing.T) {
			f := makeFindingRow(1)
			store := &evidenceURLStore{}
			u := New(Deps{Stores: &port.Stores{Findings: &mockFindingRepo{getByIDFn: func(context.Context, string) (port.Finding, error) { return f, nil }}, Evidence: store}})
			_, err := u.CreateEvidence(adminCtx(), f.ID, "", "reference", tc.url, "test")
			if tc.ok {
				require.NoError(t, err)
				require.Len(t, store.writes, 1)
			} else {
				require.Error(t, err)
				require.Empty(t, store.writes)
			}
		})
	}
}
