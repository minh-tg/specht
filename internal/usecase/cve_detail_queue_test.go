package usecase

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/cvedetail"
)

func TestGetFindingCVE_LookupCarriesTheProjectAsOwner(t *testing.T) {
	resolver := &fakeResolver{names: []string{"nvd"}, answer: []cvedetail.ProviderLookup{{Name: "nvd", Status: cvedetail.LookupPending}}}
	uc := newCVETestUsecases(testCVEID, nil, resolver, nil)
	_, err := uc.GetFindingCVE(memberSessionCtx(), cveTestFindingID)
	require.NoError(t, err)
	assert.Equal(t, []string{makeFindingRow(1).ProjectID}, resolver.owners)
}

func TestGetFindingCVE_DroppedFetchIsNotPending(t *testing.T) {
	resolver := &fakeResolver{names: []string{"nvd"}, answer: []cvedetail.ProviderLookup{{Name: "nvd", Status: cvedetail.LookupError}}}
	uc := newCVETestUsecases(testCVEID, nil, resolver, nil)
	resp, err := uc.GetFindingCVE(memberSessionCtx(), cveTestFindingID)
	require.NoError(t, err)
	assert.False(t, resp.Pending)
	require.NotEmpty(t, resp.Providers)
	assert.Equal(t, cvedetail.LookupError, resp.Providers[0].Status)
}
