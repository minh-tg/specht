package sqlc

import (
	"strings"
	"testing"
)

// ClaimExpiringWaivers warns about a waiver only while expiry_warned_at is NULL.
// UpdateWaiver must clear it when the expiry moves, or a waiver extended after
// its warning ends without a second one. Writing the same expiry keeps it.
func TestUpdateWaiverClearsTheExpiryWarningOnANewExpiry(t *testing.T) {
	query := strings.Join(strings.Fields(updateWaiver), " ")
	want := "expiry_warned_at = CASE WHEN $5::boolean AND expires_at IS DISTINCT FROM $6::timestamptz" +
		" THEN NULL ELSE expiry_warned_at END"
	if !strings.Contains(query, want) {
		t.Fatalf("UpdateWaiver does not clear expiry_warned_at on a new expiry:\n%s", updateWaiver)
	}
}
