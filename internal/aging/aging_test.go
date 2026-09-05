package aging

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestSLADays_Table(t *testing.T) {
	assert.Equal(t, 7, SLADays(4))
	assert.Equal(t, 30, SLADays(3))
	assert.Equal(t, 90, SLADays(2))
	assert.Equal(t, 180, SLADays(1))
	assert.Equal(t, 90, SLADays(0))
	assert.Equal(t, 90, SLADays(99))
}

func TestBucket_Boundaries(t *testing.T) {
	assert.Equal(t, BucketNew, Bucket(0))
	assert.Equal(t, BucketNew, Bucket(6))
	assert.Equal(t, BucketAging, Bucket(7))
	assert.Equal(t, BucketAging, Bucket(29))
	assert.Equal(t, BucketStale, Bucket(30))
	assert.Equal(t, BucketStale, Bucket(89))
	assert.Equal(t, BucketDebt, Bucket(90))
	assert.Equal(t, BucketDebt, Bucket(900))
}

func TestClassify_OverdueEdges(t *testing.T) {
	now := time.Date(2026, 9, 5, 15, 4, 5, 0, time.FixedZone("X", -3*3600))
	// Critical SLA is 7 days: 6 days open is not overdue, 7 is.
	fresh := Classify(now.AddDate(0, 0, -6), now, 4, "open", false)
	assert.False(t, fresh.Overdue)
	assert.Equal(t, 6, fresh.AgeDays)
	assert.Equal(t, BucketNew, fresh.Bucket)
	due := Classify(now.AddDate(0, 0, -7), now, 4, "open", false)
	assert.True(t, due.Overdue)
	assert.Equal(t, BucketAging, due.Bucket)
}

func TestClassify_ClosedStatesNeverOverdue(t *testing.T) {
	now := time.Now()
	for _, state := range []string{"resolved", "muted", "closed", "accepted_risk"} {
		c := Classify(now.AddDate(0, 0, -400), now, 4, state, false)
		assert.False(t, c.Overdue, state)
		assert.Equal(t, BucketDebt, c.Bucket)
	}
}

func TestClassify_TimezoneSafe(t *testing.T) {
	east := time.FixedZone("E", 14*3600)
	west := time.FixedZone("W", -11*3600)
	seen := time.Date(2026, 8, 1, 23, 0, 0, 0, time.UTC)
	instant := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	assert.Equal(t,
		Classify(seen, instant.In(east), 3, "open", false).AgeDays,
		Classify(seen, instant.In(west), 3, "open", false).AgeDays)
}

func TestClassify_NegativeAgeClamps(t *testing.T) {
	now := time.Now()
	c := Classify(now.Add(time.Hour), now, 3, "open", false)
	assert.Equal(t, 0, c.AgeDays)
	assert.False(t, c.Overdue)
}
