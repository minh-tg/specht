package lifecycle

import (
	"context"
	"testing"
	"time"
)

func TestRunAnalysisExpiryRejectsNonPositiveInterval(t *testing.T) {
	for _, interval := range []time.Duration{0, -time.Second} {
		t.Run(interval.String(), func(t *testing.T) {
			err := RunAnalysisExpiry(context.Background(), nil, interval, nil)
			if err == nil {
				t.Fatalf("expected error for interval %s", interval)
			}
		})
	}
}

func TestRunWaiverExpiryRejectsNonPositiveInterval(t *testing.T) {
	for _, interval := range []time.Duration{0, -time.Second} {
		t.Run(interval.String(), func(t *testing.T) {
			err := RunWaiverExpiry(context.Background(), nil, interval, nil)
			if err == nil {
				t.Fatalf("expected error for interval %s", interval)
			}
		})
	}
}
