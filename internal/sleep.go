package internal

import (
	"context"
	"time"
)

// SleepWithContext sleeps for the specified duration but returns early with an error if the context is cancelled.
func SleepWithContext(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
