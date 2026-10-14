// Package reqctx carries per-request facts in a context: the request id that
// ties a response header to its log lines, and the moment the request began.
// It sits below both the HTTP layer and the audit logger so neither imports the
// other.
package reqctx

import (
	"context"
	"time"
)

type key int

const (
	idKey key = iota
	startKey
)

// With returns a context that carries the request id and start time.
func With(ctx context.Context, id string, start time.Time) context.Context {
	ctx = context.WithValue(ctx, idKey, id)
	return context.WithValue(ctx, startKey, start)
}

// ID returns the request id, or "" outside a request.
func ID(ctx context.Context) string {
	id, _ := ctx.Value(idKey).(string)
	return id
}

// Start returns when the request began, or the zero time outside a request.
func Start(ctx context.Context) time.Time {
	t, _ := ctx.Value(startKey).(time.Time)
	return t
}
