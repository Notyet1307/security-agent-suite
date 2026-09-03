package httpapi

import "context"

type contextKey string

const (
	requestIDKey contextKey = "request_id"
	tenantIDKey  contextKey = "tenant_id"
)

func requestIDFromContext(ctx context.Context) string {
	value, _ := ctx.Value(requestIDKey).(string)
	return value
}

func tenantIDFromContext(ctx context.Context) string {
	value, _ := ctx.Value(tenantIDKey).(string)
	return value
}
