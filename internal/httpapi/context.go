package httpapi

import "context"

type requestIDKey struct{}
type principalKey struct{}

type authenticatedClient struct {
	principal        string
	clientIdentifier string
}

func withRequestID(ctx context.Context, value string) context.Context {
	return context.WithValue(ctx, requestIDKey{}, value)
}

func requestIDFromContext(ctx context.Context) string {
	value, _ := ctx.Value(requestIDKey{}).(string)
	return value
}

func requestID(request interface{ Context() context.Context }) string {
	return requestIDFromContext(request.Context())
}

func withPrincipal(ctx context.Context, principal, clientIdentifier string) context.Context {
	return context.WithValue(ctx, principalKey{}, authenticatedClient{
		principal: principal, clientIdentifier: clientIdentifier,
	})
}

func principalFromContext(ctx context.Context) authenticatedClient {
	value, _ := ctx.Value(principalKey{}).(authenticatedClient)
	return value
}
