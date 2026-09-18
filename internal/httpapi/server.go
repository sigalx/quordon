package httpapi

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"net/url"
	"time"
	"unicode/utf8"

	"github.com/sigalx/quordon/internal/auth"
	"github.com/sigalx/quordon/internal/queryservice"
	"github.com/sigalx/quordon/internal/queryspec"
)

type Server struct {
	authenticator *auth.Basic
	service       *queryservice.Service
	logger        *slog.Logger
	handler       http.Handler
}

type apiError struct {
	Code          string `json:"code"`
	Message       string `json:"message"`
	RequestID     string `json:"request_id"`
	PolicyVersion string `json:"policy_version,omitempty"`
}

func New(authenticator *auth.Basic, service *queryservice.Service, logger *slog.Logger) *Server {
	server := &Server{authenticator: authenticator, service: service, logger: logger}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health/live", server.live)
	mux.HandleFunc("GET /health/ready", server.ready)
	mux.Handle("GET /capabilities", server.requireAuth(http.HandlerFunc(server.capabilities)))
	mux.Handle(
		"/query-shapes",
		server.varyAccept(server.noStore(exactMethod(http.MethodGet, server.requireAuth(http.HandlerFunc(server.queryShapes))))),
	)
	mux.Handle("GET /schemas/{schema}/objects", server.requireAuth(http.HandlerFunc(server.listObjects)))
	mux.Handle(
		"/schemas/{schema}/objects/{object}/statistics",
		server.noStore(exactStatisticsMethod(server.requireAuth(http.HandlerFunc(server.describeObjectStatistics)))),
	)
	mux.Handle("GET /schemas/{schema}/objects/{object}", server.requireAuth(http.HandlerFunc(server.describeObject)))
	mux.Handle("POST /queries/explain", server.requireAuth(http.HandlerFunc(server.explain)))
	mux.Handle(
		"/queries/select",
		server.noStore(exactMethod(http.MethodPost, server.requireAuth(http.HandlerFunc(server.selectQuery)))),
	)
	mux.Handle("POST /queries/aggregate", server.requireAuth(http.HandlerFunc(server.aggregateQuery)))
	mux.HandleFunc("/", server.notFound)
	server.handler = server.withRequestID(server.recoverPanic(mux))
	return server
}

func (s *Server) Handler() http.Handler { return s.handler }

func (s *Server) live(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) ready(w http.ResponseWriter, r *http.Request) {
	if !s.authenticator.Ready() || s.service.Ready(r.Context()) != nil {
		s.writeError(w, r, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", "Service is not ready")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) capabilities(w http.ResponseWriter, r *http.Request) {
	client := principalFromContext(r.Context())
	writeJSON(w, http.StatusOK, s.service.Capabilities(client.principal))
}

func (s *Server) queryShapes(w http.ResponseWriter, r *http.Request) {
	mediaType, ok := queryShapesMediaType(r)
	if !ok {
		s.writeError(w, r, http.StatusBadRequest, "INVALID_REQUEST", "Accept must select a supported query-shape representation")
		return
	}
	profile, ok := s.profileRequest(w, r)
	if !ok {
		return
	}
	client := principalFromContext(r.Context())
	payload, err := s.service.ListQueryShapes(
		r.Context(), requestID(r), client.principal, client.clientIdentifier, profile,
	)
	if err != nil {
		s.writeServiceError(w, r, err)
		return
	}
	writeJSONPayloadMedia(w, http.StatusOK, mediaType, payload)
}

func queryShapesMediaType(r *http.Request) (string, bool) {
	values := r.Header.Values("Accept")
	if len(values) == 0 {
		return "application/json", true
	}
	if len(values) != 1 {
		return "", false
	}
	switch values[0] {
	case "application/json", "*/*":
		return "application/json", true
	default:
		return "", false
	}
}

func (s *Server) explain(w http.ResponseWriter, r *http.Request) {
	request, bodyBytes, ok := s.readQueryRequest(w, r, false)
	if !ok {
		return
	}
	client := principalFromContext(r.Context())
	result, err := s.service.Explain(
		r.Context(), requestID(r), newID("q"), client.principal, client.clientIdentifier, bodyBytes, request,
	)
	if err != nil {
		s.writeServiceError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) selectQuery(w http.ResponseWriter, r *http.Request) {
	request, bodyBytes, ok := s.readSelectRequest(w, r)
	if !ok {
		return
	}
	client := principalFromContext(r.Context())
	queryID := newID("q")
	if legacy, legacyOK := request.Legacy(); legacyOK {
		result, err := s.service.Select(
			r.Context(), requestID(r), queryID, client.principal, client.clientIdentifier, bodyBytes, legacy,
		)
		if err != nil {
			s.writeServiceError(w, r, err)
			return
		}
		writeJSON(w, http.StatusOK, result)
		return
	}
	keyset, keysetOK := request.Keyset()
	if !keysetOK {
		s.writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "The request could not be completed")
		return
	}
	result, err := s.service.SelectKeyset(
		r.Context(), requestID(r), queryID, client.principal, client.clientIdentifier, bodyBytes, keyset,
	)
	if err != nil {
		s.writeServiceError(w, r, err)
		return
	}
	writeJSONPayload(w, http.StatusOK, result.EncodedJSON())
}

func (s *Server) readSelectRequest(
	w http.ResponseWriter, r *http.Request,
) (queryspec.SelectRequestVNext, int, bool) {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		s.writeError(w, r, http.StatusUnsupportedMediaType, "UNSUPPORTED_MEDIA_TYPE", "Content-Type must be application/json")
		return queryspec.SelectRequestVNext{}, 0, false
	}
	hardLimit := s.service.HardLimits().MaxRequestBytes
	body, err := io.ReadAll(io.LimitReader(r.Body, int64(hardLimit)+1))
	if err != nil {
		s.writeError(w, r, http.StatusBadRequest, "INVALID_REQUEST", "Request body could not be read")
		return queryspec.SelectRequestVNext{}, 0, false
	}
	if len(body) > hardLimit {
		s.writeError(w, r, http.StatusRequestEntityTooLarge, "REQUEST_TOO_LARGE", "Request body exceeds the configured limit")
		return queryspec.SelectRequestVNext{}, 0, false
	}
	hardLimits := s.service.HardLimits()
	request, err := queryspec.DecodeStrictSelectVNext(
		body, hardLimits.MaxExpressionDepth, hardLimits.MaxPredicates, hardLimits.MaxParameters,
	)
	if err != nil {
		s.writeError(w, r, http.StatusBadRequest, "INVALID_REQUEST", "Request body is not valid for this operation")
		return queryspec.SelectRequestVNext{}, 0, false
	}
	return request, len(body), true
}

func (s *Server) aggregateQuery(w http.ResponseWriter, r *http.Request) {
	request, bodyBytes, ok := s.readAggregateRequest(w, r)
	if !ok {
		return
	}
	client := principalFromContext(r.Context())
	result, err := s.service.Aggregate(
		r.Context(), requestID(r), newID("q"), client.principal, client.clientIdentifier, bodyBytes, request,
	)
	if err != nil {
		s.writeServiceError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) readAggregateRequest(
	w http.ResponseWriter, r *http.Request,
) (queryspec.AggregateRequest, int, bool) {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		s.writeError(w, r, http.StatusUnsupportedMediaType, "UNSUPPORTED_MEDIA_TYPE", "Content-Type must be application/json")
		return queryspec.AggregateRequest{}, 0, false
	}
	hardLimit := s.service.HardLimits().MaxRequestBytes
	body, err := io.ReadAll(io.LimitReader(r.Body, int64(hardLimit)+1))
	if err != nil {
		s.writeError(w, r, http.StatusBadRequest, "INVALID_REQUEST", "Request body could not be read")
		return queryspec.AggregateRequest{}, 0, false
	}
	if len(body) > hardLimit {
		s.writeError(w, r, http.StatusRequestEntityTooLarge, "REQUEST_TOO_LARGE", "Request body exceeds the configured limit")
		return queryspec.AggregateRequest{}, 0, false
	}
	hardLimits := s.service.HardLimits()
	request, err := queryspec.DecodeStrictAggregate(
		body, hardLimits.MaxExpressionDepth, hardLimits.MaxPredicates, hardLimits.MaxParameters,
	)
	if err != nil {
		s.writeError(w, r, http.StatusBadRequest, "INVALID_REQUEST", "Request body is not valid for this operation")
		return queryspec.AggregateRequest{}, 0, false
	}
	return request, len(body), true
}

func (s *Server) readQueryRequest(
	w http.ResponseWriter, r *http.Request, selectOnly bool,
) (queryspec.Request, int, bool) {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		s.writeError(w, r, http.StatusUnsupportedMediaType, "UNSUPPORTED_MEDIA_TYPE", "Content-Type must be application/json")
		return queryspec.Request{}, 0, false
	}
	hardLimit := s.service.HardLimits().MaxRequestBytes
	body, err := io.ReadAll(io.LimitReader(r.Body, int64(hardLimit)+1))
	if err != nil {
		s.writeError(w, r, http.StatusBadRequest, "INVALID_REQUEST", "Request body could not be read")
		return queryspec.Request{}, 0, false
	}
	if len(body) > hardLimit {
		s.writeError(w, r, http.StatusRequestEntityTooLarge, "REQUEST_TOO_LARGE", "Request body exceeds the configured limit")
		return queryspec.Request{}, 0, false
	}
	var request queryspec.Request
	if selectOnly {
		request, err = queryspec.DecodeStrictSelect(body, s.service.HardLimits().MaxExpressionDepth)
	} else {
		request, err = queryspec.DecodeStrict(body, s.service.HardLimits().MaxExpressionDepth)
	}
	if err != nil {
		s.writeError(w, r, http.StatusBadRequest, "INVALID_REQUEST", "Request body is not valid for this operation")
		return queryspec.Request{}, 0, false
	}
	return request, len(body), true
}

func (s *Server) listObjects(w http.ResponseWriter, r *http.Request) {
	profile, ok := s.schemaRequest(w, r)
	if !ok {
		return
	}
	client := principalFromContext(r.Context())
	result, err := s.service.ListObjects(
		r.Context(), requestID(r), client.principal, client.clientIdentifier,
		profile, r.PathValue("schema"),
	)
	if err != nil {
		s.writeServiceError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) describeObject(w http.ResponseWriter, r *http.Request) {
	profile, ok := s.schemaRequest(w, r)
	if !ok {
		return
	}
	object := r.PathValue("object")
	if !queryspec.IsIdentifier(object) {
		s.writeError(w, r, http.StatusBadRequest, "INVALID_REQUEST", "Object name is invalid")
		return
	}
	client := principalFromContext(r.Context())
	result, err := s.service.DescribeObject(
		r.Context(), requestID(r), client.principal, client.clientIdentifier, profile,
		queryspec.ResourceRef{Schema: r.PathValue("schema"), Name: object},
	)
	if err != nil {
		s.writeServiceError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) describeObjectStatistics(w http.ResponseWriter, r *http.Request) {
	if !s.requireEmptyRequestBody(w, r) {
		return
	}
	profile, ok := s.schemaRequest(w, r)
	if !ok {
		return
	}
	object := r.PathValue("object")
	if !queryspec.IsIdentifier(object) {
		s.writeError(w, r, http.StatusBadRequest, "INVALID_REQUEST", "The request is invalid")
		return
	}
	client := principalFromContext(r.Context())
	payload, err := s.service.DescribeObjectStatistics(
		r.Context(), requestID(r), client.principal, client.clientIdentifier, profile,
		queryspec.ResourceRef{Schema: r.PathValue("schema"), Name: object},
	)
	if err != nil {
		s.writeServiceError(w, r, err)
		return
	}
	writeJSONPayload(w, http.StatusOK, payload)
}

func (s *Server) requireEmptyRequestBody(w http.ResponseWriter, r *http.Request) bool {
	if len(r.TransferEncoding) != 0 || r.ContentLength > 0 {
		s.writeError(w, r, http.StatusBadRequest, "INVALID_REQUEST", "The request is invalid")
		return false
	}
	if r.Body == nil {
		return true
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1))
	if err != nil || len(body) != 0 {
		s.writeError(w, r, http.StatusBadRequest, "INVALID_REQUEST", "The request is invalid")
		return false
	}
	return true
}

func (s *Server) schemaRequest(w http.ResponseWriter, r *http.Request) (string, bool) {
	if !queryspec.IsIdentifier(r.PathValue("schema")) {
		s.writeError(w, r, http.StatusBadRequest, "INVALID_REQUEST", "Schema name is invalid")
		return "", false
	}
	return s.profileRequest(w, r)
}

func (s *Server) profileRequest(w http.ResponseWriter, r *http.Request) (string, bool) {
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		s.writeError(w, r, http.StatusBadRequest, "INVALID_REQUEST", "Query parameters are malformed")
		return "", false
	}
	profiles, ok := query["profile"]
	if !ok || len(profiles) != 1 || profiles[0] == "" || !utf8.ValidString(profiles[0]) || len(query) != 1 {
		s.writeError(w, r, http.StatusBadRequest, "INVALID_REQUEST", "Exactly one profile query parameter is required")
		return "", false
	}
	return profiles[0], true
}

func (s *Server) noStore(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) varyAccept(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Vary", "Accept")
		next.ServeHTTP(w, r)
	})
}

func exactMethod(method string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != method {
			w.Header().Set("Allow", method)
			w.Header().Set("X-Quordon-Error-Code", "METHOD_NOT_ALLOWED")
			writeJSONStatus(w, http.StatusMethodNotAllowed, apiError{
				Code:      "METHOD_NOT_ALLOWED",
				Message:   "HTTP method is not allowed for this endpoint",
				RequestID: requestID(r),
			})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func exactStatisticsMethod(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			if r.Method == http.MethodHead {
				w.Header().Set("X-Quordon-Error-Code", "METHOD_NOT_ALLOWED")
			}
			writeJSONStatus(w, http.StatusMethodNotAllowed, apiError{
				Code:      "METHOD_NOT_ALLOWED",
				Message:   "HTTP method is not allowed for this endpoint",
				RequestID: requestID(r),
			})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, present := r.BasicAuth()
		if !present {
			s.authenticationError(w, r, "AUTHENTICATION_REQUIRED")
			return
		}
		principal, err := s.authenticator.Authenticate(username, password)
		if errors.Is(err, auth.ErrUnavailable) {
			s.writeError(w, r, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", "Authentication dependency is unavailable")
			return
		}
		if err != nil {
			s.authenticationError(w, r, "INVALID_CREDENTIALS")
			return
		}
		next.ServeHTTP(w, r.WithContext(withPrincipal(
			r.Context(), principal.Name, principal.ClientIdentifier,
		)))
	})
}

func (s *Server) authenticationError(w http.ResponseWriter, r *http.Request, code string) {
	w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Basic realm=%q, charset="UTF-8"`, s.authenticator.Realm()))
	s.writeError(w, r, http.StatusUnauthorized, code, "Valid HTTP Basic credentials are required")
}

func (s *Server) writeServiceError(w http.ResponseWriter, r *http.Request, err error) {
	var serviceError *queryservice.Error
	if !errors.As(err, &serviceError) {
		s.logger.Error("unclassified request error", "request_id", requestID(r), "error", err)
		s.writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "The request could not be completed")
		return
	}
	switch serviceError.Kind {
	case queryservice.ErrorInvalid:
		s.writeError(w, r, http.StatusUnprocessableEntity, "UNSUPPORTED_QUERY", "The structured query is invalid or unsupported")
	case queryservice.ErrorDenied:
		s.writeError(w, r, http.StatusForbidden, serviceError.ReasonCode, "The operation is not allowed by policy")
	case queryservice.ErrorNotFound:
		s.writeError(w, r, http.StatusNotFound, "NOT_FOUND", "The requested resource was not found")
	case queryservice.ErrorTooLarge:
		s.writeError(w, r, http.StatusRequestEntityTooLarge, "REQUEST_TOO_LARGE", "Request body exceeds the configured limit")
	case queryservice.ErrorResultTooLarge:
		s.writeError(w, r, http.StatusRequestEntityTooLarge, "RESULT_TOO_LARGE", "Database result exceeds the configured limit")
	case queryservice.ErrorCapacity:
		s.writeError(w, r, http.StatusServiceUnavailable, "CAPACITY_EXCEEDED", "The service has reached its configured concurrency capacity")
	case queryservice.ErrorNotImplemented:
		s.writeError(w, r, http.StatusNotImplemented, "CAPABILITY_NOT_IMPLEMENTED", "The selected datasource adapter does not implement this capability")
	case queryservice.ErrorServiceUnavailable:
		s.writeError(w, r, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", "A required service dependency is unavailable")
	case queryservice.ErrorUnavailable:
		s.writeError(w, r, http.StatusServiceUnavailable, "DATABASE_UNAVAILABLE", "The database is unavailable")
	case queryservice.ErrorTimeout:
		s.writeError(w, r, http.StatusGatewayTimeout, "QUERY_TIMEOUT", "The query deadline was exceeded")
	case queryservice.ErrorUpstream:
		s.writeError(w, r, http.StatusBadGateway, "UPSTREAM_ERROR", "The database operation failed")
	default:
		s.writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "The request could not be completed")
	}
}

func (s *Server) writeError(w http.ResponseWriter, r *http.Request, status int, code, message string) {
	writeJSONStatus(w, status, apiError{
		Code: code, Message: message, RequestID: requestID(r), PolicyVersion: s.service.PolicyVersion(),
	})
}

func (s *Server) notFound(w http.ResponseWriter, r *http.Request) {
	s.writeError(w, r, http.StatusNotFound, "NOT_FOUND", "Endpoint not found")
}

func (s *Server) withRequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := newID("req")
		w.Header().Set("X-Request-ID", id)
		next.ServeHTTP(w, r.WithContext(withRequestID(r.Context(), id)))
	})
}

func (s *Server) recoverPanic(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if recovered := recover(); recovered != nil {
				s.logger.Error("panic while handling request", "request_id", requestID(r))
				s.writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "The request could not be completed")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, value any) { writeJSONStatus(w, status, value) }

func writeJSONStatus(w http.ResponseWriter, status int, value any) {
	payload, err := json.Marshal(value)
	if err != nil {
		panic(fmt.Errorf("marshal JSON response: %w", err))
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(payload)
}

func writeJSONPayload(w http.ResponseWriter, status int, payload []byte) {
	writeJSONPayloadMedia(w, status, "application/json", payload)
}

func writeJSONPayloadMedia(w http.ResponseWriter, status int, mediaType string, payload []byte) {
	if len(payload) == 0 || !json.Valid(payload) {
		panic("invalid prebuilt JSON response")
	}
	if mediaType == "" {
		panic("empty JSON response media type")
	}
	w.Header().Set("Content-Type", mediaType)
	w.WriteHeader(status)
	_, _ = w.Write(payload)
}

func newID(prefix string) string {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano())
	}
	return prefix + "-" + hex.EncodeToString(bytes)
}
