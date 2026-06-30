package server

import (
	"encoding/json"
	"log"
	"log/slog"
	"net/http"

	"github.com/vulnserve/vulnserve/internal/auth"
	"github.com/vulnserve/vulnserve/internal/usecase"
)

func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ident := &auth.Identity{UserID: "anonymous"}
		ctx := auth.ContextWithIdentity(r.Context(), ident)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func LoggerMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		slog.Info("request",
			"method", r.Method,
			"path", r.URL.Path,
			"remote", r.RemoteAddr,
		)
		next.ServeHTTP(w, r)
	})
}

type Handler struct {
	uc *usecase.Usecases
}

func NewHandler(uc *usecase.Usecases) *Handler {
	return &Handler{uc: uc}
}

type ingestRequest struct {
	Project       string          `json:"project"`
	Scanner       string          `json:"scanner"`
	ScannerVersion string         `json:"scanner_version,omitempty"`
	ParserVersion  string         `json:"parser_version,omitempty"`
	RawData       json.RawMessage `json:"raw_data"`
	Branch        string          `json:"branch,omitempty"`
	CommitSha     string          `json:"commit_sha,omitempty"`
}

type ingestResponse struct {
	ReportID      string `json:"report_id"`
	TotalFindings int    `json:"total_findings"`
}

type apiError struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func respondJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("encode response: %v", err)
	}
}

func respondError(w http.ResponseWriter, status int, code, message string) {
	var e apiError
	e.Error.Code = code
	e.Error.Message = message
	respondJSON(w, status, e)
}

func (h *Handler) IngestReport(w http.ResponseWriter, r *http.Request) {
	var req ingestRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid_json", "invalid request body")
		return
	}

	if req.Project == "" {
		respondError(w, http.StatusBadRequest, "missing_field", "project is required")
		return
	}
	if req.Scanner == "" {
		respondError(w, http.StatusBadRequest, "missing_field", "scanner is required")
		return
	}
	if len(req.RawData) == 0 {
		respondError(w, http.StatusBadRequest, "missing_field", "raw_data is required")
		return
	}

	result, err := h.uc.IngestReport(r.Context(), usecase.IngestReportInput{
		ProjectSlug:    req.Project,
		Scanner:        req.Scanner,
		ScannerVersion: req.ScannerVersion,
		ParserVersion:  req.ParserVersion,
		RawData:        req.RawData,
		Branch:         req.Branch,
		CommitSha:      req.CommitSha,
	})
	if err != nil {
		log.Printf("ingest report: %v", err)
		respondError(w, http.StatusUnprocessableEntity, "ingest_failed", err.Error())
		return
	}

	respondJSON(w, http.StatusCreated, ingestResponse{
		ReportID:      result.ReportID,
		TotalFindings: result.TotalFindings,
	})
}
