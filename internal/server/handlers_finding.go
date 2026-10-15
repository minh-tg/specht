package server

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/minh-tg/specht/internal/audit"
	"github.com/minh-tg/specht/internal/scanner"
	"github.com/minh-tg/specht/internal/usecase"
)

func (h *Handler) GetFinding(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		respondError(w, http.StatusBadRequest, "missing_id", "finding id is required")
		h.audit.HTTP(r, audit.EventGetFinding, audit.OutcomeFailure, "", id, nil)
		return
	}
	finding, err := h.usecase.GetFinding(r.Context(), id)
	if err != nil {
		if errors.Is(err, usecase.ErrProjectAccessDenied) {
			respondAccessDenied(w, r, "finding")
			h.audit.HTTP(r, audit.EventGetFinding, audit.OutcomeFailure, "", id, err)
		} else if _, parseErr := uuid.Parse(id); parseErr != nil {
			respondError(w, http.StatusBadRequest, "invalid_id", "invalid finding id format")
			h.audit.HTTP(r, audit.EventGetFinding, audit.OutcomeFailure, "", id, err)
		} else {
			respondError(w, http.StatusNotFound, "not_found", "finding not found")
			h.audit.HTTP(r, audit.EventGetFinding, audit.OutcomeFailure, "", id, err)
		}
		return
	}
	h.audit.HTTP(r, audit.EventGetFinding, audit.OutcomeSuccess, "", id, nil)
	respondJSON(w, http.StatusOK, finding)
}

// ingestFailure turns an ingest error into the code and message the caller
// sees. A file that is not the chosen scanner's output, a report that cannot be
// read, and an unknown scanner each say what to do next. Anything else stays
// generic so parser and store internals never reach the response.
func ingestFailure(scannerName string, err error) (code, message string) {
	var unrecognized *scanner.UnrecognizedFormatError
	switch {
	case errors.As(err, &unrecognized):
		return "unrecognized_format", unrecognizedMessage(unrecognized)
	case errors.Is(err, scanner.ErrMalformedReport):
		return "malformed_report", fmt.Sprintf("The %s report could not be read. Check that the file is complete and came from a current version of the tool.", scannerName)
	case errors.Is(err, usecase.ErrUnknownScanner):
		return "unknown_scanner", fmt.Sprintf("The scanner %q is not supported. List the supported scanners with GET /api/v1/scanners.", scannerName)
	default:
		return "ingest_failed", "report ingestion failed"
	}
}

func unrecognizedMessage(e *scanner.UnrecognizedFormatError) string {
	switch len(e.LooksLike) {
	case 0:
		return fmt.Sprintf("The file is not %s output. Check that you chose the scanner that wrote it.", e.Scanner)
	case 1:
		return fmt.Sprintf("The file is not %s output. It looks like %s output; choose %s as the scanner.", e.Scanner, e.LooksLike[0], e.LooksLike[0])
	default:
		return fmt.Sprintf("The file is not %s output. It looks like %s output; choose the one that wrote it.", e.Scanner, strings.Join(e.LooksLike, " or "))
	}
}

func (h *Handler) IngestReport(w http.ResponseWriter, r *http.Request) {
	var req ingestRequest
	if !decodeJSONBody(w, r, &req, maxIngestBodyBytes, "invalid_json", "invalid request body") {
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
	if err := h.enforceProjectAccess(r, req.Project); err != nil {
		h.respondProjectAccessError(w, r, err)
		return
	}

	var gateSeverity, gateStatus []string
	if req.GateSeverity != "" {
		gateSeverity = strings.Split(req.GateSeverity, ",")
	}
	if req.GateStatus != "" {
		gateStatus = strings.Split(req.GateStatus, ",")
	}

	result, err := h.usecase.IngestReport(r.Context(), usecase.IngestReportInput{
		ProjectSlug:        req.Project,
		Scanner:            req.Scanner,
		ScannerVersion:     req.ScannerVersion,
		ParserVersion:      req.ParserVersion,
		RawData:            req.RawData,
		Branch:             req.Branch,
		CommitSha:          req.CommitSha,
		BaseRevision:       req.BaseRevision,
		ChangedFiles:       req.ChangedFiles,
		ScanMode:           req.ScanMode,
		GateIntroducedOnly: req.GateIntroducedOnly,
		GateSeverity:       gateSeverity,
		GateStatus:         gateStatus,
		Environment:        req.Environment,
		Owner:              req.Owner,
		Digest:             req.Digest,
		ArtifactName:       req.ArtifactName,
		ArtifactVersion:    req.ArtifactVersion,
		ArtifactType:       req.ArtifactType,
	})
	if err != nil {
		if errors.Is(err, usecase.ErrProjectAccessDenied) {
			respondError(w, http.StatusForbidden, "project_access_denied", "project role cannot ingest reports")
			h.audit.HTTP(r, audit.EventIngestReport, audit.OutcomeFailure, req.Project, req.Scanner, err)
			return
		}
		slog.Error("ingest report", "error", err)
		if errors.Is(err, usecase.ErrDuplicateReport) {
			respondError(w, http.StatusConflict, "duplicate_report", "report already exists for this project and data")
			h.audit.HTTP(r, audit.EventIngestReport, audit.OutcomeFailure, req.Project, req.Scanner, err)
			return
		}
		code, message := ingestFailure(req.Scanner, err)
		respondError(w, http.StatusUnprocessableEntity, code, message)
		h.audit.HTTP(r, audit.EventIngestReport, audit.OutcomeFailure, req.Project, req.Scanner, err)
		return
	}
	h.audit.HTTP(r, audit.EventIngestReport, audit.OutcomeSuccess, req.Project, req.Scanner, nil)
	status := http.StatusCreated
	if result.Replayed {
		status = http.StatusOK
	}
	respondJSON(w, status, ingestResponse{
		ReportID:          result.ReportID,
		TotalFindings:     result.TotalFindings,
		ThresholdBreached: result.ThresholdBreached,
		ScanMode:          result.ScanMode,
		FallbackReason:    result.FallbackReason,
		IntroducedCount:   result.IntroducedCount,
		PreExistingCount:  result.PreExistingCount,
		Replayed:          result.Replayed,
	})
}
