package server

import (
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/minh-tg/specht/internal/audit"
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
			respondError(w, http.StatusForbidden, "project_access_denied", "API key does not have access to this finding")
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
		respondError(w, http.StatusUnprocessableEntity, "ingest_failed", "report ingestion failed")
		h.audit.HTTP(r, audit.EventIngestReport, audit.OutcomeFailure, req.Project, req.Scanner, err)
		return
	}
	h.audit.HTTP(r, audit.EventIngestReport, audit.OutcomeSuccess, req.Project, req.Scanner, nil)
	respondJSON(w, http.StatusCreated, ingestResponse{
		ReportID:          result.ReportID,
		TotalFindings:     result.TotalFindings,
		ThresholdBreached: result.ThresholdBreached,
		ScanMode:          result.ScanMode,
		FallbackReason:    result.FallbackReason,
		IntroducedCount:   result.IntroducedCount,
		PreExistingCount:  result.PreExistingCount,
	})
}
