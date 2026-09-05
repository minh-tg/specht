package server

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/xMinhx/specht/internal/usecase"
)

func (h *Handler) GetFinding(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		respondError(w, http.StatusBadRequest, "missing_id", "finding id is required")
		return
	}

	finding, err := h.usecase.GetFinding(r.Context(), id)
	if err != nil {
		if errors.Is(err, usecase.ErrProjectAccessDenied) {
			respondError(w, http.StatusForbidden, "project_access_denied", "API key does not have access to this finding")
		} else if _, parseErr := uuid.Parse(id); parseErr != nil {
			respondError(w, http.StatusBadRequest, "invalid_id", "invalid finding id format")
		} else {
			respondError(w, http.StatusNotFound, "not_found", "finding not found")
		}
		return
	}

	respondJSON(w, http.StatusOK, finding)
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
	if err := h.enforceProjectAccess(r, req.Project); err != nil {
		respondError(w, http.StatusForbidden, "project_access_denied", "API key does not have access to this project")
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
		ProjectSlug:     req.Project,
		Scanner:         req.Scanner,
		ScannerVersion:  req.ScannerVersion,
		ParserVersion:   req.ParserVersion,
		RawData:         req.RawData,
		Branch:          req.Branch,
		CommitSha:       req.CommitSha,
		GateSeverity:    gateSeverity,
		GateStatus:      gateStatus,
		Environment:     req.Environment,
		Owner:           req.Owner,
		Digest:          req.Digest,
		ArtifactName:    req.ArtifactName,
		ArtifactVersion: req.ArtifactVersion,
		ArtifactType:    req.ArtifactType,
	})
	if err != nil {
		log.Printf("ingest report: %v", err)
		if errors.Is(err, usecase.ErrDuplicateReport) {
			respondError(w, http.StatusConflict, "duplicate_report", "report already exists for this project and data")
			return
		}
		respondError(w, http.StatusUnprocessableEntity, "ingest_failed", err.Error())
		return
	}

	respondJSON(w, http.StatusCreated, ingestResponse{
		ReportID:          result.ReportID,
		TotalFindings:     result.TotalFindings,
		ThresholdBreached: result.ThresholdBreached,
	})
}
