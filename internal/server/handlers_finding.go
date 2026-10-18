package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/minh-tg/specht/internal/audit"
	"github.com/minh-tg/specht/internal/auth"
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
// read, a report with too many findings, a report nested deeper than the cap,
// and an unknown scanner each say what to do next. Anything else stays generic
// so parser and store internals never reach the response.
func ingestFailure(scannerName string, err error) (code, message string) {
	var unrecognized *scanner.UnrecognizedFormatError
	var tooMany *scanner.TooManyFindingsError
	switch {
	case errors.As(err, &unrecognized):
		return "unrecognized_format", unrecognizedMessage(unrecognized)
	case errors.As(err, &tooMany):
		if tooMany.Depth {
			return "too_many_findings", fmt.Sprintf("The %s report nests deeper than %d levels, the most this instance accepts. Split it into smaller reports and ingest each.", scannerName, tooMany.Limit)
		}
		return "too_many_findings", fmt.Sprintf("The %s report has more than %d findings, the most one report may hold. Split it into smaller reports (for example one per module or directory) and ingest each.", scannerName, tooMany.Limit)
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

// IngestReport takes a report in four steps, so that a caller pays for each
// only after passing the one before:
//
//  1. Authorize. Only the head of the body is read, to find the project; the
//     caller is checked against it before anything is held. A caller with no
//     access gets a 403 and costs a few KiB of reading, nothing else.
//  2. Enter the caller's own gate and read the rest of the body. Each caller
//     (user or API key) has a few places, so a slow or numerous caller fills
//     its own queue and nobody else's.
//  3. Admit: with the whole body in memory, take a share of the caller's and
//     the project's memory allowance, a global slot and the global memory
//     charge. A project holds at most half the slots whoever calls for it. A
//     slow upload never holds these.
//  4. Decode and ingest, on a context a hang-up cannot cancel.
func (h *Handler) IngestReport(w http.ResponseWriter, r *http.Request) {
	adm := h.ingestAdmission()
	deadlines := ingestDeadlines{body: ingestBodyWindow, window: ingestWindow, writeSlack: ingestWriteSlack}
	deadlines.armBody(w)
	if r.Body == nil {
		respondError(w, http.StatusBadRequest, "invalid_json", "invalid request body")
		return
	}
	if r.ContentLength > maxIngestBodyBytes {
		respondError(w, http.StatusRequestEntityTooLarge, "body_too_large", "request body too large")
		return
	}
	body := http.MaxBytesReader(w, r.Body, maxIngestBodyBytes)

	project, rest, err := scanIngestProject(body, ingestHeadBytes)
	if err != nil {
		h.respondIngestBodyError(w, err, "invalid_json", "invalid request body")
		return
	}
	if project == "" {
		respondError(w, http.StatusBadRequest, "missing_field", "project is required")
		return
	}
	if problem := textProblem(project, maxTextFieldBytes); problem != "" {
		respondError(w, http.StatusBadRequest, "invalid_field", "project "+problem)
		return
	}
	tenant, err := h.authorizeIngest(r, project)
	if err != nil {
		h.respondIngestAuthError(w, r, project, err)
		return
	}
	if tenant == "" {
		tenant = project
	}

	ident := auth.ContextIdentity(r.Context())
	ticket, err := adm.enter(r.Context(), principalKey(ident), tenant)
	if err != nil {
		if errors.Is(err, errIngestBusy) {
			respondIngestBusy(w, adm.queueWait)
		}
		return
	}
	defer ticket.release()

	deadlines.armBody(w)
	data, err := io.ReadAll(rest)
	if err != nil {
		h.respondIngestBodyError(w, err, "invalid_json", "invalid request body")
		return
	}
	if err := ticket.admit(r.Context(), len(data)); err != nil {
		if errors.Is(err, errIngestBusy) {
			respondIngestBusy(w, adm.queueWait)
		}
		return
	}
	deadlines.armProcessing(w)

	var req ingestRequest
	if err := json.Unmarshal(data, &req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid_json", "invalid request body")
		return
	}
	if req.Project != project {
		respondError(w, http.StatusBadRequest, "invalid_field", "project must be named once, or with the same value each time")
		return
	}
	if req.Scanner == "" {
		respondError(w, http.StatusBadRequest, "missing_field", "scanner is required")
		return
	}
	if field, problem := req.invalidField(); field != "" {
		respondError(w, http.StatusBadRequest, "invalid_field", field+" "+problem)
		return
	}
	if len(req.RawData) == 0 {
		respondError(w, http.StatusBadRequest, "missing_field", "raw_data is required")
		return
	}

	var gateSeverity, gateStatus []string
	if req.GateSeverity != "" {
		gateSeverity = strings.Split(req.GateSeverity, ",")
	}
	if req.GateStatus != "" {
		gateStatus = strings.Split(req.GateStatus, ",")
	}

	// The write phase runs on a context a hang-up cannot cancel (see
	// detachedContext), so the report ends completed or failed, never half
	// written. Waiting for memory above still stops when the client leaves.
	ingestCtx, cancelIngest := detachedContext(r.Context())
	defer cancelIngest()
	result, err := h.usecase.IngestReport(ingestCtx, usecase.IngestReportInput{
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

// authorizeIngest checks, from the project slug alone, that the caller may
// ingest into the project: membership or key match first (the same check every
// project route makes), then the role or scope that allows ingest.
func (h *Handler) authorizeIngest(r *http.Request, project string) (string, error) {
	projectID, err := h.projectAccess(r, project)
	if err != nil {
		return "", err
	}
	return projectID, h.usecase.AuthorizeIngest(r.Context(), project)
}

// respondIngestAuthError answers a caller refused before its body was read.
func (h *Handler) respondIngestAuthError(w http.ResponseWriter, r *http.Request, project string, err error) {
	if errors.Is(err, usecase.ErrProjectAccessDenied) {
		respondError(w, http.StatusForbidden, "project_access_denied", "project role cannot ingest reports")
		h.audit.HTTP(r, audit.EventIngestReport, audit.OutcomeFailure, project, "", err)
		return
	}
	h.respondProjectAccessError(w, r, err)
}

// respondIngestBodyError answers a failure to read the body. A caller that went
// away gets no answer.
func (h *Handler) respondIngestBodyError(w http.ResponseWriter, err error, invalidCode, invalidMsg string) {
	var tooLarge *http.MaxBytesError
	var syntax *json.SyntaxError
	var typed *json.UnmarshalTypeError
	switch {
	case errors.As(err, &tooLarge):
		respondError(w, http.StatusRequestEntityTooLarge, "body_too_large", "request body too large")
	case errors.Is(err, errProjectNotInHead):
		respondError(w, http.StatusBadRequest, "missing_field", fmt.Sprintf("project must be named in the first %d bytes of the body, before raw_data", ingestHeadBytes))
	case errors.As(err, &syntax), errors.As(err, &typed), errors.Is(err, errNotAnObject), errors.Is(err, io.ErrUnexpectedEOF):
		respondError(w, http.StatusBadRequest, invalidCode, invalidMsg)
	case errors.Is(err, os.ErrDeadlineExceeded):
		respondError(w, http.StatusRequestTimeout, "request_timeout", "the request body did not arrive in time")
	}
}
