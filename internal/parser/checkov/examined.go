package checkov

import (
	"encoding/json"

	"github.com/minh-tg/specht/internal/domain"
	"github.com/minh-tg/specht/internal/parser/parseutil"
)

// passedCheckKeys turns the passed checks of one framework report into
// examination keys. A passed check for a check id, resource and file is the
// scanner saying that check ran and the resource is fine, which is positive
// proof a failed finding with the same fingerprint is fixed. Checkov writes
// passed_checks unless it ran with --quiet; without them the report proves
// nothing, and so does a check that was skipped. A passed check that does not
// decode proves nothing either.
func passedCheckKeys(report checkovReport) []string {
	if report.Results == nil {
		return nil
	}
	keys := make([]string, 0, len(report.Results.PassedChecks))
	for _, raw := range report.Results.PassedChecks {
		var check checkovFinding
		if json.Unmarshal(raw, &check) != nil || check.CheckID == "" {
			continue
		}
		// Built the way a failed check is, so both agree on the fingerprint.
		fp := parseutil.HardenFinding(convertCheck(check, report.CheckType)).Fingerprint
		keys = append(keys, domain.ExaminedFingerprint(fp))
	}
	return keys
}
