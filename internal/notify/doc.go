// Package notify plans issue-tracker and messaging actions as
// pure data: what work item or message a finding maps to, with a stable
// dedupe key so updates never duplicate tickets or lose state. Plans are
// preview-only — no live calls, no credentials. Publishing (delivery,
// retries, sync status) rides the existing tracker/webhook dispatch and
// stays out of this package.
package notify
