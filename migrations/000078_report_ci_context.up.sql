-- Where a report came from, so the change view can link back to the pull
-- request, the CI run and the file at the scanned commit. All four are display
-- only and optional: nothing in scope, closing or the gate reads them.
--
-- The URLs must be http(s) and carry no user info, so a GitLab
-- CI_REPOSITORY_URL with its job token can never be stored. The API checks the
-- same rules first and answers 400; these constraints are the backstop.
ALTER TABLE reports
    ADD COLUMN repository_url TEXT
        CONSTRAINT reports_repository_url_check
        CHECK (repository_url ~ '^https?://[^/@[:space:]]+(/[^[:space:]]*)?$' AND length(repository_url) <= 2048),
    ADD COLUMN pull_request_number INTEGER
        CONSTRAINT reports_pull_request_number_check CHECK (pull_request_number > 0),
    ADD COLUMN pull_request_title TEXT
        CONSTRAINT reports_pull_request_title_check CHECK (length(pull_request_title) <= 512),
    ADD COLUMN ci_run_url TEXT
        CONSTRAINT reports_ci_run_url_check
        CHECK (ci_run_url ~ '^https?://[^/@[:space:]]+(/[^[:space:]]*)?$' AND length(ci_run_url) <= 2048);
