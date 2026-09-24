# Tikti production hotfix guide

This worktree is based on the exact Go source embedded in the production Tikti image, commit `941a0d17f889f0f03901ace525f92e98949f3aac`. Keep company-admin authority tied to the active company's persisted `adminUserId`; the current upstream main has a different runtime and must not be substituted into the production wrapper without a separate migration.

Run `go test ./...` and `go vet ./...`. The private `/v1/internal/passwords/temporary` route requires `PASSWORD_RESET_SERVICE_KEY` and must remain outside the public ingress. The public `/v1/accounts/changeTemporaryPassword` route verifies the provisional password before allowing replacement. Do not log passwords, service keys, or identity tokens.
