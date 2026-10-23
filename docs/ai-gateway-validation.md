# CFP-116 validation record

Local source validation on 2026-10-23; no push, deployment or production calls.
Branch: integration/workload-stabilization. Base: e62a3d7.

The default-off audience test failed before implementation because all three
reserved audience variants entered legacy exchange. It passes with the closed
AI dispatch. New identity protocol tests initially failed on missing implementation
and then passed. Current user version/status/role and tenant withdrawal, ceiling
intersection, delegated actor/expiry, nested delegation, replacement workload UID
and table-scoped machine grant negatives pass.

| Check | Result |
| --- | --- |
| go test -race -count=1 -shuffle=on -timeout=10m ./... | PASS; services 59.749s, all packages passed |
| go vet ./... and go build ./... | PASS |
| make helm-test | PASS, including unchanged Logs chart contract |
| make fuzz-ai-gateway | PASS, 133079 executions, 12.879s |
| Focused AI statement coverage | 328/430 statements, 76.3%, new AI production files only |
| gosec v2.28.0 | PASS |
| make security | NOT PASS: govulncheck used host Go1.27.1 and reported 12 standard-library findings; no dependency/toolchain change in this task |
| Branch, condition, MC/DC and mutation floors | NOT demonstrated |

The focused statement figure is not whole changed-package coverage. Sentinel's
release floors (90% changed-package statements, 85% branches and 70% mutation)
are not met by this evidence. Release remains NO-GO until independently qualified;
these limits do not claim functional test failures or authorize production.
No toolchain vulnerability remediation is included in CFP-116's feature diff.

The management manifest matches the API byte-for-byte:
SHA256 a8ff94abb20b942c61dd732cb7f131d7205c3e5178005415f458505220e2e54a.
The remaining integration gate is current API callback, installation identity,
private receiver/store qualification and authenticated public-path acceptance.
No existing Logs grants or Cefas sources/protocols/images changed.
