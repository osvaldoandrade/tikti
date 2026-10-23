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

## CFP-070 local qualification, 2026-10-23

The feature base is dff7e2a. Additional tests cover independent tenant and epoch,
subject, issuer/cluster/namespace/ServiceAccount/UID pins, current token claims,
delegation, installation grants, authority saturation, transport failures and
strict JSON size/depth/array limits. Each negative changes one named condition
from a valid control where applicable; this is not instrumented branch or MC/DC
coverage. No authorization protocol or feature-default change is included.

The qualified Go1.26.9 security run reproduced reachable crypto/x509 advisory
[GO-2026-6809](https://pkg.go.dev/vuln/GO-2026-6809). Module, Makefile and immutable
Docker builder now use Go1.26.10; all four Go workflows consume go.mod and select
local toolchain mode after setup. Official Docker-library and mirror resolutions
agreed on builder index SHA256
909771fef53e3dcb0950255f0c9a8b4728c3b841e61509c7b29b098de7ee02d4.

| Check at Go1.26.10 | Result |
| --- | --- |
| Full race/shuffle test suite | PASS; services 109.273s |
| Build, vet, module verification | PASS |
| Helm contracts and bounded AI fuzz | PASS; fuzz 101611 executions |
| Gosec v2.28.0 / govulncheck v1.1.4 | PASS; zero gosec issues and zero reachable vulnerabilities |
| Focused AI statement coverage | 409/430 = 95.1% |
| Whole changed packages | aigateway 99.0%, services 85.4%, controllers 72.5%, config 91.7% |
| Scoped mutation, authority.go + json.go | 80/81 killed (98.77%), one surviving slice-depth arithmetic mutant; no unresolved timeout after serial replay |
| Workflow actionlint | Four pre-existing release shell warnings, reproduced at dff7e2a; no new workflow syntax findings |

The verbose vulnerability result retains GO-2026-5932 for the unmaintained
OpenPGP package in required x/crypto; Tikti does not import that package or call
its symbols. This is not a waiver or a zero-findings claim. The actionlint warnings
are SC2097/SC2098 in the existing release shell environment assignment.

Gremlins v0.6.0 parallel runs produced 2 and then 8 timeouts; their nine distinct
mutants were replayed serially in an isolated copy of the actual package, with a
passing unmutated control. All nine produced test failures without timeout or
build error. The 80/81 count combines mutation results and this explicit replay;
it does not count timeouts as kills. The remaining `depth+1` to `depth-1` mutation
is in generic slice traversal; current AI schemas use flat string scopes.
It remains in the denominator. This mutation scope excludes services/controllers
and configuration; it is not a repository-wide mutation score.

The unchanged manifest hash above was reverified. Statement improvements do not
close the legacy whole-package, branch or MC/DC release floors. Local validation
does not establish CI, built-container, installation or authenticated acceptance.
Rollback can exclude this local hardening commit without changing grants or
credentials; reverting the Go pin reintroduces the documented x509 finding.
