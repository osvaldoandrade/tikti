# SAML Threat Model

## Review Engagement

| Field | Details |
|---|---|
| **Reviewer** | TBD — external security reviewer (NDA required before engagement) |
| **Scope** | SAML 2.0 SP implementation in Tikti: XML validator handling, signature wrapping defense, replay protection, cookie policy, IdP metadata trust |
| **Timeline** | 3-day pentest window scheduled for Week 5 of the SAML milestone |
| **Deliverables** | Markdown report at `docs/security/saml-pentest-report.md` (produced in P8.7) |

### Reviewer Checklist

- [ ] Reviewer identified and NDA executed.
- [ ] This threat-model document shared and acknowledged.
- [ ] Severity scale agreed (see below).
- [ ] 3-day pentest calendar invite confirmed for Week 5.

---

## Severity Scale

All findings will be classified using the following severity levels:

| Severity | Definition | SLA |
|---|---|---|
| **Critical** | Exploitable remotely with no authentication; leads to full tenant compromise, data exfiltration, or authentication bypass. | Must fix before GA; blocks release. |
| **High** | Exploitable with limited preconditions (e.g., authenticated attacker, specific IdP configuration); leads to privilege escalation or significant data exposure. | Must fix before GA. |
| **Medium** | Requires non-trivial preconditions or chaining with another issue; limited blast radius. | Fix targeted for GA; may ship with documented mitigation. |
| **Low** | Defence-in-depth finding, informational, or hardening recommendation with no direct exploit path. | Tracked; fix in next minor release. |

## Triage Rubric

1. **Reproduce** — confirm the finding against the local dev stack (`make saml-dev`).
2. **Classify** — assign severity using the table above.
3. **Scope** — determine affected tenants (single-tenant vs. all tenants).
4. **Prioritise** — Critical and High block GA; Medium and Low enter the backlog.
5. **Remediate** — open a GitHub issue per finding, link to this document, assign owner.
6. **Verify** — reviewer re-tests the fix in a follow-up session.

---

## STRIDE Threat Model

*Source: `docs/12_saml_federation_hld.md` — Appendix I.*

| Threat | Vector | Control | Residual |
|---|---|---|---|
| **S**poofing — fake IdP | Attacker publishes look-alike metadata | Cert pinned at registration; rotation requires CLI with API key | Low |
| **S**poofing — stolen idToken cookie | XSS, infostealer | `HttpOnly`, `Secure`, short TTL, rotation on login | Medium (same as today) |
| **T**ampering — assertion mutation | Man-in-the-middle | TLS at ingress; XML-DSig over the assertion | Low |
| **T**ampering — signature wrapping | Layered XML | Ancestor-walk validator, ID-collision rejection | Low |
| **R**epudiation — who logged in | Insider dispute | Immutable audit record per assertion | Low |
| **I**nfo disclosure — raw XML in logs | Debug log leaks PII | Raw XML behind feature flag off in prod | Low |
| **I**nfo disclosure — error oracle | Attacker probes reasons | 4 neutral pages, reasons only in logs | Low |
| **D**oS — large SAMLResponse | Attacker spams ACS | 1 MiB body limit, 413 before work | Medium |
| **D**oS — Redis saturation | AuthnRequest flood | Per-IP rate limit at ingress, `SET NX EX` TTLs | Medium |
| **E**levation — tenant escalation | Assertion with alien `tid` | `tid` from URL only, never assertion | Blocked |
| **E**levation — role injection | IdP sends `roles=[admin]` | Per-tenant attribute map whitelist | Low |

---

## References

- High-Level Design: `docs/12_saml_federation_hld.md`
- Pentest report (P8.7): `docs/security/saml-pentest-report.md`
