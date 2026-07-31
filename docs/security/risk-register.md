# Risk Register

Accepted risks, open decisions and residual exposure arising from the security remediation.
Findings are described in the [security audit report](security-audit-report.md); the changes made
are recorded in the [remediation log](remediation-log.md).

Each entry states what the risk is, who owns the decision, and — where the risk is accepted — the
reasoning that justifies acceptance.

## Open decisions

### RISK-001 — `AutoMapper` 15.1.3 licence conflicts with the declared project licence

| Field | Value |
| --- | --- |
| **Status** | **Open — repository-owner decision. Not resolved by the remediation.** |
| **Related finding** | H-01 (CWE-674, GHSA-rvv3-g6hj-g44x / CVE-2026-32933, OWASP A06:2021) |
| **Owner** | Repository owner / maintainers. This is a licensing and product-distribution decision, not an engineering one, so it is escalated rather than settled during remediation. |

**What the conflict is.** Closing H-01 requires moving `AutoMapper` off every version below
`15.1.1`, because that is where the advisory is first patched. Version `14.0.0` declares the MIT
licence (`automapper.nuspec`: `<license type="expression">MIT</license>`). From the patched line
onwards the package instead ships a licence file (`<license type="file">LICENSE.md</license>`) that
places the code under the **Reciprocal Public License 1.5**, with a separate commercial licence
agreement offered as the alternative. The core project declares
`<PackageLicenseExpression>Apache-2.0</PackageLicenseExpression>`, ships a matching licence file and
publishes packages for third-party consumption. A reciprocal licence's source-disclosure obligation
is not compatible with that distribution posture, and there is no patched permissive line to fall
back to — the fix begins at `15.1.1`, already under the new terms.

**Current state of the repository.** The pin has been raised to `[15.1.3]`, so the security
advisory is closed and the dependency gate is green. The declared licence expression was **not**
changed, no `PackageLicenseFile` was substituted for it, and the upgrade was **not** reverted. The
conflict is therefore visible and undecided rather than silently absorbed in either direction.

**Documented fallback, if the owner declines the upgrade.** Retain `14.0.0` behind a narrowly
scoped dependency-audit suppression carrying an inline justification, together with a formal
recorded risk acceptance. The acceptance rests on the following exploitability assessment: every
mapping is statically declared in source, and no user-controlled mapping configuration or type
graph reaches the configuration builder, so the recursion path is reachable only through a
self-referential mapping the developers themselves would have to author. Real-world exposure is
therefore low despite the High rating. The fallback keeps the build gate green without pretending
the advisory does not exist.

**Options, stated plainly.**

1. **Accept the upgrade** and reconcile the product's licensing position with the Reciprocal Public
   License 1.5 (or obtain the vendor's commercial licence).
2. **Decline the upgrade** and apply the documented fallback above — suppression plus formal,
   justified risk acceptance.
3. **Replace the dependency.** Not recommended on cost grounds: the platform declares hundreds of
   mappings across its profiles, so removing the library means hand-writing them, which is far
   beyond a security remediation.

## Accepted risks

### RISK-002 — Uncontrolled recursion in `AutoMapper` remains theoretically reachable by a developer

| Field | Value |
| --- | --- |
| **Status** | Accepted — residual, informational. |
| **Related finding** | H-01 |

The advisory is closed by the upgrade, so this entry records only the residual shape of the
weakness class for future reference: a self-referential mapping authored in source could still
produce deep recursion. It is not reachable by an external actor, because mapping configuration is
statically declared and no user-controlled configuration or type graph reaches the configuration
builder. No control is added for it, consistent with fixing only what is confirmed and with the
prohibition on enhancement beyond remediation.
