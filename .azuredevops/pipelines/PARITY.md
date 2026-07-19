---
title: Azure DevOps Workflow Parity and Operator Guide
description: Live parity status, evidence routing, prerequisites, operation, and cutover controls for the 19 migrated workflows
ms.date: 2026-07-17
ms.topic: reference
---
<!-- markdownlint-disable-file -->

## Current status

The migration status is `local-pass-live-partial`. Implemented and static parity
is complete for all 19 workflows, and all 19 Azure DevOps definitions have run
history. Live operational parity is incomplete.

Pull request 201 includes the follow-on dual-publication implementation. Local
validation requires third-party and MSDO SARIF to publish through both
`CodeAnalysisLogs` and `AdvancedSecurity-Publish@1`. The recorded scanner run
IDs below predate that follow-on and prove only the SARIF Scans artifact path.
Live visibility and exact MSDO tool identities in Repos Advanced Security Code
Scanning remain pending exact-commit runs and product-view inspection.

The documented code snapshot is branch
`feature/2987-azdo-pipeline-migration` at commit
`70dab831c5e002a15f3810105d462993b52ac47b` (`70dab83`). It targets Azure
DevOps organization `MngEnvMCAP675646`, project `DevSecOps`, and Azure Repos
repository `gh-advsec-devsecops`. Azure DevOps Issue 2987 tracks the migration,
and pull request 201 carries the implementation. Blocking dependency policy 142
uses definition 230. Its successful proof run 3854 published dependency evidence
and updated marker-owned pull request thread 762.

At the recorded snapshot, 15 definitions have successful live proof and four
fail closed on missing approved external governance inputs. Definition 217
completed signed digest deployment and HTTP readiness in run 3922. Definition
234 completed project-wiki publication in run 3911, followed by API read-back
of all five managed pages. Full cutover remains gated only by the four external
input groups identified below.

Parity has three separate levels:

1. Implemented and static parity is complete for all 19 source workflows.
2. Queue coverage is complete because all 19 target definitions have run history.
3. Live operational parity is incomplete until approved external inputs and the
   affected live behaviors pass.

> [!IMPORTANT]
> A scanner run can succeed while publishing findings from this intentionally
> insecure demonstration application. Findings are expected evidence, not
> execution failures. Tool startup, scanner execution, report integrity, and
> admission failures remain blocking. Do not weaken those gates or rewrite the
> vulnerable demonstration application as part of this migration.

## Evidence summary

Local validation at the documented snapshot produced this evidence:

* 172 Pester tests passed
* 21 YAML files parsed: 19 top-level definitions and two shared templates
* 19 source workflows mapped to 19 unique target definitions
* Four GitHub-platform gaps remained explicit and `decision-required`
* The Bicep build passed
* The .NET Release build passed
* CI/CD run 3922 deployed exact digest
  `sha256:6f4581c65a9336d935b63c685b27703563deb68d37dc50191dfdc271c18b689d`
  and independent endpoint verification returned HTTP 200
* Documentation run 3911 published and API-verified the five managed
  `/Documentation` pages
* No unauthorized governance, security-agent, Scorecard, Microsoft SBOM, or
  DAST mutation occurred during the remaining live validation

Run 3893 published DAST precondition evidence with
`mutationAttempted: false`. Run 3894 published security-agent precondition
evidence with `assessmentExecuted: false`. Runs 3885 and 3891 did not start a
job, so they could not mutate Azure or Storage. Governance run 3887 followed the
designed `decision-required` no-mutation path.

## Workflow parity matrix

The checked-in
[`config/workflow-contracts.json`](config/workflow-contracts.json) is the machine
authority for source-to-target mapping, triggers, UTC schedules, gates,
artifacts, side effects, and platform gaps. Azure Repos pull request execution is
configured through branch build policies, not YAML `pr:` triggers. Every listed
schedule is UTC and has `always: true` in its target YAML.

| Source workflow | Target YAML | Definition | Trigger or schedule in UTC | Gate and finding behavior | Primary evidence or visualization | Latest live run | Parity or blocker |
| --- | --- | --- | --- | --- | --- | --- | --- |
| [`.github/workflows/ci.yml`](../../.github/workflows/ci.yml) | [`.azuredevops/pipelines/ci.yml`](ci.yml) | 216 `ci` | PR to `main` through build policy | Restore, Release build, and container build must pass | Pipeline job and build logs | 3839, `c91bdc8`, succeeded | Live proof succeeded |
| [`.github/workflows/cicd.yml`](../../.github/workflows/cicd.yml) | [`.azuredevops/pipelines/cicd.yml`](cicd.yml) | 217 `cicd` | Push to `main`; manual | Bicep deployment, managed-identity ACR pull, signed digest evidence, and HTTP readiness must pass | Azure DevOps environment and `signed-image-evidence` | 3922, `70dab83`, succeeded | Live proof passed OIDC provisioning, EC signing, SPDX and SLSA v1 verification, digest-only deployment, and HTTP readiness |
| [`.github/workflows/CIS-Anchore-Grype.yml`](../../.github/workflows/CIS-Anchore-Grype.yml) | [`.azuredevops/pipelines/cis-anchore-grype.yml`](cis-anchore-grype.yml) | 218 `cis-anchore-grype` | Push to `main`; PR to `main`; `0 1 * * 0` | Execution and SARIF integrity block; critical findings remain report-only | SARIF Scans through exact `CodeAnalysisLogs` | 3875, `6b5fcee`, succeeded | Live proof succeeded with finding-exit handling preserved |
| [`.github/workflows/CIS-Trivy-AquaSecurity.yml`](../../.github/workflows/CIS-Trivy-AquaSecurity.yml) | [`.azuredevops/pipelines/cis-trivy.yml`](cis-trivy.yml) | 219 `cis-trivy` | Push to `main`; PR to `main`; `0 1 * * 0` | Execution and SARIF integrity block; findings remain report-only | SARIF Scans through exact `CodeAnalysisLogs` | 3867, `6eca867`, succeeded | Live proof succeeded |
| [`.github/workflows/DAST-ZAP-Zed-Attach-Proxy-Checkmarx.yml`](../../.github/workflows/DAST-ZAP-Zed-Attach-Proxy-Checkmarx.yml) | [`.azuredevops/pipelines/dast-zap.yml`](dast-zap.yml) | 220 `dast-zap` | Push to `main`; `0 1 * * 0` | Authorization, readiness, execution, and report integrity block; findings remain report-only | `CodeAnalysisLogs` plus `zap-reports` | 3893, `4bc0d2b`, failed | Approved digest-qualified `ZAP_IMAGE` absent; evidence proves `mutationAttempted: false` |
| [`.github/workflows/enforce-ghas-policy.yml`](../../.github/workflows/enforce-ghas-policy.yml) | [`.azuredevops/pipelines/enforce-ghas-policy.yml`](enforce-ghas-policy.yml) | 221 `enforce-ghas-policy` | Manual; `0 6 * * *` | Approved disposition and post-apply verification gate any mutation | `governance-report`, optional `governance-apply-report`, sanitized wiki fallback | 3887, `c99dd0b`, succeeded | Designed `decision-required` no-mutation path succeeded; operational replacement decision remains open |
| [`.github/workflows/IACS-AquaSecurity-tfsec.yml`](../../.github/workflows/IACS-AquaSecurity-tfsec.yml) | [`.azuredevops/pipelines/iacs-aquasecurity-tfsec.yml`](iacs-aquasecurity-tfsec.yml) | 222 `iacs-aquasecurity-tfsec` | Push to `main`; PR to `main`; `15 03 * * 5` | Execution and SARIF integrity block; findings remain report-only | SARIF Scans through exact `CodeAnalysisLogs` | 3868, `6eca867`, succeeded | Live proof succeeded |
| [`.github/workflows/IACS-Checkmarx-kics.yml`](../../.github/workflows/IACS-Checkmarx-kics.yml) | [`.azuredevops/pipelines/iacs-checkmarx-kics.yml`](iacs-checkmarx-kics.yml) | 223 `iacs-checkmarx-kics` | Push to `main`; PR to `main`; `15 03 * * 5` | Execution and SARIF integrity block; findings remain report-only | `CodeAnalysisLogs`, `kics-json`, and PR summary | 3869, `6eca867`, succeeded | Live proof succeeded |
| [`.github/workflows/IACS-Microsoft-Security-DevOps.yml`](../../.github/workflows/IACS-Microsoft-Security-DevOps.yml) | [`.azuredevops/pipelines/iacs-microsoft-security-devops.yml`](iacs-microsoft-security-devops.yml) | 224 `iacs-microsoft-security-devops` | Push to `main`; PR to `main`; `15 03 * * 5` | MSDO execution and dual publication must pass | Microsoft Security DevOps native `CodeAnalysisLogs` plus Repos Advanced Security Code Scanning | 3844, `c91bdc8`, succeeded | Recorded run proves native publication only; exact-commit Advanced Security run pending |
| [`.github/workflows/MSDO-Microsoft-Security-DevOps.yml`](../../.github/workflows/MSDO-Microsoft-Security-DevOps.yml) | [`.azuredevops/pipelines/msdo-security-devops.yml`](msdo-security-devops.yml) | 225 `msdo-security-devops` | Push to `main`; PR to `main`; `42 13 * * 5` | MSDO execution and dual publication must pass | Microsoft Security DevOps native `CodeAnalysisLogs` plus Repos Advanced Security Code Scanning | 3845, `c91bdc8`, succeeded | Recorded run proves native publication only; exact-commit Advanced Security run pending |
| [`.github/workflows/SAST-ESLint.yml`](../../.github/workflows/SAST-ESLint.yml) | [`.azuredevops/pipelines/sast-eslint.yml`](sast-eslint.yml) | 226 `sast-eslint` | Push to `main`; PR to `main`; `39 9 * * 4` | SARIF integrity blocks; findings remain report-only | SARIF Scans through exact `CodeAnalysisLogs` | 3879, `42ab39b`, succeeded | Live proof succeeded with finding-exit handling preserved |
| [`.github/workflows/SAST-GitHubAdvancedSecurity-CodeQL.yml`](../../.github/workflows/SAST-GitHubAdvancedSecurity-CodeQL.yml) | [`.azuredevops/pipelines/sast-codeql.yml`](sast-codeql.yml) | 227 `sast-codeql` | Push to `main`; PR to `main`; `26 8 * * 2` | C#, Python, and JavaScript analysis run independently with `security-and-quality`; analysis failures block | Repos Advanced Security code scanning | 3847, `c91bdc8`, succeeded | Live proof succeeded; Actions-language gap still requires disposition |
| [`.github/workflows/SAST-Kubesec.yml`](../../.github/workflows/SAST-Kubesec.yml) | [`.azuredevops/pipelines/sast-kubesec.yml`](sast-kubesec.yml) | 228 `sast-kubesec` | Push to `main`; PR to `main`; `18 8 * * 6` | Execution, deterministic conversion, nonempty runs, and SARIF integrity block; findings remain report-only | SARIF Scans through exact `CodeAnalysisLogs` | 3884, `c99dd0b`, succeeded | Live proof succeeded with scored findings preserved |
| [`.github/workflows/SCA-Anchore-Syft-SBOM.yml`](../../.github/workflows/SCA-Anchore-Syft-SBOM.yml) | [`.azuredevops/pipelines/sca-anchore-syft-sbom.yml`](sca-anchore-syft-sbom.yml) | 229 `sca-anchore-syft-sbom` | Push to `main` | Image build and SBOM generation must pass | `syft-sbom` artifact | 3863, `6ce494f`, succeeded | Live proof succeeded |
| [`.github/workflows/SCA-GitHubAdvancedSecurity-DependencyReview.yml`](../../.github/workflows/SCA-GitHubAdvancedSecurity-DependencyReview.yml) | [`.azuredevops/pipelines/sca-dependency-scanning.yml`](sca-dependency-scanning.yml) | 230 `sca-dependency-scanning` | PR to `main` through build policy | Native scan plus changed-package comparison; moderate-or-higher vulnerabilities and disallowed detected SPDX licenses block; unknown licenses warn | Repos Advanced Security, JSON and Markdown artifacts, marker-owned PR thread | 3892, `6e8faa2`, succeeded | Latest run succeeded; policy proof 3854, policy 142, and thread 762 verify admission behavior |
| [`.github/workflows/SCA-Microsoft-SBOM.yml`](../../.github/workflows/SCA-Microsoft-SBOM.yml) | [`.azuredevops/pipelines/sca-microsoft-sbom.yml`](sca-microsoft-sbom.yml) | 231 `sca-microsoft-sbom` | Push to `main` | Release build and SPDX generation must pass | `microsoft-spdx-sbom` artifact | 3888, `c99dd0b`, failed | Approved immutable tool version, URL, SHA-256, supplier, namespace, and platform-gap disposition absent |
| [`.github/workflows/SCA-OpenSSF-Scorecard.yml`](../../.github/workflows/SCA-OpenSSF-Scorecard.yml) | [`.azuredevops/pipelines/sca-openssf-scorecard.yml`](sca-openssf-scorecard.yml) | 232 `sca-openssf-scorecard` | Push to `main`; `25 23 * * 3` | Execution and authoritative JSON validation block | `openssf-scorecard-json` with sanitized wiki fallback | 3889, `c99dd0b`, failed | Approved image, repository, protected token, wiki, retention, and disposition inputs absent |
| [`.github/workflows/security-agent-workflow.yml`](../../.github/workflows/security-agent-workflow.yml) | [`.azuredevops/pipelines/security-agent.yml`](security-agent.yml) | 233 `security-agent` | Manual | Pinned CLI, bounded read-only tools, timeout, and structured severity output must pass | `security-agent-report` with sanitized wiki fallback | 3894, `4bc0d2b`, failed | Approved CLI integrity and protected token absent; evidence proves `assessmentExecuted: false` |
| [`.github/workflows/static.yml`](../../.github/workflows/static.yml) | [`.azuredevops/pipelines/docs-static.yml`](docs-static.yml) | 234 `docs-static` | Push to `main`; manual | Wiki staging, content validation, and protected exclusive-lock publication must pass | `wiki-documentation`, project wiki `/Documentation`, and environment deployment record | 3911, `bc716bd`, succeeded | Live project-wiki publication and API read-back succeeded for the index and four managed child pages |

## Explicit platform gaps

The following four entries are copied from the machine authority. Each remains
`decision-required`. The accountable owner must record exactly one allowed
disposition: `accepted`, `replaced`, `retained`, or `retired`.

| Gap ID | Owner role | Required disposition input | Current status | Requirement |
| --- | --- | --- | --- | --- |
| `codeql-actions-language` | `application-security-owner` | `PLATFORM_GAP_CODEQL_ACTIONS_DISPOSITION` | `decision-required` | Decide whether GitHub Actions language analysis is accepted as absent, replaced in Azure DevOps, retained on GitHub, or retired |
| `github-spdx-dependency-submission` | `software-supply-chain-owner` | `PLATFORM_GAP_SPDX_SUBMISSION_DISPOSITION` | `decision-required` | Decide how GitHub SPDX dependency submission is accepted, replaced, retained, or retired |
| `public-openssf-scorecard-publication` | `open-source-program-owner` | `PLATFORM_GAP_SCORECARD_PUBLICATION_DISPOSITION` | `decision-required` | Decide whether public Scorecard publication is accepted as absent, replaced, retained, or retired |
| `github-organization-policy-mutation` | `azure-devops-platform-owner` | `PLATFORM_GAP_ORG_POLICY_DISPOSITION` | `decision-required` | Approve an Azure DevOps governance replacement or explicitly accept, retain, or retire the GitHub organization mutation |

The contract validator keeps these decisions visible. A pending decision is not
operational parity, even when the associated pipeline follows its designed
no-mutation path.

## Visualization and evidence routing

Use Azure DevOps in-product visualization first. Use the project wiki only when
no suitable product view exists. The checked-in
[`config/visualization-routing.json`](config/visualization-routing.json) defines
the authoritative routes.

* Publish GHAzDO CodeQL and dependency results to Repos Advanced Security
* Publish Microsoft Security DevOps results natively through `publish: true`
  and `CodeAnalysisLogs`, then publish the documented `.gdn` directory through
  `AdvancedSecurity-Publish@1` to Repos Advanced Security Code Scanning
* Publish only validated third-party SARIF 2.1.0 with a nonempty run through the
  artifact named exactly `CodeAnalysisLogs`, which feeds the SARIF Scans tab,
  and through `AdvancedSecurity-Publish@1`, which feeds Repos Advanced Security
  Code Scanning
* Retain SBOMs, signed SLSA provenance, deployment records, ZAP reports, and
  other machine evidence as pipeline artifacts, OCI referrers, or Azure DevOps
  environment records according to their contracts
* Publish a sanitized project-wiki summary only for Scorecard, security-agent,
  governance, and final workflow-parity reports because no better product view
  exists; link back to authoritative run or artifact evidence
* Publish the four approved documentation sources and generated index as
  authoritative Markdown under project-wiki path `/Documentation`, backed by
  the `wiki-documentation` manifest and content artifact

Wiki summaries may contain aggregate counts, status, run and artifact links,
and approved remediation summaries. They must not contain tokens, credentials,
request headers, target secrets, or raw sensitive payloads. The pinned OpenSSF
Scorecard v5.5.0 CLI supports JSON, not SARIF, so Scorecard remains authoritative
JSON. Do not fabricate SARIF for a format the tool does not support. Exact live
MSDO Code Scanning tool identities remain pending exact-commit runs.

## Operational prerequisites

Supply administrative values through approved protected resources, pipeline
variables, variable groups, service connections, or untracked operator input.
Never commit secrets. Never fabricate a value merely to turn a run green.

### Azure services and environments

* Workload-identity Azure Resource Manager service connections authorized only
  for definition 217 and any separately approved Azure deployment consumer
* Approved subscription, resource groups, ACR, App Service, retained Storage
  infrastructure, Key Vault signing key, and deployment bootstrap digest inputs
* Application and documentation environments with explicit pipeline access
* An exclusive-lock check for the production documentation environment
* Azure roles limited to the exact deployment, ACR, App Service, Storage, and
  Key Vault operations in each contract

### Tool and scanner integrity

* Immutable image digests for containerized scanners
* Exact tool versions, approved download URLs, and vendor-verified checksums
* NPM SHA-512 integrity values for approved CLI packages
* Supplier and namespace metadata needed by Microsoft SPDX generation
* Integrity values reviewed from authoritative vendor or registry evidence

### Protected tokens and publication

* Protected tokens scoped to the security agent, Scorecard, and approved API
  operations that require them
* An initialized project wiki ID and Build Service permission limited to the
  approved wiki paths
* Repository-scoped pull request thread contribution for definition 230
* Approved run, pull request run, artifact, OCI, and optional lease retention
  that matches the audit policy

### DAST authorization

* A digest-qualified `ZAP_IMAGE`
* An approved target, scan mode, time window, owner, and authorization record
* Network reachability and a bounded readiness contract
* No external active scan without the approved record

### Platform decisions and least privilege

* A disposition for each of the four explicit platform gaps
* Per-pipeline authorization for every service connection, variable group, and
  environment
* No branch contribution, policy bypass, permission management, key
  administration, account-key, or organization-wide rights unless the contract
  and an accountable owner explicitly require them

## Registration and governance

Start with the nonsecret shape in
[`config/pipeline-registration.example.json`](config/pipeline-registration.example.json).
Copy it to an untracked operator location, populate approved IDs, and keep that
live configuration outside version control.

Preview registration without network mutation:

```powershell
./scripts/azure-devops/Register-PipelineDefinitions.ps1 `
  -ConfigurationPath <untracked-registration-input.json>
```

Register exactly 19 definitions after review and checkpoint the resolved IDs:

```powershell
./scripts/azure-devops/Register-PipelineDefinitions.ps1 `
  -ConfigurationPath <untracked-registration-input.json> `
  -OutputPath <untracked-registration-result.json> `
  -Apply
```

Verify definition IDs, repository identity, and exact YAML paths without
mutation:

```powershell
./scripts/azure-devops/Register-PipelineDefinitions.ps1 `
  -ConfigurationPath <untracked-governance-input.json> `
  -Verify
```

Preview governance changes before applying them:

```powershell
./scripts/azure-devops/Initialize-PipelineGovernance.ps1 `
  -ConfigurationPath <untracked-governance-input.json>
```

Apply only after an administrator reviews the plan and protected-resource
authorizations:

```powershell
./scripts/azure-devops/Initialize-PipelineGovernance.ps1 `
  -ConfigurationPath <untracked-governance-input.json> `
  -Apply
```

Verify live state read-only and retain the report:

```powershell
./scripts/azure-devops/Test-PipelineGovernance.ps1 `
  -ConfigurationPath <untracked-governance-input.json> `
  -OutputPath <governance-verification.json>
```

Required governance includes automatic blocking build validation for contracted
pull request workflows, `valid-duration=0`, source-update requeue behavior, at
least one reviewer, no creator vote, blocking downvotes, reset on source push,
resolved comments, 30-day minimum run retention, protected-resource
authorization, and the documentation exclusive lock.

## Validation commands

Run the static contract validator before registration, after contract or YAML
changes, and before any cutover decision:

```powershell
pwsh -NoProfile -File scripts/validation/Test-WorkflowContracts.ps1
```

Run the complete pipeline-focused test suite:

```powershell
pwsh -NoProfile -Command "Invoke-Pester -Path tests/pipelines -EnableExit"
```

Parse all configuration JSON:

```powershell
Get-ChildItem .azuredevops/pipelines/config -Filter *.json |
  ForEach-Object { Get-Content -LiteralPath $_.FullName -Raw | ConvertFrom-Json -Depth 100 | Out-Null }
```

Parse all 19 definitions and two templates with an approved YAML parser. Build
the solution in Release mode and compile the Bicep entry point as part of the
full local gate:

```powershell
dotnet build gh-aspnet-webapp-01.sln --configuration Release
az bicep build --file blueprints/gh-aspnet-webapp/bicep/main.bicep
```

Local validation proves implementation and contract consistency. It does not
replace live service-connection authorization, environment checks, product-view
inspection, retention verification, deployment smoke tests, DAST authorization,
or platform-owner decisions.

## Run interpretation and troubleshooting

Use the earliest failing gate and its authoritative evidence. Do not classify a
published vulnerability as a pipeline failure unless the contract has an
admission gate for that finding.

| Symptom | Interpretation | Operator action |
| --- | --- | --- |
| Pipeline preparation rejects `AZURE_SERVICE_CONNECTION` | The named service connection is missing, unresolved, or not authorized for an Azure deployment definition | Create or select the approved workload-identity connection, authorize only the consuming Azure deployment definition, and requeue |
| Documentation publication rejects `PROJECT_WIKI_IDENTIFIER` or `System.AccessToken` | The project wiki is not identified or the deployment task lacks an explicitly mapped job token | Supply the initialized project wiki identifier, enable the job token, verify Build Service wiki contribution under `/Documentation`, and requeue definition 234 |
| A prerequisite task rejects an empty digest, checksum, token, wiki ID, or disposition | The pipeline failed closed before trusted execution | Obtain the approved value from its accountable owner; do not substitute a placeholder |
| Scanner exits with documented finding status and valid evidence publishes | The intentionally insecure demo produced expected findings | Review the product view or artifact; keep execution and integrity gates enabled |
| Scanner crashes, tool integrity fails, report is absent, or SARIF is invalid | Execution or evidence integrity failed | Treat the run as blocking and repair the tool, invocation, or report path before requeueing |
| DAST precondition evidence shows `mutationAttempted: false` | Authorization or immutable image prerequisites stopped the scan safely | Complete DAST approvals, then requeue in the approved window |
| Security-agent evidence shows `assessmentExecuted: false` | CLI integrity or token prerequisites stopped assessment safely | Supply the approved protected inputs and requeue |
| Governance disposition is `decision-required` | No mutation is permitted, even when the no-mutation run succeeds | Obtain the platform-owner disposition before enabling an apply path |
| Native results are absent but the job succeeded | Publication or product licensing may be incomplete | Verify GHAzDO or MSDO licensing, task publication, and the intended product view |
| `CodeAnalysisLogs` is absent or named differently | Third-party SARIF cannot feed the expected SARIF Scans experience | Restore exact artifact naming after SARIF 2.1.0 validation |
| `AdvancedSecurity-Publish@1` fails or results are absent | The Advanced Security entitlement, bundled task, repository association, permissions, or SARIF ingestion contract may be incomplete | Inspect the publish task log, confirm the absolute `SarifsInputDirectory`, and verify the exact branch and pipeline in Repos Advanced Security Code Scanning |

## Cutover and rollback

Do not disable or delete the GitHub workflows at `local-pass-live-partial`.
Retain them until the equivalent active controls and live behavior are verified.

Cutover requires all of the following:

* All recorded administrative prerequisite failures are resolved with approved
  values, and definition 234 completes a new project-wiki publication run
* Definitions 217, 220, 231, 232, 233, and 234 complete their intended live
  behavior; definition 221 has an approved platform disposition and any
  authorized apply path is independently verified
* Native GHAzDO and Microsoft Security DevOps views contain expected results
* Every third-party SARIF producer publishes validated SARIF 2.1.0 through
  exact `CodeAnalysisLogs` and `AdvancedSecurity-Publish@1`, with both product
  views inspected against the same commit
* Branch policies, reviewer controls, protected-resource permissions,
  environments, locks, schedules, retention, wiki permissions, and least
  privilege pass read-only governance verification
* Application and documentation deployment evidence, signed OCI evidence,
  endpoint readiness, static content, DAST cleanup, and authorized side effects
  are verified in nonproduction before production activation
* All four platform gaps have accountable, recorded dispositions
* No critical or major behavioral parity defect remains

Rollback follows a preservation principle: keep the GitHub workflows available
until Azure DevOps controls and live behavior are proven. If an Azure DevOps
control regresses after activation, stop its mutation or deployment path,
restore the previously verified control path, preserve run and artifact
evidence, and investigate before retrying. Do not run both deployment systems
concurrently against the same production target without an explicit
serialization and ownership decision.

## Ownership and sources of truth

Use this hierarchy when evidence conflicts:

1. [`config/workflow-contracts.json`](config/workflow-contracts.json) controls
   workflow mapping, triggers, schedules, gates, artifacts, side effects, and
   platform-gap declarations.
2. Target YAML and shared scripts implement the contract.
3. [`config/visualization-routing.json`](config/visualization-routing.json)
   controls authoritative evidence destinations and sanitized wiki fallback.
4. Azure DevOps definition read-back, governance state, run records, product
   views, artifacts, OCI evidence, and environment history prove live behavior.
5. This guide records the operator interpretation and the dated live snapshot.

Contract changes require corresponding YAML, test, and documentation updates.
Run history can supersede the dated snapshot, but it does not silently alter the
checked-in behavior contract.