---
title: Azure DevOps Pipeline Migration
description: Current status, prerequisites, registration, governance, visualization, and cutover guidance for the Azure DevOps pipeline migration
ms.date: 2026-07-17
ms.topic: reference
---

## Current status

This directory contains one Azure DevOps pipeline definition for each source
workflow under `.github/workflows`. Azure Repos branch policies provide pull
request validation. Pipeline YAML must not use `pr:` triggers.

The current status is `local-pass-live-partial`:

* Implemented and static parity is complete for all 19 workflows
* Queue coverage is complete for all 19 definitions
* The recorded live snapshot has 15 succeeded definitions and four definitions
  that fail closed on approved external governance inputs
* Definition 217 deploys signed, attested images by digest through secretless
  OIDC; run 3922 passed independent evidence verification and HTTP readiness
* Definition 234 publishes five validated pages to the project wiki; run 3911
  completed publication and all pages passed API read-back

The implemented deployment and documentation paths are live-proven. Full
operational parity remains gated by the four approved external-input groups
documented in the parity matrix. See the
[Azure DevOps Workflow Parity and Operator Guide](PARITY.md) for the complete
19-workflow matrix, definition and run evidence, blocker status, troubleshooting,
validation, ownership, cutover, and rollback guidance.

The configuration files in [`config/`](config/) are executable migration
contracts. Run the contract validator before registering or changing pipeline
definitions:

```powershell
pwsh -NoProfile -File scripts/validation/Test-WorkflowContracts.ps1
```

## Required administrative inputs

Supply these values outside the repository through approved Azure DevOps
configuration or an untracked governance input file. Do not place credentials,
tokens, account keys, or service-principal secrets in these files.

| Input | Approved source |
| --- | --- |
| Azure DevOps organization URL, project ID, and repository ID | Governance input file or script parameters |
| Repository source branch for pipeline YAML (`main` when omitted) | Governance input file |
| Nineteen pipeline definition IDs | Governance input file after pipeline registration |
| Workload-identity service connection IDs | Per-pipeline authorization in Azure DevOps for Azure deployment consumers |
| Production application and documentation environment IDs | Governance input file |
| Azure subscription and resource names | Variable group and workload-identity service connection |
| Build Service and administrator identity descriptors | Governance input file |
| Audit retention lease duration | Organization audit-policy decision |
| Authorized non-ephemeral ZAP targets and scan windows | Application-owner approval record |
| Tool checksums and container digests marked `requiredInput` | Vendor release evidence reviewed by an administrator |
| Platform-gap owner and disposition | Platform-owner approval record |

Protected tokens, wiki identifiers and permissions, approved retention values,
digest-qualified scanner images, tool integrity metadata, and platform-gap
dispositions must come from accountable owners. Do not fabricate values merely
to produce green runs.

The project run, pull request run, and artifact retention baseline is 30 days.
Production deployment evidence leases remain disabled until an audit-approved
duration is supplied. A lease duration must never be inferred from the baseline.

## Registration sequence

1. Install and license GitHub Advanced Security for Azure DevOps. Confirm the
  bundled `AdvancedSecurity-Publish@1` task is available to pipeline jobs.
2. Install the SARIF SAST Scans Tab and Microsoft Security DevOps extensions.
3. Create least-privilege workload-identity service connections. Authorize each
  connection only for the Azure deployment pipeline that consumes it. The
  documentation pipeline does not use an Azure service connection.
4. Create the Azure Key Vault signing key outside pipeline execution. Grant the
   pipeline identity `Key Vault Crypto User`; do not grant key-management roles.
5. Create the application and documentation environments. Add an exclusive-lock
   check to the production documentation environment.
6. Copy
  [`config/pipeline-registration.example.json`](config/pipeline-registration.example.json)
  outside the repository or to a git-ignored location, then replace every null
  administrative input.
7. Preview all 19 registrations without network calls:

   ```powershell
   ./scripts/azure-devops/Register-PipelineDefinitions.ps1 `
     -ConfigurationPath <untracked-registration-input.json>
   ```

8. Register all 19 YAML definitions only after administrator review. Capture
   the returned definition IDs in a separate untracked file:

   ```powershell
   ./scripts/azure-devops/Register-PipelineDefinitions.ps1 `
     -ConfigurationPath <untracked-registration-input.json> `
     -OutputPath <untracked-registration-result.json> `
     -Apply
   ```

9. Merge the captured IDs into the untracked governance input, then verify that
   every registered definition points to its configured YAML path. Verification
   lists definitions but does not mutate Azure DevOps:

   ```powershell
   ./scripts/azure-devops/Register-PipelineDefinitions.ps1 `
     -ConfigurationPath <untracked-governance-input.json> `
     -Verify
   ```

10. Run `Initialize-PipelineGovernance.ps1` without `-Apply` and review the plan.
11. Apply the plan in a nonproduction project with approved administrator access.
12. Run `Test-PipelineGovernance.ps1` against nonproduction and retain its report.
13. Repeat the reviewed operation for production only after gap decisions and
    ZAP authorization are complete.

The registration script reuses only an exact repository and YAML-path match,
rejects ambiguous definitions, and checkpoints resolved IDs. The governance
initializer is dry-run-first. Do not apply either operation from an unreviewed
configuration.

## Least-privilege identity contract

* Build pipelines receive repository read access only.
* The pull request dependency pipeline additionally receives pull request thread
  contribution permission for its marker-owned summary.
* Deployment uses workload identity and scoped Azure roles. The provisioning
  identity needs deployment rights plus narrowly scoped role-assignment write
  permission because Bicep creates `AcrPull`.
* Runtime deployment identities receive only the ACR, App Service, Storage, and
  Key Vault data-plane roles documented by their pipeline contracts.
* Direct pushes and policy bypass remain limited to explicitly named
  administrators or service identities.
* Tokens are passed through environment variables and must never be printed.

## Platform-gap decision inputs

These decisions are intentionally unresolved until an accountable owner records
one of `accepted`, `replaced`, `retained`, or `retired`. The contract validator
keeps them visible as required administrative inputs and does not treat a pending
decision as parity.

| Gap | Required owner | Current disposition input |
| --- | --- | --- |
| CodeQL analysis for the GitHub Actions language | Application security owner | `PLATFORM_GAP_CODEQL_ACTIONS_DISPOSITION` |
| GitHub SPDX dependency submission | Software supply-chain owner | `PLATFORM_GAP_SPDX_SUBMISSION_DISPOSITION` |
| Public OpenSSF Scorecard publication | Open source program owner | `PLATFORM_GAP_SCORECARD_PUBLICATION_DISPOSITION` |
| GitHub organization policy mutation | Azure DevOps platform owner | `PLATFORM_GAP_ORG_POLICY_DISPOSITION` |

## Visualization contract

Use Azure DevOps in-product visualization first. Native GHAzDO CodeQL and
dependency results publish directly to Repos Advanced Security. Microsoft
Security DevOps retains `publish: true` for its native `CodeAnalysisLogs`
publication and then passes the documented
`$(Build.ArtifactStagingDirectory)/.gdn/` directory directly to
`AdvancedSecurity-Publish@1` for Repos Advanced Security Code Scanning. It does
not use the shared publisher because that would duplicate `CodeAnalysisLogs`.
Third-party SARIF must be valid SARIF 2.1.0 with a nonempty run before it
publishes to either destination. The shared publisher retains the exact
`CodeAnalysisLogs` artifact for the SARIF Scans tab and passes the same
validated absolute directory to `AdvancedSecurity-Publish@1`. Native CodeQL
and dependency pipelines do not use the shared publisher.

Pull request 201 remains the active review vehicle. Local contracts cover both
publication paths, but live Advanced Security visibility is pending exact-commit
pipeline runs and product-view inspection. Exact live Code Scanning tool
identities for the MSDO analyzers also remain pending those exact-commit runs.
Do not infer Advanced Security publication from an existing `CodeAnalysisLogs`
artifact alone.

OpenSSF Scorecard v5.5.0 CLI supports JSON, not SARIF, so Scorecard remains
authoritative JSON. A sanitized project-wiki summary may link to that artifact,
but the migration must never fabricate Scorecard SARIF. Governance, agent, and
parity summaries use the wiki only because no suitable product view exists.
Wiki content must exclude secrets, tokens, raw request headers, target
credentials, and sensitive scanner payloads.

Documentation publishes authoritative Markdown directly to the initialized
project wiki under `/Documentation`. The `wiki-documentation` artifact contains
the staged page manifest and content used for publication. The pipeline does
not modify `/Security`, `/Governance`, or unknown manual wiki pages.

## Schedule contract

Every scheduled security or governance pipeline preserves its source UTC cron in
its own YAML and sets `always: true`. The workflow contract validator fails when
a scheduled contract omits either requirement.

## Run and cutover guidance

The intentionally insecure application is expected to produce findings. A
report-only scanner may succeed while publishing those findings. Scanner or tool
execution failures, invalid reports, admission failures, and evidence-integrity
failures remain blocking and must not be softened.

Keep the GitHub workflows until active Azure DevOps controls and live behavior
are verified. Cutover requires approved prerequisites, successful intended live
behavior for the blocked definitions, product-view and artifact inspection,
read-only governance verification, deployment and DAST evidence, and recorded
dispositions for all four platform gaps. Use the detailed
[parity and operator guide](PARITY.md#cutover-and-rollback) as the cutover and
rollback checklist.
