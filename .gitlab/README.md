---
title: GitLab CI Pipeline Conversion
description: Workflow parity, required variables, schedules, and operating guidance for the GitLab CI pipeline
ms.date: 2026-07-20
ms.topic: reference
---

## Pipeline layout

The root `.gitlab-ci.yml` loads focused modules from `.gitlab/ci`. The modules
map every file under `.github/workflows` to a GitLab job or an explicit
platform-gap disposition. Existing PowerShell helpers remain authoritative for
dependency admission, Kubesec SARIF conversion, ZAP execution, and provenance.

Run local contract validation before pushing pipeline changes:

```powershell
Invoke-Pester tests/pipelines/Test-GitLabPipelineContracts.Tests.ps1
pwsh -NoProfile -File scripts/validation/Test-GitLabPipelineContracts.ps1
glab ci lint .gitlab-ci.yml --dry-run --ref main
```

## Required CI variables

Configure sensitive values as masked and protected GitLab CI/CD variables.

| Variable | Purpose |
| --- | --- |
| `AZURE_CLIENT_ID` | Microsoft Entra application or managed identity client ID for GitLab OIDC |
| `AZURE_TENANT_ID` | Microsoft Entra tenant ID |
| `AZURE_SUBSCRIPTION_ID` | Azure deployment subscription |
| `SBOM_TOOL_VERSION` | Approved Microsoft SBOM Tool version |
| `SBOM_TOOL_DOWNLOAD_URL` | Immutable Microsoft SBOM Tool binary URL |
| `SBOM_TOOL_SHA256` | SHA-256 digest for the SBOM Tool binary |
| `COSIGN_DOWNLOAD_URL` | Immutable Linux Cosign binary URL |
| `COSIGN_SHA256` | SHA-256 digest for the Cosign binary |
| `SIGNING_KEY_VAULT_NAME` | Azure Key Vault that contains the signing key |
| `SIGNING_KEY_NAME` | Azure Key Vault signing key name |
| `ZAP_IMAGE` | Approved ZAP image pinned with an `@sha256:` digest |
| `COPILOT_GITHUB_TOKEN` | Token for the manual GitHub Copilot security-agent compatibility job |
| `COPILOT_CLI_VERSION` | Exact approved GitHub Copilot CLI version |
| `GITLAB_GOVERNANCE_TOKEN` | Project access token with API scope for governance audit or apply |
| `GITLAB_GOVERNANCE_APPLY` | Set to `true` only through an approved protected run to mutate project policy |
| `GITLAB_WIKI_PUBLISH_TOKEN` | Masked, protected project access token with API scope for Wiki publication |

The Azure federated credential must trust the GitLab subject claims used by
this project. The deployment jobs request an ID token with audience
`api://AzureADTokenExchange`; no Azure client secret is stored in GitLab.

The `docs:gitlab-wiki` job publishes the approved documentation index and four
source pages under the GitLab Wiki `Documentation` namespace. On `main` pushes
it also publishes the aggregated security tool breakdown produced by
`security:summary` to `Documentation/Security-Findings-Summary`. It does not
delete unmanaged pages. Rotate `GITLAB_WIKI_PUBLISH_TOKEN` according to the
project credential policy.

## Pipeline schedules

GitLab stores cron schedules outside repository YAML. Create these schedules
against `main`, set the listed `SCAN_PROFILE` variable, and use UTC.

| Description | Cron | `SCAN_PROFILE` |
| --- | --- | --- |
| Weekly container and DAST scans | `0 1 * * 0` | `weekly-container-dast` |
| Daily governance audit | `0 6 * * *` | `daily-governance` |
| Weekly IaC scans | `15 3 * * 5` | `weekly-iac` |
| Weekly MSDO replacement scan | `42 13 * * 5` | `weekly-msdo` |
| Weekly ESLint scan | `39 9 * * 4` | `sast-eslint` |
| Weekly CodeQL replacement scan | `26 8 * * 2` | `sast-codeql` |
| Weekly Kubesec scan | `18 8 * * 6` | `sast-kubesec` |
| Weekly OpenSSF disposition report | `25 23 * * 3` | `openssf-scorecard` |

## Platform replacements

GitLab-native or portable tools replace GitHub-specific publication surfaces:

* Semgrep replaces CodeQL execution and emits GitLab SAST plus SARIF evidence
* Trivy emits GitLab container-scanning JSON plus SARIF evidence
* Checkov and Trivy replace Microsoft Security DevOps orchestration
* NuGet graph comparison replaces the GitHub dependency-review API
* GitLab Pages replaces GitHub Pages
* GitLab project-policy audit replaces GitHub organization policy mutation
* GitLab OIDC, Cosign, and Azure Key Vault preserve signed SLSA provenance
  before the immutable image digest reaches the deployment environment
* OpenSSF Scorecard publication remains an explicit disposition because the
  upstream service evaluates GitHub-hosted repositories
