<div align="center">

# 🤖 Agentic AI for DevSecOps: Transforming Security with GitHub Advanced Security and GitHub Copilot

[![GitHub Advanced Security](https://img.shields.io/badge/GitHub-Advanced_Security-181717?style=for-the-badge&logo=github&logoColor=white)](https://github.com/security)
[![Copilot](https://img.shields.io/badge/GitHub-Copilot-181717?style=for-the-badge&logo=github&logoColor=white)](https://github.com/features/copilot)
[![DevSecOps](https://img.shields.io/badge/DevSecOps-Enabled-success?style=for-the-badge)](https://github.com/security)

> **Agentic DevSecOps is essential for building secure AI apps and agents.**
> 
> **Transforming Security with GHAS & GHCP & MDC**
>
> **Discover how GitHub Advanced Security and DevSecOps guidelines empower teams to build, secure, and ship software faster.**

<img width="3224" height="1818" alt="Agentic AI for DevSecOps - Transforming Security with GHAS and GHCP" src="https://github.com/user-attachments/assets/5aa8b864-712a-4c52-858c-3224079e0810" />

</div>

---

## 🌟 Overview

Step into the future of DevSecOps where Agentic AI and intelligent agents like GitHub Copilot revolutionize how teams secure code. Discover how GitHub Advanced Security and GitHub Copilot Autofix embed security into developer workflows and automate vulnerability remediation. Secure Coding with GHAS and AI-powered Security Campaigns. Through live demos and practical strategies, learn to operationalize DevSecOps at scale for faster, secure software delivery.

Secure Coding & DevSecOps with GitHub Advanced Security (GHAS): End‑to‑End with GitHub Copilot features and Defender for Cloud for a complete ASPM solution. A practical, demo‑heavy journey through GHAS (Secret scanning, SCA, SAST) and how it pairs with Defender for Cloud DevOps Security and popular OSS tools to deliver an integrated DevSecOps experience.

## 🎯 Goals

<table>
<tr>
<td width="50%">

### 🤖 AI-Powered DevSecOps
Experience how Agentic AI and GitHub Copilot are transforming DevSecOps practices.

</td>
<td width="50%">

### 🔒 Security Integration
Embed security into developer workflows - Demo GitHub Advanced Security capabilities (Secret Scanning, SCA, SAST) that shift security left.

</td>
</tr>
<tr>
<td width="50%">

### 🛠️ Automated Remediation
AI-powered vulnerability remediation - Leverage Copilot Autofix and Security Campaigns to deliver context-aware fixes, reducing manual security effort for development teams.

</td>
<td width="50%">

### 📊 Enhanced Visibility
Boost visibility between security and development teams by integrating GHAS with Microsoft Defender for Cloud.

</td>
</tr>
</table>

## 💡 Key Takeaways

> **🚀 Scalable end-to-end DevSecOps blueprint** - Operationalize application security at scale while maintaining development velocity.

> **🤖 AI-powered vulnerability remediation** - Automate security fixes with GitHub Security Campaigns and GitHub Copilot Autofix to reduce manual effort.

> **📋 Reusable templates and guidelines** - Implement proven patterns for integrating GHAS into your SDLC to detect secrets, dependencies, and code vulnerabilities automatically.

> **✅ Continuous security, compliance, and monitoring are achievable with the right tools and processes.**

> **⚡ DevSecOps is essential for modern software delivery.**

> **🛡️ GitHub Advanced Security (GHAS) embeds security natively into developer workflows.**

## 📖 Documentation

For a concise overview of the shift-left security concepts, workflows, AI agents, and infrastructure patterns demonstrated in this repo, see the [DevSecOps Concepts Guide](docs/devsecops-concepts.md).

For the full deep-dive on GHAS, GitHub Copilot, and Microsoft Defender for Cloud integration, see [Agentic AI for DevSecOps — GHAS + GHCP + MDC](docs/ghas-mdc-devsecops.md).

For the L400 technical deep-dive on code-to-cloud security, see [GHAS + MDC L400 Technical Deep Dive](docs/GHAS-MDC-L400-Guide.md).

For the current Azure DevOps migration status, 19-workflow parity matrix, prerequisites, and operating procedures, see the [Azure DevOps Pipeline Migration documentation](.azuredevops/pipelines/README.md).

## 🔀 Provider Parity Matrix (GitHub · Azure DevOps · GitLab)

The same DevSecOps controls are implemented across three CI providers. GitHub Actions is the canonical source (`.github/workflows`), Azure DevOps mirrors it under `.azuredevops/pipelines`, and GitLab CI mirrors it under `.gitlab/ci`. Each cell notes the provider-specific implementation.

> [!NOTE]
> GitLab jobs run on the self-hosted runner fleet on AKS HCI `workload-cluster-002` (job tags `aks-hci, cluster-002, linux`) to avoid shared-runner minutes. That executor is non-privileged (no `docker:dind`), so container images are built remotely with `az acr build` and scanned by registry reference against `devopsabcs.azurecr.io`.

| Capability (source workflow) | GitHub Actions | Azure DevOps | GitLab CI (cluster-002) |
| --- | --- | --- | --- |
| Build & test (`ci.yml`) | `actions/setup-dotnet` restore/build/publish; `docker/build-push-action` builds the image | `DotNetCoreCLI@2` restore/build/publish; Docker task builds `$(Build.SourceVersion)` | `ci:dotnet-build` on the .NET SDK image; `ci:container-build` builds via `az acr build` (no dind), pushing `:$CI_COMMIT_SHA` + `:latest` |
| Deploy pipeline (`cicd.yml`) | `azure/login` OIDC + Bicep + `az acr build` + Cosign sign/attest + web-app deploy | Workload-identity service connection + Bicep + `New-SlsaProvenance`/`Sign-And-AttestImage`/`Verify-ImageEvidence`, deploy by digest | `cicd:*` jobs, OIDC `id_tokens`, `az acr build` to the deployment ACR, Cosign sign+attest+verify, `az webapp` deploy |
| SAST — CodeQL (`SAST-GitHubAdvancedSecurity-CodeQL.yml`) | Native `github/codeql-action` init/analyze (csharp, javascript, python) | GHAzDO `AdvancedSecurity-Codeql-Init@1`/`Analyze@1` language matrix | `sast:semgrep-codeql-replacement` (Semgrep) → GitLab SAST report + SARIF (CodeQL is GitHub-only) |
| SAST — ESLint (`SAST-ESLint.yml`) | ESLint + `@microsoft/eslint-formatter-sarif` → `upload-sarif` | ESLint via script → SARIF Scans tab | `sast:eslint` on the Node image → SARIF artifact |
| IaC — tfsec (`IACS-AquaSecurity-tfsec.yml`) | `aquasecurity/tfsec-sarif-action` | tfsec container image via PowerShell → SARIF | `iac:tfsec` runs the `aquasec/tfsec` image directly as the job image (no dind) |
| IaC — KICS (`IACS-Checkmarx-kics.yml`) | `Checkmarx/kics-github-action` | KICS container image via script | `iac:kics` runs the `checkmarx/kics` image directly |
| IaC — MSDO (`IACS-Microsoft-Security-DevOps.yml`) | `microsoft/security-devops-action` (IaC categories) | `MicrosoftSecurityDevOps@1` `categories: IaC` + `AdvancedSecurity-Publish@1` | `iac:msdo-replacement` runs Checkov over terraform/bicep/kubernetes |
| Multi-tool MSDO (`MSDO-Microsoft-Security-DevOps.yml`) | `microsoft/security-devops-action` (bandit, checkov, templateanalyzer, terrascan, trivy) | `MicrosoftSecurityDevOps@1` on Windows, same toolset + publish | `security:msdo-replacement` runs Checkov (all) + Trivy filesystem (pinned binary) |
| Container scan — Grype (`CIS-Anchore-Grype.yml`) | `anchore/scan-action` on the built image | Grype container image via script | `container:grype` builds via `az acr build`, scans the ACR image with a pinned Grype binary (OIDC to `devopsabcs`) |
| Container scan — Trivy (`CIS-Trivy-AquaSecurity.yml`) | `aquasecurity/trivy-action` | Trivy container image via script | `container:trivy` scans the ACR image ref; emits GitLab `container_scanning` report + SARIF |
| DAST — OWASP ZAP (`DAST-ZAP-Zed-Attach-Proxy-Checkmarx.yml`) | `zaproxy/action-full-scan` / baseline | `Invoke-ZapScan.ps1` builds + runs the app container and ZAP via Docker | `dast:zap` runs the self-contained app inside the pinned ZAP image and drives `zap.sh -autorun` over loopback (no dind) |
| K8s manifests — Kubesec (`SAST-Kubesec.yml`) | `controlplaneio/kubesec-action` + `upload-sarif` | Kubesec container + `Convert-KubesecToSarif.ps1` | `sast:kubesec` pinned Kubesec binary + `Convert-KubesecToSarif.ps1` |
| SBOM — Syft (`SCA-Anchore-Syft-SBOM.yml`) | `anchore/sbom-action` | Syft container via script | `supply-chain:syft-sbom` scans the ACR image with a pinned Syft binary → SPDX + CycloneDX |
| Dependency review (`SCA-GitHubAdvancedSecurity-DependencyReview.yml`) | `actions/dependency-review-action` | `AdvancedSecurity-Dependency-Scanning@1` + resolved-graph admission + PR comment | `supply-chain:dependency-review` resolved NuGet graph admission (`Get-ResolvedNuGetGraph`/`Test-DependencyChanges`) |
| SBOM — Microsoft (`SCA-Microsoft-SBOM.yml`) | `sbom-tool` download + generate | `sbom-tool` via script from a deterministic publish drop | `supply-chain:microsoft-sbom` downloads the SHA-pinned `sbom-tool` + generate |
| OpenSSF Scorecard (`SCA-OpenSSF-Scorecard.yml`) | `ossf/scorecard-action` → code scanning | Platform-gap disposition (no non-GitHub publisher) | `supply-chain:openssf-scorecard-disposition` records a disposition JSON (Scorecard publishes only for GitHub) |
| Governance policy (`enforce-ghas-policy.yml`) | `enforce-ghas-policy.ps1` (GHAS enablement) | `Initialize-PipelineGovernance`/`Test-PipelineGovernance` | `governance:gitlab-policy` audits protected branches/approval rules via `glab api` |
| AI security agent (`security-agent-workflow.yml`) | `setup-node` + Copilot CLI agent report | Copilot CLI via script (manual) | `security-agent:assessment` Copilot CLI (manual/web) |
| Static site / docs (`static.yml`) | `actions/jekyll-build-pages` + Pages deploy | `docs-static.yml` publishes to the project wiki | `pages` publishes `docs/` to GitLab Pages; `docs:gitlab-wiki` publishes the wiki via `Publish-DocumentationWiki.ps1` |

### Cross-cutting platform mechanics

| Concern | GitHub Actions | Azure DevOps | GitLab CI (cluster-002) |
| --- | --- | --- | --- |
| Compute | GitHub-hosted runners | Microsoft-hosted agents (+ GHAzDO tasks) | Self-hosted Kubernetes executor on `workload-cluster-002`, non-privileged, tags `aks-hci, cluster-002, linux` |
| Azure identity | OIDC app registration in the deployment tenant | Workload-identity service connections per pipeline | OIDC `id_tokens`: deployment app (`gitlab-gh-advsec-devsecops`) for Azure deploy + dedicated ACR app (`gitlab-acr-gh-advsec-devsecops`) for `devopsabcs` |
| Container build | `docker/build-push-action` | Docker task on the hosted agent | `az acr build` (remote, rootless — no daemon or privileged mode) |
| Findings surface | Code scanning / Security tab (SARIF), per-tool breakdown | Advanced Security + SARIF Scans tab | SARIF artifacts per job **+** the `security:summary` per-tool breakdown on GitLab Pages and the project Wiki **+** a Code Quality report in the MR (see below) |
| Scheduled scans | Workflow `schedule:` crons | Pipeline `schedules` + `always: true` | Pipeline schedules set `SCAN_PROFILE`; all run on the self-hosted fleet |

### Security findings visibility (SARIF & the tool breakdown)

GitHub's Code scanning view groups every alert by the tool that produced it (CodeQL, Trivy, Grype, KICS, Checkov, ZAP, …) because GitHub Advanced Security ingests each tool's **SARIF** and aggregates it. GitLab does **not** ingest SARIF into its security UI — it consumes its own report JSON (`artifacts:reports:*`), and the equivalent aggregated views (the **Vulnerability Report** and **Security Dashboard**, filterable by scanner) require the **GitLab Ultimate** tier.

This project runs on a **non-Ultimate** GitLab plan, so the tool breakdown is reproduced without those features:

| GitHub view | GitLab equivalent here | Tier | Where |
| --- | --- | --- | --- |
| Code scanning, filter by tool | `security:summary` per-tool breakdown table (Markdown + HTML) | All tiers | GitLab Pages at `/security`, the project Wiki page `Documentation/Security-Findings-Summary`, and the job artifact `security-results/summary/` |
| PR inline alert annotations | **Code Quality** report merged from all SARIF | All tiers | MR diff annotations + the MR **Code Quality** widget |
| Raw SARIF per tool | Job artifacts | All tiers | `security-results/<tool>/*.sarif` on every scan job |
| Security Dashboard / Vulnerability Report | Native (not enabled) | Ultimate only | — |

**How it works.** [scripts/sarif/New-SecuritySummary.ps1](scripts/sarif/New-SecuritySummary.ps1) walks every `*.sarif` produced under `security-results/`, counts results per tool and per severity (a numeric `security-severity` takes precedence over the SARIF `level`), and writes:

- `security-results/summary/index.html` — a self-contained per-tool breakdown page published to **GitLab Pages** under `/security` by the `pages` job, mirroring GitHub's tool breakdown.
- `security-results/summary/summary.md` / `summary.json` — the same data as Markdown and machine-readable JSON artifacts. On `main` pushes the `docs:gitlab-wiki` job also publishes `summary.md` to the project Wiki as `Documentation/Security-Findings-Summary`.
- `security-results/summary/gl-code-quality-report.json` — a GitLab **Code Quality** report (published via `artifacts:reports:codequality`). Code Quality is available on every tier, so findings that resolve to a repository file appear **inline in the merge request diff** and in the MR Code Quality widget. Findings without a repository file (for example container-image CVEs from Grype/Trivy) are still counted in the breakdown but excluded from inline annotations.

The `security:summary` job runs on merge requests to `main`, on `main` pushes, and on scheduled scans, using `needs: [...] optional: true` so it aggregates whatever scanners ran in that pipeline. Individual tools also emit GitLab-native reports where they can (`sast:semgrep-codeql-replacement` → `reports:sast`, `container:trivy` → `reports:container_scanning`); those additionally populate the native Vulnerability Report **if** the project is ever upgraded to Ultimate, with no pipeline changes required.

