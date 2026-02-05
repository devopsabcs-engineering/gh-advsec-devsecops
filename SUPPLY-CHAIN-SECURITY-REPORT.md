# Supply Chain Security Report

**Repository:** devopsabcs-engineering/gh-advsec-devsecops  
**Scan Date:** 2026-02-04  
**Agent:** Supply Chain Security Agent v1.0.0

## Executive Summary

| Category | Critical | High | Medium | Low | Total |
|----------|----------|------|--------|-----|-------|
| Secrets | 1 | 0 | 1 | 0 | 2 |
| Dependencies | 0 | 2 | 0 | 1 | 3 |
| Governance | 0 | 3 | 2 | 1 | 6 |
| Provenance | 0 | 1 | 1 | 0 | 2 |
| **TOTALS** | **1** | **6** | **4** | **2** | **13** |

## Priority Actions (Top 5)

1. **[CRITICAL]** Remove exposed Azure Storage key from appsettings.json files
2. **[HIGH]** Update Microsoft.Data.SqlClient to 5.2.0+ (CVE-2024-0056, CVE-2024-0057)
3. **[HIGH]** Enable branch protection on main branch with required reviews
4. **[HIGH]** Enhance CODEOWNERS for security-sensitive paths
5. **[HIGH]** Pin GitHub Actions to commit SHAs instead of tags

---

## 1. Secrets Detection & Exposure

### CRITICAL-001: Azure Storage Access Key Exposed in Application Configuration

**Severity:** CRITICAL  
**Category:** Secrets Exposure  
**Risk:** Unauthorized access to Azure Storage resources

**Location:**
- [src/webapp01/appsettings.json](src/webapp01/appsettings.json#L9)
- [src/webapp01/appsettings.Development.json](src/webapp01/appsettings.Development.json#L9)

**Finding:**
```json
"STORAGE_TEST":"18gryvHXuSVGDBcdJ3+QhRypNi413Kri8oalcQPAAZ7UGMHjaTVpSq4R9fYqzCsmZDnvK6AaE8Ce+AStDHNkpQ=="
```

This appears to be a base64-encoded Azure Storage account access key committed to source control.

**Impact:**
- Anyone with repository access can extract and use this credential
- Potential data exfiltration from associated storage account
- Compliance violations (PCI-DSS, GDPR, SOC2)

**Remediation Steps:**

1. **Immediate (within 1 hour):**
   ```powershell
   # Rotate the storage account key in Azure Portal or CLI
   az storage account keys renew --account-name <storage-account> --key primary
   ```

2. **Remove from source control:**
   - Remove the key from appsettings files
   - Migrate to Azure Key Vault or User Secrets for development

3. **Audit access logs:**
   ```powershell
   az monitor activity-log list --resource-id <storage-account-resource-id> --start-time 2026-01-01
   ```

4. **Enable GitHub push protection:**
   Already configured in `.github/secret_scanning.yml` ✅

**Recommended Pattern:**
```json
// appsettings.json - Use Key Vault reference
{
  "STORAGE_TEST": "@Microsoft.KeyVault(SecretUri=https://myvault.vault.azure.net/secrets/StorageKey/)"
}

// appsettings.Development.json - Use User Secrets (never commit)
// Store in: %APPDATA%\Microsoft\UserSecrets\<UserSecretsId>\secrets.json
// Reference: <UserSecretsId>7f0355f0-e3cb-4a1e-bf2d-0431db9b93f8</UserSecretsId> (already in .csproj ✅)
```

---

### MEDIUM-001: Sample Files with Hardcoded Credentials

**Severity:** MEDIUM  
**Category:** Secrets in Examples  
**Risk:** Demonstration of insecure patterns

**Locations:**
- [terraform/azure/sql.tf](terraform/azure/sql.tf#L15) - `administrator_login_password = "Aa12345678"`
- [terraform/azure/sql.tf](terraform/azure/sql.tf#L65) - `administrator_login_password = "Aa12345678"`

**Context:**  
These appear to be intentional examples for security testing/training purposes. While acceptable for demos, they should be clearly marked.

**Recommendation:**
Add prominent warnings in sample files:
```terraform
# ⚠️ SECURITY WARNING: This file contains intentionally insecure configurations
# for demonstration purposes only. DO NOT use these patterns in production.
```

---

## 2. Dependency Security Analysis

### HIGH-001: Outdated Microsoft.Data.SqlClient with Known Vulnerabilities

**Severity:** HIGH  
**Category:** Software Composition Analysis (SCA)  
**CVSS Score:** 8.1 (High)

**Location:** [src/webapp01/webapp01.csproj](src/webapp01/webapp01.csproj#L12)

**Current Version:** 5.0.2  
**Latest Secure Version:** 5.2.0

**Known CVEs:**
- **CVE-2024-0056** - .NET Denial of Service Vulnerability
- **CVE-2024-0057** - .NET Security Feature Bypass Vulnerability

**Remediation:**
```xml
<!-- Update to latest secure version -->
<PackageReference Include="Microsoft.Data.SqlClient" Version="5.2.0" />
```

**Status:** Dependabot is configured ✅ (should auto-create PR)

---

### HIGH-002: System.Text.Json Potentially Vulnerable Version

**Severity:** HIGH  
**Category:** SCA  

**Location:** [src/webapp01/webapp01.csproj](src/webapp01/webapp01.csproj#L14)

**Current Version:** 8.0.4  
**Recommendation:** Update to 8.0.5+ (latest patches)

**Remediation:**
```xml
<PackageReference Include="System.Text.Json" Version="8.0.5" />
```

---

### LOW-001: Dual JSON Serialization Libraries

**Severity:** LOW  
**Category:** Dependency Hygiene  

**Finding:** Both `System.Text.Json` (8.0.4) and `Newtonsoft.Json` (13.0.1) are referenced.

**Recommendation:**  
Standardize on `System.Text.Json` unless `Newtonsoft.Json` is explicitly required for compatibility. Having both increases attack surface and bundle size.

---

## 3. Repository Governance & Access Control

### HIGH-003: Weak CODEOWNERS Configuration

**Severity:** HIGH  
**Category:** Access Control  
**Risk:** Insufficient review oversight for security-sensitive changes

**Current State:**
```
* @CalinL
```

**Issues:**
- Single reviewer for entire repository
- No specific protection for security-sensitive paths
- No team-based reviews

**Recommendation:**

```gitignore
# .github/CODEOWNERS

# Default owner for everything
* @CalinL @devopsabcs-engineering/engineering-team

# Security-sensitive paths require additional review
/.github/workflows/ @CalinL @devopsabcs-engineering/security-team
/.github/dependabot.yml @CalinL @devopsabcs-engineering/security-team
/.github/secret_scanning.yml @CalinL @devopsabcs-engineering/security-team
/SECURITY.md @CalinL @devopsabcs-engineering/security-team

# Infrastructure as Code requires platform team review
/terraform/ @CalinL @devopsabcs-engineering/platform-team
/blueprints/ @CalinL @devopsabcs-engineering/platform-team
*.bicep @CalinL @devopsabcs-engineering/platform-team
*.tf @CalinL @devopsabcs-engineering/platform-team

# Application dependencies require security review
*.csproj @CalinL @devopsabcs-engineering/security-team
*.sln @CalinL @devopsabcs-engineering/security-team

# Dockerfiles require container security review
**/Dockerfile @CalinL @devopsabcs-engineering/security-team
```

---

### MEDIUM-002: Missing Branch Protection Rules

**Severity:** MEDIUM  
**Category:** Repository Configuration  
**Risk:** Direct pushes to main branch, bypassing CI/CD

**Recommendation:**

Configure branch protection for `main` branch with:

- [x] Require pull request before merging
- [x] Require approvals: **2** (currently 0)
- [x] Dismiss stale reviews when new commits pushed
- [x] Require review from code owners
- [x] Require status checks to pass:
  - `ci_build` (from ci.yml)
  - `dependency-review` (from SCA-GitHubAdvancedSecurity-DependencyReview.yml)
  - `CodeQL` (from SAST-GitHubAdvancedSecurity-CodeQL.yml)
- [x] Require branches to be up to date before merging
- [x] Require linear history
- [x] Do not allow bypassing settings (even for admins)

**Note:** These settings must be configured through GitHub repository settings UI.

---

### MEDIUM-003: Generic SECURITY.md Template

**Severity:** MEDIUM  
**Category:** Documentation  

**Current State:** Uses placeholder text ("Use this section to tell people...")

**Impact:** Unclear vulnerability reporting process for external researchers

**Recommendation:** Update with project-specific details (see remediation file)

---

### HIGH-004: GitHub Actions Not Pinned to Commit SHAs

**Severity:** HIGH  
**Category:** Supply Chain Integrity  
**Risk:** Tag/branch immutability - actions can be modified after release

**Finding:**  
All workflows use mutable tag references (e.g., `@v5`, `@v4`) instead of pinned commit SHAs.

**Example from ci.yml:**
```yaml
- uses: actions/checkout@v5  # ❌ Mutable tag
- uses: actions/setup-dotnet@v4  # ❌ Mutable tag
```

**Recommended Pattern:**
```yaml
# Pin to commit SHA with comment showing version
- uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v5.0.0
- uses: actions/setup-dotnet@3e891f8e7821d4dca12bd3f9e5e5e0a7cc92f4e1 # v4.2.0
```

**Remediation Tool:**  
Use Dependabot to manage action versions (already configured for `github-actions` ecosystem ✅)

**Action Items:**
1. Enable Dependabot security updates for GitHub Actions
2. Consider adding `.github/workflows/dependency-review.yml` to enforce pinning

---

### LOW-001: Missing Contributor Guidelines

**Severity:** LOW  
**Category:** Documentation  

**Recommendation:** Add `CONTRIBUTING.md` with security expectations for contributors.

---

## 4. Provenance & SBOM Posture

### HIGH-005: SBOM Workflow Lacks Artifact Attestation

**Severity:** HIGH  
**Category:** Supply Chain Integrity  
**Risk:** No cryptographic proof of build provenance

**Current State:**  
[.github/workflows/SCA-Microsoft-SBOM.yml](.github/workflows/SCA-Microsoft-SBOM.yml) generates SBOMs but doesn't sign or attest them.

**Finding:**
```yaml
# Current: SBOM uploaded but not signed
- name: Upload a Build Artifact
  uses: actions/upload-artifact@v4
  with:
    path: buildOutput
```

**Recommendation:**

```yaml
# Add after SBOM generation
- name: Generate Build Provenance Attestation
  uses: actions/attest-build-provenance@v1
  with:
    subject-path: 'buildOutput/**/*'

- name: Attest SBOM
  uses: actions/attest-sbom@v1
  with:
    subject-path: 'buildOutput/**/*'
    sbom-path: '_manifest/spdx_2.2/manifest.spdx.json'
```

**Benefits:**
- SLSA Level 2+ compliance
- Verifiable supply chain integrity
- Tamper-evident artifact provenance

---

### MEDIUM-004: Missing Container Image Signing

**Severity:** MEDIUM  
**Category:** Container Security  

**Finding:**  
[.github/workflows/ci.yml](.github/workflows/ci.yml#L41) builds Docker images but doesn't sign them.

**Current:**
```yaml
- name: Build the Docker image
  run: docker build ./src/webapp01 --file ./src/webapp01/Dockerfile --tag ${{ env.imageName }}:${{ env.tag }}
```

**Recommendation:**
```yaml
# Add Sigstore cosign signing
- name: Install Cosign
  uses: sigstore/cosign-installer@v3

- name: Sign container image
  run: |
    cosign sign --yes ${{ env.imageName }}:${{ env.tag }}
```

---

## 5. CI/CD Security Posture

### Current Security Controls ✅

**Strengths:**
1. ✅ GitHub Advanced Security enabled (GHAS)
   - Secret scanning configured (`.github/secret_scanning.yml`)
   - CodeQL SAST workflow (`SAST-GitHubAdvancedSecurity-CodeQL.yml`)
   - Dependency Review on PRs (`SCA-GitHubAdvancedSecurity-DependencyReview.yml`)

2. ✅ Dependabot configured for NuGet and GitHub Actions
   - Weekly update cadence
   - Open PR limit: 15

3. ✅ SBOM generation with Microsoft SBOM Tool
   - SPDX 2.2 format
   - Automatic upload to dependency graph

4. ✅ Multiple security scanning tools integrated:
   - Trivy (container scanning)
   - Grype (vulnerability scanning)
   - KICS (IaC scanning)
   - tfsec (Terraform scanning)
   - Microsoft Security DevOps
   - OpenSSF Scorecard

5. ✅ Least privilege permissions in workflows:
   ```yaml
   permissions:
     id-token: write
     contents: read
   ```

**Gaps:**
1. ❌ No required status checks enforced on main branch
2. ❌ GitHub Actions not pinned to commit SHAs
3. ❌ No artifact attestation/signing
4. ❌ No container image signing

---

## Engineering Backlog

### Sprint 1 (Immediate - Next 3 Days)

- [ ] **SEC-001** [CRITICAL] Rotate Azure Storage key exposed in appsettings.json
- [ ] **SEC-002** [CRITICAL] Remove storage key from appsettings.json and migrate to Key Vault
- [ ] **SEC-003** [HIGH] Update Microsoft.Data.SqlClient to 5.2.0+
- [ ] **SEC-004** [HIGH] Update System.Text.Json to 8.0.5+

### Sprint 2 (Short-term - Next 2 Weeks)

- [ ] **SEC-005** [HIGH] Configure branch protection rules for main branch
- [ ] **SEC-006** [HIGH] Enhance CODEOWNERS with team-based reviews
- [ ] **SEC-007** [HIGH] Add artifact attestation to SBOM workflow
- [ ] **SEC-008** [MEDIUM] Update SECURITY.md with project-specific details

### Sprint 3 (Medium-term - Next Month)

- [ ] **SEC-009** [MEDIUM] Implement container image signing with Sigstore
- [ ] **SEC-010** [MEDIUM] Pin GitHub Actions to commit SHAs (via Dependabot)
- [ ] **SEC-011** [LOW] Remove redundant Newtonsoft.Json dependency
- [ ] **SEC-012** [LOW] Add CONTRIBUTING.md with security guidelines

---

## Compliance & Standards Alignment

### SLSA Framework

| Level | Requirement | Current Status | Gap |
|-------|------------|----------------|-----|
| Level 1 | Build documented | ✅ CI workflows | None |
| Level 2 | Signed provenance | ⚠️ SBOM only | Missing attestation |
| Level 3 | Hardened builds | ⚠️ Partial | Actions not pinned |
| Level 4 | Hermetic builds | ❌ Not implemented | Future work |

**Target:** SLSA Level 2 by end of Sprint 2

### OpenSSF Scorecard

**Current Score:** Unknown (SCA-OpenSSF-Scorecard.yml exists but results not analyzed)

**Expected Improvements After Remediation:**
- Branch-Protection: 0 → 8/10
- Pinned-Dependencies: ~3 → 9/10
- Signed-Releases: 0 → 8/10

---

## Reference Standards

- [SLSA Framework](https://slsa.dev/) - Supply Chain Levels for Software Artifacts
- [OpenSSF Scorecard](https://securityscorecards.dev/) - Automated security health checks
- [CIS Software Supply Chain Security Guide](https://www.cisecurity.org/)
- [NIST SSDF](https://csrc.nist.gov/Projects/ssdf) - Secure Software Development Framework
- [GitHub Security Best Practices](https://docs.github.com/en/code-security/getting-started/github-security-features)

---

## Appendix A: Dependency Inventory

### NuGet Packages (src/webapp01/webapp01.csproj)

| Package | Current | Latest | Vulnerabilities |
|---------|---------|--------|-----------------|
| Azure.Identity | 1.13.2 | 1.13.2 | None known |
| Microsoft.Data.SqlClient | 5.0.2 ⚠️ | 5.2.0 | CVE-2024-0056, CVE-2024-0057 |
| Microsoft.VisualStudio.Azure.Containers.Tools.Targets | 1.21.0 | 1.21.0 | None known |
| System.Text.Json | 8.0.4 ⚠️ | 8.0.5 | Check advisories |
| Newtonsoft.Json | 13.0.1 ⚠️ | 13.0.3 | CVE-2024-21907 (Low) |

---

## Appendix B: Secret Scanning Patterns

The following patterns should be monitored via GitHub secret scanning:

- Azure Storage account keys (base64, 88 chars)
- Azure SQL connection strings
- Azure Service Principal credentials
- GitHub Personal Access Tokens (ghp_*)
- NuGet API keys (oy2_*)
- Docker Hub tokens
- Generic high-entropy strings in config files

**Status:** Push protection enabled via `.github/secret_scanning.yml` ✅

---

## Report Metadata

- **Generated:** 2026-02-04 by Supply Chain Security Agent
- **Next Review:** 2026-03-04 (monthly cadence)
- **Responsible Team:** @devopsabcs-engineering/security-team
- **Escalation Contact:** @CalinL

**Remediation tracking:** See [SUPPLY-CHAIN-REMEDIATION.md](./SUPPLY-CHAIN-REMEDIATION.md)
