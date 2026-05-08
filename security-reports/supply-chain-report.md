# Supply Chain Security Report - webapp01

**Generated:** May 8, 2026  
**Scope:** `src/webapp01/`  
**Ecosystem:** .NET 9.0

## Executive Summary

**Total Findings:** 11  
**Critical:** 3  
**High:** 4  
**Medium:** 3  
**Low:** 1

The webapp01 application presents **critical supply chain security risks** requiring immediate remediation. Three hardcoded secrets were discovered in production configuration files and source code. The project lacks a dependency lockfile, preventing reproducible builds. Multiple NuGet packages require updates to address known vulnerabilities.

---

## 1. Secrets Detection

### Critical Findings

| Severity | File | Line | Pattern | Recommendation | Status |
|----------|------|------|---------|----------------|--------|
| **CRITICAL** | [appsettings.json](../src/webapp01/appsettings.json#L9) | 9 | Azure Storage Key | Rotate immediately, use Azure Key Vault | 🔴 ACTIVE |
| **CRITICAL** | [appsettings.json](../src/webapp01/appsettings.json#L10) | 10 | GitHub Token (custom format) | Rotate immediately, use GitHub Secrets or Key Vault | 🔴 ACTIVE |
| **CRITICAL** | [appsettings.Development.json](../src/webapp01/appsettings.Development.json#L8) | 8 | Azure Storage Key (duplicate) | Remove, use User Secrets for development | 🔴 ACTIVE |

### High Severity

| Severity | File | Line | Pattern | Recommendation | Status |
|----------|------|------|---------|----------------|--------|
| **HIGH** | [Pages/DevSecOps.cshtml.cs](../src/webapp01/Pages/DevSecOps.cshtml.cs#L15) | 15 | SQL Connection String with Password | Move to configuration with Key Vault reference | 🔴 ACTIVE |
| **HIGH** | [Pages/Index.cshtml.cs](../src/webapp01/Pages/Index.cshtml.cs#L11) | 11 | Hardcoded Default Password | Remove constant, implement secure password policy | 🔴 ACTIVE |

### Secret Details

#### 1. Azure Storage Account Key (STORAGE_TEST)
- **Location:** `appsettings.json:9`, `appsettings.Development.json:8`
- **Pattern:** Base64-encoded 88-character string (Azure Storage Key signature)
- **Value Preview:** `18gr***pQ==` (masked)
- **Risk:** Complete storage account compromise, data exfiltration, unauthorized access
- **Remediation:**
  1. Rotate the storage account key immediately via Azure Portal
  2. Implement Azure Key Vault reference: `@Microsoft.KeyVault(SecretUri=...)`
  3. Configure Managed Identity for the App Service
  4. Remove hardcoded value from all configuration files

#### 2. Custom Token (CUSTOM_TEST)
- **Location:** `appsettings.json:10`
- **Pattern:** `githubabcs_token_` prefix followed by 64-character alphanumeric string
- **Value Preview:** `gith***Z` (masked)
- **Risk:** GitHub API access, potential repository compromise
- **Remediation:**
  1. Revoke token immediately via GitHub Settings > Developer Settings > Personal Access Tokens
  2. Use Azure Key Vault or GitHub Actions Secrets for CI/CD workflows
  3. Implement short-lived tokens with minimal scopes

#### 3. SQL Connection String
- **Location:** `Pages/DevSecOps.cshtml.cs:15`
- **Credentials:** `User Id=admin;Password=Secr***!` (masked)
- **Risk:** Database unauthorized access, SQL injection opportunities
- **Remediation:**
  1. Move connection string to `appsettings.json` or User Secrets
  2. Reference Azure Key Vault for production credentials
  3. Use Azure AD authentication instead of SQL authentication

#### 4. Default Password Constant
- **Location:** `Pages/Index.cshtml.cs:11`
- **Value:** `Pass@word1` (developer comment indicates awareness this is insecure)
- **Risk:** Predictable credentials, potential authentication bypass
- **Remediation:**
  1. Remove hardcoded password constant
  2. Implement secure password generation
  3. Enforce password complexity policies

---

## 2. Dependency Vulnerabilities (SCA)

### Missing Lockfile - HIGH SEVERITY
❌ **No `packages.lock.json` found**

- **Risk:** Non-reproducible builds, supply chain attacks, version drift
- **Impact:** Different developers and CI/CD pipelines may resolve different package versions
- **Recommendation:** Enable Central Package Management and lockfile generation:

```xml
<!-- Add to webapp01.csproj -->
<PropertyGroup>
  <RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>
  <RestoreLockedMode Condition="'$(CI)' == 'true'">true</RestoreLockedMode>
</PropertyGroup>
```

### Package Analysis

| Package | Current Version | Latest Version | Severity | CVE | Status | Recommendation |
|---------|----------------|----------------|----------|-----|--------|----------------|
| **Microsoft.Data.SqlClient** | 5.0.2 | 5.2.1 | **HIGH** | CVE-2024-0056 | Outdated (March 2023) | Upgrade to 5.2.1+ |
| **Newtonsoft.Json** | 13.0.1 | 13.0.3 | **MEDIUM** | - | Minor lag | Upgrade to 13.0.3 |
| **System.Text.Json** | 8.0.4 | 9.0.0 | **MEDIUM** | - | Minor version behind | Upgrade to 9.0.x (align with .NET 9) |
| **Azure.Identity** | 1.13.2 | 1.14.0 | **LOW** | - | One version behind | Upgrade to 1.14.0 |
| Microsoft.VisualStudio.Azure.Containers.Tools.Targets | 1.21.0 | Latest | **INFO** | - | Dev dependency | Check for updates periodically |

### Critical Package Issues

#### Microsoft.Data.SqlClient 5.0.2
- **Published:** March 2023 (over 2 years old as of May 2026)
- **Known Issues:** 
  - CVE-2024-0056: Security Feature Bypass Vulnerability
  - Performance improvements in newer versions
  - Bug fixes for connection pooling
- **Action Required:** Upgrade to **5.2.1 or later**
- **Breaking Changes:** Review [migration guide](https://github.com/dotnet/SqlClient/blob/main/release-notes/5.2/5.2.0.md)

#### Newtonsoft.Json 13.0.1
- **Current:** 13.0.1 (December 2021)
- **Latest:** 13.0.3 (March 2023)
- **Changes:** Security and stability improvements
- **Action:** Upgrade to 13.0.3 (backward compatible)

### Dependabot Configuration - ✅ ACTIVE

Dependabot is properly configured for this project:
- **Ecosystem:** NuGet ✅
- **Directory:** `/src/webapp01/` ✅
- **Schedule:** Weekly ✅
- **PR Limit:** 15 ✅

**Status:** Dependabot should automatically detect outdated packages. Verify alerts in the Security tab.

---

## 3. SBOM (Software Bill of Materials)

### Current Status

✅ **SBOM Generation Workflow Exists:** `.github/workflows/SCA-Microsoft-SBOM.yml`  
✅ **Format:** SPDX 2.2 (industry standard)  
⚠️ **Location:** Build artifacts only (not versioned)

### Workflow Configuration

The SBOM workflow is properly configured:
- **Tool:** Microsoft SBOM Tool (sbom-tool)
- **Trigger:** Push to `main` branch
- **Output:** `buildOutput/_manifest/spdx_2.2/`
- **Upload:** GitHub Dependency Graph via `spdx-dependency-submission-action`

### Recommendations

| Priority | Recommendation | Rationale |
|----------|---------------|-----------|
| **MEDIUM** | Archive SBOM artifacts for release versions | Enable compliance audits and historical tracking |
| **MEDIUM** | Add SBOM validation step | Verify completeness before upload |
| **LOW** | Generate CycloneDX format as alternative | Some tools prefer CycloneDX over SPDX |

### SBOM Completeness Assessment

Without access to generated SBOM artifacts, manual verification required:
- ✅ Direct dependencies likely covered
- ❓ Transitive dependencies (verify in actual SBOM)
- ❓ Container base image packages (if Dockerfile-based SBOM included)

**Action:** Review latest SBOM artifact from GitHub Actions to verify:
1. All 5 NuGet packages are listed
2. Transitive dependencies are included
3. License information is complete

---

## 4. License Compliance

### Dependency License Summary

| Package | Version | License | Policy Status | Notes |
|---------|---------|---------|---------------|-------|
| Azure.Identity | 1.13.2 | MIT | ✅ Allowed | Microsoft package |
| Microsoft.Data.SqlClient | 5.0.2 | MIT | ✅ Allowed | Microsoft package |
| Microsoft.VisualStudio.Azure.Containers.Tools.Targets | 1.21.0 | Proprietary/MIT | ⚠️ Review | Dev-time only |
| System.Text.Json | 8.0.4 | MIT | ✅ Allowed | Microsoft package |
| Newtonsoft.Json | 13.0.1 | MIT | ✅ Allowed | Community package, JSON.NET |

### Third-Party Component Licenses (wwwroot/lib)

| Component | License | Policy Status |
|-----------|---------|---------------|
| Bootstrap 5.x | MIT | ✅ Allowed |
| jQuery | MIT | ✅ Allowed |
| jQuery Validation | MIT | ✅ Allowed |
| jQuery Validation Unobtrusive | Apache 2.0 | ✅ Allowed |

### License Policy Assessment

✅ **All Clear** - No GPL/AGPL copyleft licenses detected  
✅ **MIT/Apache 2.0** - Compatible with proprietary projects  
⚠️ **Missing:** Formal LICENSE file in `src/webapp01/` subdirectory (root has LICENSE)

**Recommendation:** No license issues identified. All dependencies use permissive licenses.

---

## 5. Repository Governance

### GitHub Advanced Security (GHAS) Status

| Feature | Status | Configuration |
|---------|--------|---------------|
| **Secret Scanning** | ❓ Unknown | Verify in repo Security Settings |
| **Push Protection** | ❓ Unknown | Recommended: Enable |
| **Dependabot Alerts** | ✅ Enabled | Configured for NuGet |
| **Dependabot Security Updates** | ✅ Enabled | Auto-PRs for vulnerabilities |
| **Dependency Review** | ❓ Unknown | Verify enforcement on PRs |
| **Code Scanning (CodeQL)** | ✅ Exists | Workflow: `SAST-GitHubAdvancedSecurity-CodeQL.yml` |

### Branch Protection

**Status:** ❓ Requires manual verification in repository settings

**Recommended Rules for `main` branch:**
- ✅ Require pull request reviews (minimum 1 approver)
- ✅ Require status checks (security scans, build)
- ✅ Require branches to be up to date before merging
- ✅ Require conversation resolution
- ⚠️ Consider: Require signed commits

### Code Owners

✅ **CODEOWNERS File Exists:** `.github/CODEOWNERS` (repository root)

**Action Required:** Verify webapp01 paths are covered in CODEOWNERS

### Security Policy

✅ **SECURITY.md Exists:** Root-level security policy present

**Recommendation:** Update SECURITY.md with actual supported versions and vulnerability reporting process (current content is template boilerplate)

### .gitignore Coverage

⚠️ **CRITICAL GAP IDENTIFIED**

**Missing Patterns:**
- `.env` files (not excluded)
- `.env.local`, `.env.development`, `.env.production` (not excluded)
- `appsettings.*.json` files (not excluded - **secrets currently committed!**)

**Current .gitignore:** Covers build artifacts, Visual Studio files, but **does not exclude sensitive configuration files**

**Immediate Action Required:** Add to `.gitignore`:
```gitignore
# Sensitive configuration files
**/.env
**/.env.*
**/appsettings.Development.json
**/appsettings.Production.json
**/appsettings.Staging.json

# User secrets (already gitignored via .vs/)
**/secrets.json
```

---

## 6. Dockerfile Security Assessment

### Base Image Analysis

```dockerfile
FROM mcr.microsoft.com/dotnet/aspnet:9.0 AS base
FROM mcr.microsoft.com/dotnet/sdk:9.0 AS build
```

✅ **Official Microsoft Images**  
✅ **Latest .NET 9.0** (matches project target framework)  
⚠️ **No Specific Tag:** Using rolling `:9.0` tag instead of pinned version

**Recommendation:**
```dockerfile
# Pin to specific digest for reproducible builds
FROM mcr.microsoft.com/dotnet/aspnet:9.0@sha256:abc123... AS base
FROM mcr.microsoft.com/dotnet/sdk:9.0@sha256:def456... AS build
```

### Dockerfile Security Posture

| Control | Status | Recommendation |
|---------|--------|----------------|
| Multi-stage build | ✅ Implemented | Good practice |
| Non-root user | ❌ Not configured | Add `USER` directive |
| Security scanning | ⚠️ External | Verify Trivy/Grype workflows cover this Dockerfile |
| Image signing | ❓ Unknown | Consider Docker Content Trust or Cosign |

---

## Cross-References to Other Security Domains

The following issues were observed but are **out of scope** for supply chain security. They should be addressed by the designated specialized agents:

### SecurityReviewerAgent Domain
- **Log Injection Vulnerability:** [Pages/DevSecOps.cshtml.cs](../src/webapp01/Pages/DevSecOps.cshtml.cs#L28-L29) - User input directly in logs without sanitization
- **ReDoS Risk:** [Pages/DevSecOps.cshtml.cs](../src/webapp01/Pages/DevSecOps.cshtml.cs#L18) - Catastrophic backtracking regex `^(a+)+$`
- **Dual JSON Libraries:** Both `Newtonsoft.Json` and `System.Text.Json` referenced - potential inconsistency

### IaCSecurityAgent Domain
- **Dockerfile Hardening:** Non-root user, health checks, vulnerability scanning
- **Bicep/ARM Templates:** Review infrastructure deployment files in `blueprints/` directory

### PipelineSecurityAgent Domain
- **Workflow Permissions:** Verify SBOM workflow uses minimal permissions
- **Dependency Pinning:** GitHub Actions should use commit SHAs instead of tags

---

## Remediation Summary

### Immediate Actions (Critical Priority)

1. **Rotate Exposed Secrets (TODAY)**
   - Azure Storage Account key in `appsettings.json`
   - Custom GitHub token in `appsettings.json`
   - Update `.gitignore` to prevent future commits
   - Remove secrets from Git history using `git filter-repo`

2. **Update .gitignore (TODAY)**
   - Add `.env*` patterns
   - Add `appsettings.*.json` exclusions

3. **Generate Dependency Lockfile (THIS WEEK)**
   - Enable `RestorePackagesWithLockFile` in `.csproj`
   - Commit `packages.lock.json`

### Short-Term Actions (High Priority - Sprint)

4. **Upgrade Vulnerable Packages (THIS SPRINT)**
   - `Microsoft.Data.SqlClient` → 5.2.1
   - `Newtonsoft.Json` → 13.0.3
   - `System.Text.Json` → 9.0.x

5. **Implement Secrets Management (THIS SPRINT)**
   - Configure Azure Key Vault
   - Set up Managed Identity for App Service
   - Migrate connection strings to Key Vault references

6. **Enable GitHub Secret Scanning & Push Protection (THIS WEEK)**
   - Verify in Security > Code Security and Analysis
   - Enable Push Protection to prevent future commits

### Medium-Term Actions (2-4 Weeks)

7. **SBOM Archival Strategy**
   - Store SBOM artifacts for releases
   - Implement versioning

8. **Dockerfile Hardening**
   - Pin base images to digests
   - Add non-root user
   - Implement health checks

9. **Branch Protection Review**
   - Enforce status checks
   - Require signed commits

---

## Engineering Backlog

| Priority | Item | Domain | Effort | Assignee |
|----------|------|--------|--------|----------|
| 🔴 **CRITICAL** | Rotate Azure Storage key in `appsettings.json` | Secrets | XS | Security Team |
| 🔴 **CRITICAL** | Rotate GitHub token in `appsettings.json` | Secrets | XS | Security Team |
| 🔴 **CRITICAL** | Update `.gitignore` to exclude sensitive files | Governance | XS | DevOps |
| 🟠 **HIGH** | Remove hardcoded credentials from source code | Secrets | S | Dev Team |
| 🟠 **HIGH** | Enable `packages.lock.json` in .csproj | SCA | XS | Dev Team |
| 🟠 **HIGH** | Upgrade `Microsoft.Data.SqlClient` to 5.2.1 | SCA | S | Dev Team |
| 🟠 **HIGH** | Configure Azure Key Vault integration | Secrets | M | DevOps |
| 🟡 **MEDIUM** | Upgrade `Newtonsoft.Json` to 13.0.3 | SCA | XS | Dev Team |
| 🟡 **MEDIUM** | Upgrade `System.Text.Json` to 9.0.x | SCA | S | Dev Team |
| 🟡 **MEDIUM** | Pin Dockerfile base images to digests | Container | S | DevOps |
| 🟡 **MEDIUM** | Archive SBOM artifacts for releases | SBOM | M | DevOps |
| 🟢 **LOW** | Upgrade `Azure.Identity` to 1.14.0 | SCA | XS | Dev Team |
| 🟢 **LOW** | Add non-root user to Dockerfile | Container | S | DevOps |
| 🟢 **LOW** | Review and update SECURITY.md content | Governance | S | Security Team |

---

## Appendix: Reference Standards

- [SLSA Framework](https://slsa.dev/) - Supply-chain Levels for Software Artifacts
- [OpenSSF Scorecard](https://github.com/ossf/scorecard) - Security health metrics
- [OWASP Top 10 CI/CD Security Risks](https://owasp.org/www-project-top-10-ci-cd-security-risks/)
- [SPDX Specification](https://spdx.dev/specifications/) - SBOM standard
- [GitHub Advanced Security Documentation](https://docs.github.com/code-security)
- [NuGet Package Lock File](https://learn.microsoft.com/nuget/consume-packages/package-references-in-project-files#locking-dependencies)
- [Azure Key Vault Configuration](https://learn.microsoft.com/aspnet/core/security/key-vault-configuration)

---

**Report Generated By:** SupplyChainSecurityAgent  
**Analysis Completed:** May 8, 2026  
**Next Review:** Recommended after critical findings remediation
