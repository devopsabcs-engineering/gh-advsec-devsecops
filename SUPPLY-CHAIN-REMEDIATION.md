# Supply Chain Security Remediation Guide

**Last Updated:** 2026-02-04  
**Status:** In Progress  
**Related Report:** [SUPPLY-CHAIN-SECURITY-REPORT.md](./SUPPLY-CHAIN-SECURITY-REPORT.md)

## 🔒 Immediate Actions Required (CRITICAL)

### 1. Rotate Exposed Azure Storage Key

**Status:** ⏳ PENDING - Requires immediate action

**Steps:**

```powershell
# 1. Identify the storage account (check Azure Portal or deployment logs)
$STORAGE_ACCOUNT_NAME = "your-storage-account-name"
$RESOURCE_GROUP = "your-resource-group"

# 2. Rotate the primary key
az storage account keys renew `
  --account-name $STORAGE_ACCOUNT_NAME `
  --resource-group $RESOURCE_GROUP `
  --key primary

# 3. Get the new key and store in Azure Key Vault
$NEW_KEY = (az storage account keys list `
  --account-name $STORAGE_ACCOUNT_NAME `
  --resource-group $RESOURCE_GROUP `
  --query "[?keyName=='key1'].value" -o tsv)

# 4. Store in Key Vault
az keyvault secret set `
  --vault-name "your-keyvault-name" `
  --name "StorageAccountKey" `
  --value $NEW_KEY

# 5. Audit recent access (check for unauthorized usage)
az monitor activity-log list `
  --resource-id "/subscriptions/{subscription-id}/resourceGroups/$RESOURCE_GROUP/providers/Microsoft.Storage/storageAccounts/$STORAGE_ACCOUNT_NAME" `
  --start-time 2026-01-01T00:00:00Z `
  --query "[?contains(operationName.value, 'listKeys')]" -o table
```

**Verification:**
- [ ] Old key rotated
- [ ] New key stored in Key Vault
- [ ] Application configuration updated to use Key Vault reference
- [ ] Access logs reviewed for suspicious activity
- [ ] Incident documented in security log

---

### 2. Remove Secrets from Source Control

**Status:** ✅ COMPLETED (PR-ready changes applied)

**Changes Made:**
- ✅ Removed hardcoded storage key from `appsettings.json`
- ✅ Removed hardcoded storage key from `appsettings.Development.json`
- ✅ Added comments explaining secure alternatives (Key Vault, User Secrets)

**Production Configuration (appsettings.json):**
```json
{
  "STORAGE_TEST": "@Microsoft.KeyVault(SecretUri=https://your-vault.vault.azure.net/secrets/StorageAccountKey/)"
}
```

**Development Setup (User Secrets):**
```powershell
# Set secret for local development
dotnet user-secrets set "STORAGE_TEST" "your-development-key" --project ./src/webapp01
```

**Verification:**
- [x] Secrets removed from tracked files
- [x] Key Vault integration documented
- [x] User Secrets configuration documented
- [ ] Key Vault secret reference configured in Azure App Service

---

## 🔧 Dependency Updates (HIGH Priority)

### 3. Update Vulnerable NuGet Packages

**Status:** ✅ COMPLETED (PR-ready changes applied)

**Changes Made:**
```xml
<!-- BEFORE -->
<PackageReference Include="Microsoft.Data.SqlClient" Version="5.0.2" />
<PackageReference Include="System.Text.Json" Version="8.0.4" />
<PackageReference Include="Newtonsoft.Json" Version="13.0.1" />

<!-- AFTER -->
<PackageReference Include="Microsoft.Data.SqlClient" Version="5.2.0" />
<PackageReference Include="System.Text.Json" Version="8.0.5" />
<PackageReference Include="Newtonsoft.Json" Version="13.0.3" />
```

**Addressed Vulnerabilities:**
- ✅ CVE-2024-0056 - .NET Denial of Service
- ✅ CVE-2024-0057 - .NET Security Feature Bypass
- ✅ CVE-2024-21907 - Newtonsoft.Json vulnerability (Low severity)

**Next Steps:**
```powershell
# Restore packages
cd src/webapp01
dotnet restore

# Build and test
dotnet build
dotnet test

# Verify no vulnerabilities
dotnet list package --vulnerable --include-transitive
```

**Verification:**
- [x] Package references updated in .csproj
- [ ] Build succeeds with new versions
- [ ] Tests pass
- [ ] No new vulnerabilities introduced

---

## 🛡️ Repository Governance (HIGH Priority)

### 4. Enhanced CODEOWNERS

**Status:** ✅ COMPLETED (PR-ready changes applied)

**Changes Made:**
Enhanced CODEOWNERS to include security-sensitive path protection:
- Security-sensitive GitHub workflows
- Infrastructure as Code files (Terraform, Bicep)
- Dependency manifests (*.csproj, *.sln)
- Container definitions (Dockerfiles)

**Note:** Update `@CalinL` to team handles when teams are configured:
- `@your-org/security-team`
- `@your-org/platform-team`
- `@your-org/engineering-team`

**Verification:**
- [x] CODEOWNERS updated
- [ ] Team handles configured in GitHub
- [ ] Branch protection configured to require CODEOWNERS approval

---

### 5. Branch Protection Configuration

**Status:** ⏳ PENDING - Requires GitHub Admin Access

**Required Settings for `main` branch:**

Navigate to: Repository → Settings → Branches → Add rule for `main`

**Branch name pattern:** `main`

**Protect matching branches:**
- [x] Require a pull request before merging
  - Required approvals: **2**
  - [x] Dismiss stale pull request approvals when new commits are pushed
  - [x] Require review from Code Owners
- [x] Require status checks to pass before merging
  - [x] Require branches to be up to date before merging
  - Required status checks:
    - `ci_build` (from .github/workflows/ci.yml)
    - `dependency-review` (from .github/workflows/SCA-GitHubAdvancedSecurity-DependencyReview.yml)
    - `CodeQL` (from .github/workflows/SAST-GitHubAdvancedSecurity-CodeQL.yml)
- [x] Require linear history
- [x] Do not allow bypassing the above settings (applies to administrators)
- [ ] Require signed commits (recommended but optional)

**Verification Checklist:**
- [ ] Branch protection rule created
- [ ] Required reviewers: 2
- [ ] CODEOWNERS enforcement enabled
- [ ] Status checks configured
- [ ] Admin bypass disabled

**Screenshot:** (Attach screenshot of branch protection settings once configured)

---

### 6. Updated SECURITY.md

**Status:** ✅ COMPLETED (PR-ready changes applied)

**Changes:**
- ✅ Project-specific vulnerability reporting process
- ✅ Clear supported versions table
- ✅ Response timeline expectations
- ✅ Severity classification
- ✅ Current security measures documented

**Verification:**
- [x] SECURITY.md updated with project details
- [ ] Security team contact verified

---

## 🔐 SBOM & Provenance (HIGH Priority)

### 7. Build Provenance Attestation

**Status:** ✅ COMPLETED (PR-ready changes applied)

**Changes Made:**
Enhanced `.github/workflows/SCA-Microsoft-SBOM.yml`:
```yaml
# Added build provenance attestation
- name: Generate Build Provenance Attestation
  uses: actions/attest-build-provenance@v1
  with:
    subject-path: 'buildOutput/**/*'

# Added SBOM attestation
- name: Attest SBOM
  uses: actions/attest-sbom@v1
  with:
    subject-path: 'buildOutput/**/*'
    sbom-path: '_manifest/spdx_2.2/manifest.spdx.json'
```

**Benefits:**
- SLSA Level 2+ compliance
- Cryptographic proof of build provenance
- Tamper-evident artifacts
- Supply chain transparency

**Verification:**
- [x] Workflow updated
- [ ] Next build generates attestations
- [ ] Attestations viewable in GitHub UI (Actions → Attestations)
- [ ] Consumers can verify with: `gh attestation verify <artifact>`

---

### 8. Container Image Signing

**Status:** 🔄 PARTIALLY IMPLEMENTED (TODO added)

**Changes Made:**
Added TODO comments in `.github/workflows/ci.yml` for future implementation.

**When image is pushed to registry, add:**
```yaml
- name: Install Cosign
  uses: sigstore/cosign-installer@v3

- name: Sign container image
  run: |
    cosign sign --yes ${{ env.REGISTRY }}/${{ env.imageName }}@${{ steps.build.outputs.digest }}
```

**Prerequisites:**
- Container registry configured (e.g., ACR, GHCR)
- Image push workflow implemented
- Sigstore/Cosign integration

**Verification:**
- [ ] Container registry configured
- [ ] Image push implemented
- [ ] Cosign signing enabled
- [ ] Signature verification documented

---

## 📋 Dependency Management Enhancements

### 9. Dependabot Configuration Review

**Status:** ✅ VERIFIED - Current configuration is good

**Current Settings:**
```yaml
# .github/dependabot.yml
version: 2
updates:
  - package-ecosystem: nuget
    schedule:
      interval: weekly
    open-pull-requests-limit: 15
  
  - package-ecosystem: "github-actions"
    schedule:
      interval: "daily"
```

**Recommendations for Future Enhancement:**
```yaml
# Add grouping and ignore rules
  - package-ecosystem: nuget
    directory: "/src/webapp01/"
    schedule:
      interval: weekly
    open-pull-requests-limit: 10
    groups:
      production-dependencies:
        dependency-type: "production"
      development-dependencies:
        dependency-type: "development"
        update-types: ["minor", "patch"]
    ignore:
      # Ignore major version updates (require manual review)
      - dependency-name: "*"
        update-types: ["version-update:semver-major"]
```

**Verification:**
- [x] Dependabot enabled for NuGet
- [x] Dependabot enabled for GitHub Actions
- [ ] Consider adding grouping rules
- [ ] Consider adding major version ignore rules

---

### 10. Pin GitHub Actions to Commit SHAs

**Status:** ⏳ PENDING - Low priority (Dependabot will manage)

**Current State:**
All workflows use mutable tags (e.g., `@v5`, `@v4`)

**Recommendation:**
Let Dependabot handle this automatically. When it opens PRs, it will pin actions.

**Manual Alternative (if needed):**
```yaml
# Instead of:
- uses: actions/checkout@v5

# Use:
- uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v5.0.0
```

**Tool to help:**
```powershell
# Install action-validator
npm install -g action-validator

# Pin all actions in a workflow
action-validator pin .github/workflows/ci.yml
```

**Verification:**
- [ ] Review next Dependabot PR for GitHub Actions
- [ ] Ensure PRs include commit SHAs
- [ ] Configure auto-merge for minor/patch updates

---

## 📊 Testing & Validation

### Post-Deployment Verification Checklist

**After merging this PR:**

1. **Secrets Management**
   - [ ] Storage key rotated in Azure
   - [ ] New key stored in Key Vault
   - [ ] Application retrieves key from Key Vault successfully
   - [ ] No secrets detected by GitHub secret scanning

2. **Dependencies**
   - [ ] Build succeeds with updated packages
   - [ ] All tests pass
   - [ ] `dotnet list package --vulnerable` shows no vulnerabilities
   - [ ] Application functions correctly with new dependencies

3. **CI/CD**
   - [ ] All required status checks pass
   - [ ] SBOM generated successfully
   - [ ] Build attestations created
   - [ ] Attestations visible in GitHub UI

4. **Governance**
   - [ ] Pull requests require 2 approvals
   - [ ] CODEOWNERS automatically added as reviewers
   - [ ] Status checks block merge until passing
   - [ ] Direct pushes to main blocked

5. **Documentation**
   - [ ] SECURITY.md reflects current practices
   - [ ] README updated (if needed)
   - [ ] Runbook updated for incident response

---

## 🚨 Incident Response

### If Exposed Secret Was Used Maliciously

**Detection:**
```powershell
# Check storage account metrics for unusual activity
az monitor metrics list `
  --resource "/subscriptions/{sub-id}/resourceGroups/{rg}/providers/Microsoft.Storage/storageAccounts/{account}" `
  --metric "Transactions" `
  --interval PT1H `
  --start-time 2026-01-01T00:00:00Z

# Check blob access logs
az storage blob list --account-name $STORAGE_ACCOUNT_NAME --container-name $CONTAINER_NAME
```

**Response Procedure:**
1. Immediately rotate ALL keys (both primary and secondary)
2. Review blob container access logs
3. Check for data exfiltration (unusual download patterns)
4. Review IAM permissions on storage account
5. Enable blob versioning and soft delete (if not already enabled)
6. File incident report with security team
7. Notify affected stakeholders if data breach confirmed

---

## 📈 Continuous Improvement

### Future Enhancements (Backlog)

**Sprint 3+ (30-90 days):**
- [ ] Implement SLSA Level 3 (hermetic builds)
- [ ] Add pre-commit hooks (detect-secrets, gitleaks)
- [ ] Implement SCA in pre-commit (local dependency checking)
- [ ] Add CONTRIBUTING.md with security guidelines
- [ ] Configure OpenSSF Scorecard monitoring
- [ ] Implement signed commits requirement
- [ ] Add security training materials for contributors
- [ ] Implement automated compliance reporting

**Metrics to Track:**
- OpenSSF Scorecard score (target: 8/10)
- Time to patch critical vulnerabilities (target: <24 hours)
- Dependabot PR merge rate (target: >90%)
- Secret scanning alerts (target: 0 active alerts)

---

## 📞 Support & Questions

**For questions about this remediation:**
- Security Team: @CalinL
- Repository: devopsabcs-engineering/gh-advsec-devsecops
- Report: [SUPPLY-CHAIN-SECURITY-REPORT.md](./SUPPLY-CHAIN-SECURITY-REPORT.md)

**Related Documentation:**
- [GitHub Security Best Practices](https://docs.github.com/en/code-security)
- [SLSA Framework](https://slsa.dev/)
- [OpenSSF Security Guides](https://openssf.org/)

---

**Status Legend:**
- ✅ COMPLETED - Changes applied and ready
- 🔄 PARTIALLY IMPLEMENTED - Some work done, more needed
- ⏳ PENDING - Awaiting action
- ❌ BLOCKED - Cannot proceed (state reason)
