# Engineering Backlog - Supply Chain Security Remediation

**Project:** webapp01 Supply Chain Security Hardening  
**Generated:** May 8, 2026  
**Sprint Planning:** Prioritized backlog for security remediation

---

## Sprint 1: Critical Secrets Remediation (Week 1)

### Issue #1: [CRITICAL] Rotate Exposed Azure Storage Key
**Priority:** P0 - Critical  
**Effort:** XS (1-2 hours)  
**Assignee:** Security Team  
**Labels:** `security`, `secrets`, `critical`, `supply-chain`

**Description:**
Azure Storage account key is hardcoded in `appsettings.json` and `appsettings.Development.json`, creating complete storage account compromise risk.

**Acceptance Criteria:**
- [ ] Azure Storage key rotated via Azure Portal
- [ ] New key stored in Azure Key Vault
- [ ] Applications updated to use Key Vault reference
- [ ] Old key verified as revoked and non-functional
- [ ] Monitoring alert configured for unauthorized storage access

**Steps:**
1. Navigate to Azure Portal > Storage Account > Access Keys
2. Regenerate key1 (or key2 if key1 is the exposed one)
3. Store new key in Azure Key Vault: `az keyvault secret set --vault-name myapp-kv --name storage-key --value "<new-key>"`
4. Update app configuration to reference Key Vault
5. Test application connectivity
6. Rotate the second key after 24 hours

**Related Files:**
- `src/webapp01/appsettings.json:9`
- `src/webapp01/appsettings.Development.json:8`

**Dependencies:** Azure Key Vault must be provisioned (see Issue #7)

---

### Issue #2: [CRITICAL] Rotate Exposed GitHub Token
**Priority:** P0 - Critical  
**Effort:** XS (1 hour)  
**Assignee:** Security Team  
**Labels:** `security`, `secrets`, `critical`, `supply-chain`

**Description:**
Custom GitHub token with pattern `githubabcs_token_*` is hardcoded in `appsettings.json`. Potential for repository access, code exfiltration, or unauthorized actions.

**Acceptance Criteria:**
- [ ] Token revoked via GitHub Settings
- [ ] New token generated with minimal required scopes
- [ ] Token stored in Azure Key Vault or GitHub Secrets (depending on usage context)
- [ ] Application tested with new token
- [ ] GitHub audit log reviewed for unauthorized token usage

**Steps:**
1. GitHub > Settings > Developer Settings > Personal Access Tokens
2. Locate and delete token matching pattern or all tokens if uncertain
3. Generate new token with minimal scopes (e.g., `repo:status`, `public_repo` only)
4. Store in Key Vault: `az keyvault secret set --vault-name myapp-kv --name github-token --value "<new-token>"`
5. Update application configuration
6. Review GitHub audit log for suspicious activity during token exposure window

**Related Files:**
- `src/webapp01/appsettings.json:10`

**Security Review:** Determine if token is actually needed or can be removed entirely

---

### Issue #3: [CRITICAL] Update .gitignore to Prevent Future Secret Commits
**Priority:** P0 - Critical  
**Effort:** XS (30 minutes)  
**Assignee:** DevOps Team  
**Labels:** `security`, `repository-governance`, `critical`, `supply-chain`

**Description:**
The `.gitignore` file does not exclude sensitive configuration files (`.env`, `appsettings.*.json`), allowing secrets to be accidentally committed.

**Acceptance Criteria:**
- [ ] `.gitignore` updated with sensitive file patterns
- [ ] Pre-commit hook optional: Consider adding git-secrets or gitleaks
- [ ] Team notified of new patterns
- [ ] Documentation updated with secrets management guidelines

**Implementation:**
Apply the diff from `security-reports/pr-ready-fixes.md` Fix #1

**Patterns to Add:**
```gitignore
**/.env
**/.env.*
!**/.env.example
**/appsettings.Development.json
**/appsettings.Production.json
**/appsettings.Staging.json
**/appsettings.*.json
```

**Testing:**
```bash
# Verify patterns work
touch src/webapp01/.env
git status  # Should not appear
```

**Related:** Issue #4 (removing secrets from files)

---

### Issue #4: [CRITICAL] Remove Hardcoded Secrets from Configuration Files
**Priority:** P0 - Critical  
**Effort:** S (2-4 hours)  
**Assignee:** Development Team  
**Labels:** `security`, `secrets`, `critical`, `supply-chain`, `code-change`

**Description:**
After rotating secrets (Issues #1, #2), remove hardcoded values from `appsettings.json` and `appsettings.Development.json` and migrate to secure storage.

**Acceptance Criteria:**
- [ ] Secrets removed from `appsettings.json`
- [ ] Secrets removed from `appsettings.Development.json`
- [ ] User Secrets configured for development environment
- [ ] Azure Key Vault references configured for production
- [ ] Application tested in both dev and production configurations
- [ ] Code review completed

**Implementation:**
Apply the diff from `security-reports/pr-ready-fixes.md` Fix #4

**Development Setup:**
```bash
cd src/webapp01
dotnet user-secrets set "STORAGE_TEST" "<dev-storage-key>"
dotnet user-secrets set "CUSTOM_TEST" "<dev-token>"
```

**Production Setup:**
See Issue #7 for Key Vault configuration

**Dependencies:** Issues #1, #2 must be complete (secrets rotated first)

---

### Issue #5: [CRITICAL] Remove Secrets from Git History
**Priority:** P0 - Critical  
**Effort:** M (4-6 hours including coordination)  
**Assignee:** DevOps Lead  
**Labels:** `security`, `secrets`, `critical`, `supply-chain`, `git-maintenance`

**Description:**
Committed secrets remain in Git history even after removal from current files. Complete remediation requires rewriting repository history.

**Acceptance Criteria:**
- [ ] All team members notified of pending force push
- [ ] Repository backed up (mirror clone)
- [ ] Secrets purged from all commits using git-filter-repo or BFG
- [ ] History verified clean with grep search
- [ ] Force push completed to all branches
- [ ] Team re-clones repository
- [ ] CI/CD pipelines updated to re-clone
- [ ] No secrets found in `git log -p --all -S "<secret-pattern>"`

**⚠️ WARNING:** Destructive operation requiring team coordination

**Implementation:**
Follow method from `security-reports/pr-ready-fixes.md` Fix #5

**Pre-flight Checklist:**
- [ ] Secrets already rotated (Issues #1, #2)
- [ ] All PRs merged or rebased
- [ ] Team availability confirmed for re-clone
- [ ] Backup verified (test restoration)

**Post-cleanup:**
```bash
# Verify cleanup
git log -p --all -S "18gryvHXu" --all
git log -p --all -S "githubabcs_token" --all
git log -p --all -S "SecretPassword123" --all
```

**Dependencies:** Issues #1, #2, #3, #4 must be complete

---

## Sprint 1-2: High Priority Package Updates (Week 1-2)

### Issue #6: [HIGH] Enable NuGet Package Lockfile for Reproducible Builds
**Priority:** P1 - High  
**Effort:** XS (1 hour)  
**Assignee:** Development Team  
**Labels:** `security`, `sca`, `supply-chain`, `high`

**Description:**
Project lacks `packages.lock.json`, allowing non-deterministic dependency resolution. Different builds may use different package versions, creating supply chain attack surface.

**Acceptance Criteria:**
- [ ] `RestorePackagesWithLockFile` property added to `.csproj`
- [ ] `RestoreLockedMode` enabled for CI builds
- [ ] `packages.lock.json` generated and committed
- [ ] CI pipeline validates lockfile is up-to-date
- [ ] Documentation updated with lockfile maintenance procedures

**Implementation:**
Apply the diff from `security-reports/pr-ready-fixes.md` Fix #2

**Post-Implementation:**
```bash
cd src/webapp01
dotnet restore
git add packages.lock.json
git commit -m "Add NuGet lockfile for reproducible builds"
```

**CI Pipeline Addition:**
```yaml
# Add to build workflow
- name: Verify lockfile is up-to-date
  run: |
    dotnet restore --locked-mode
    git diff --exit-code packages.lock.json
```

**Benefits:**
- Prevents dependency confusion attacks
- Ensures consistent builds across environments
- Simplifies vulnerability tracking

---

### Issue #7: [HIGH] Configure Azure Key Vault for Production Secrets
**Priority:** P1 - High  
**Effort:** M (4-6 hours)  
**Assignee:** DevOps Team  
**Labels:** `security`, `secrets`, `infrastructure`, `high`

**Description:**
Implement Azure Key Vault integration to eliminate hardcoded secrets in production. Enable App Service Managed Identity for secure secret retrieval.

**Acceptance Criteria:**
- [ ] Azure Key Vault provisioned in production resource group
- [ ] Managed Identity enabled on App Service
- [ ] Key Vault access policy configured for App Service identity
- [ ] Secrets migrated to Key Vault (storage keys, tokens, connection strings)
- [ ] Application configuration updated with Key Vault references
- [ ] Smoke test in production environment
- [ ] Runbook documented for adding new secrets

**Infrastructure as Code (Bicep):**
```bicep
resource keyVault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: 'webapp01-kv-${environment}'
  location: location
  properties: {
    sku: { family: 'A', name: 'standard' }
    tenantId: subscription().tenantId
    enableRbacAuthorization: true
    enableSoftDelete: true
    softDeleteRetentionInDays: 90
  }
}

resource appServiceIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' existing = {
  name: 'webapp01-identity'
}

resource secretsUserRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: keyVault
  name: guid(keyVault.id, appServiceIdentity.id, 'Key Vault Secrets User')
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '4633458b-17de-408a-b874-0445c86b69e6')
    principalId: appServiceIdentity.properties.principalId
  }
}
```

**App Configuration Update:**
```json
{
  "STORAGE_TEST": "@Microsoft.KeyVault(SecretUri=https://webapp01-kv-prod.vault.azure.net/secrets/storage-key/)",
  "CUSTOM_TEST": "@Microsoft.KeyVault(SecretUri=https://webapp01-kv-prod.vault.azure.net/secrets/github-token/)"
}
```

**Dependencies:** Issues #1, #2 (secrets rotated)

---

### Issue #8: [HIGH] Upgrade Microsoft.Data.SqlClient to 5.2.1 (CVE-2024-0056)
**Priority:** P1 - High (CVE)  
**Effort:** S (2-4 hours including testing)  
**Assignee:** Development Team  
**Labels:** `security`, `sca`, `vulnerability`, `high`, `supply-chain`

**Description:**
`Microsoft.Data.SqlClient 5.0.2` (March 2023) has known vulnerability CVE-2024-0056. Upgrade to 5.2.1 to patch security issue and gain performance improvements.

**CVE-2024-0056:** Security Feature Bypass Vulnerability  
**CVSS Score:** 7.5 (High)  
**Patch Version:** 5.2.1+

**Acceptance Criteria:**
- [ ] Package upgraded to 5.2.1 in `.csproj`
- [ ] Breaking changes reviewed ([release notes](https://github.com/dotnet/SqlClient/releases/tag/v5.2.0))
- [ ] Unit tests pass
- [ ] Integration tests with SQL Server pass
- [ ] Performance regression testing completed
- [ ] Code review for API changes

**Implementation:**
Part of `security-reports/pr-ready-fixes.md` Fix #3

**Testing Checklist:**
- [ ] Connection pooling behavior unchanged
- [ ] Authentication methods (SQL + Azure AD) work
- [ ] Retry logic functions correctly
- [ ] No performance degradation (run benchmarks)

**Rollback Plan:** Revert `.csproj` change if critical issues found

---

### Issue #9: [HIGH] Remove Hardcoded SQL Connection String from Source Code
**Priority:** P1 - High  
**Effort:** S (2-3 hours)  
**Assignee:** Development Team  
**Labels:** `security`, `secrets`, `high`, `code-change`

**Description:**
SQL Server connection string with hardcoded password in `Pages/DevSecOps.cshtml.cs:15`. Migrate to configuration with Key Vault reference.

**Current Code:**
```csharp
private const string CONNECTION_STRING = "Server=localhost;Database=TestDB;User Id=admin;Password=SecretPassword123!;";
```

**Acceptance Criteria:**
- [ ] Connection string removed from source code
- [ ] Moved to `appsettings.json` or injected via `IConfiguration`
- [ ] Production uses Key Vault reference
- [ ] Development uses User Secrets
- [ ] Code review completed
- [ ] No hardcoded credentials in codebase

**Proposed Fix:**
```csharp
public class DevSecOpsModel : PageModel
{
    private readonly ILogger<DevSecOpsModel> _logger;
    private readonly IConfiguration _configuration;

    public DevSecOpsModel(ILogger<DevSecOpsModel> logger, IConfiguration configuration)
    {
        _logger = logger;
        _configuration = configuration;
    }

    private string GetConnectionString() => _configuration.GetConnectionString("TestDB")
        ?? throw new InvalidOperationException("Connection string 'TestDB' not found.");
}
```

**Configuration (appsettings.json):**
```json
{
  "ConnectionStrings": {
    "TestDB": "@Microsoft.KeyVault(SecretUri=https://webapp01-kv.vault.azure.net/secrets/testdb-connection/)"
  }
}
```

**User Secrets (Development):**
```bash
dotnet user-secrets set "ConnectionStrings:TestDB" "Server=localhost;Database=TestDB;User Id=admin;Password=DevPassword123!;"
```

**Related Files:**
- `src/webapp01/Pages/DevSecOps.cshtml.cs:15`

**Dependencies:** Issue #7 (Key Vault setup)

---

### Issue #10: [HIGH] Remove Hardcoded Default Password Constant
**Priority:** P1 - High  
**Effort:** XS (1-2 hours)  
**Assignee:** Development Team  
**Labels:** `security`, `secrets`, `high`, `code-change`

**Description:**
Hardcoded password constant `DEFAULT_PASSWORD = "Pass@word1"` in `Pages/Index.cshtml.cs:11`. Developer comment acknowledges insecurity but hasn't been removed.

**Current Code:**
```csharp
// TODO: Don't use this in production
public const string DEFAULT_PASSWORD = "Pass@word1";
```

**Acceptance Criteria:**
- [ ] Constant removed from source code
- [ ] Replaced with secure password generation if needed
- [ ] Usage analysis confirms no production impact
- [ ] Code review completed

**Proposed Fix (if password generation needed):**
```csharp
private string GenerateSecurePassword(int length = 16)
{
    const string validChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%^&*";
    using var rng = RandomNumberGenerator.Create();
    var bytes = new byte[length];
    rng.GetBytes(bytes);
    return new string(bytes.Select(b => validChars[b % validChars.Length]).ToArray());
}
```

**Alternative:** Remove entirely if unused in production

**Related Files:**
- `src/webapp01/Pages/Index.cshtml.cs:11`

---

## Sprint 2: Medium Priority Hardening (Week 2-3)

### Issue #11: [MEDIUM] Upgrade Newtonsoft.Json to 13.0.3
**Priority:** P2 - Medium  
**Effort:** XS (1 hour)  
**Assignee:** Development Team  
**Labels:** `security`, `sca`, `medium`, `supply-chain`

**Description:**
`Newtonsoft.Json 13.0.1` is two minor versions behind current stable `13.0.3`. Upgrade for security and stability improvements.

**Acceptance Criteria:**
- [ ] Package upgraded to 13.0.3
- [ ] Unit tests pass (backward compatible)
- [ ] Integration tests pass
- [ ] No behavioral changes in JSON serialization

**Implementation:**
Part of `security-reports/pr-ready-fixes.md` Fix #3

**Testing:**
- [ ] JSON serialization roundtrip tests
- [ ] Deserialization of complex objects
- [ ] Performance benchmarks (no regression)

**Risk:** Low - patch version upgrades are typically backward compatible

---

### Issue #12: [MEDIUM] Upgrade System.Text.Json to 9.0.x
**Priority:** P2 - Medium  
**Effort:** S (2-3 hours)  
**Assignee:** Development Team  
**Labels:** `security`, `sca`, `medium`, `supply-chain`

**Description:**
`System.Text.Json 8.0.4` is a minor version behind 9.0.x. Align with .NET 9.0 runtime for compatibility and new features.

**Acceptance Criteria:**
- [ ] Package upgraded to 9.0.0 (or latest 9.0.x)
- [ ] Breaking changes reviewed (8.0 → 9.0)
- [ ] Unit tests pass
- [ ] Integration tests pass
- [ ] JSON API behavior unchanged

**Implementation:**
Part of `security-reports/pr-ready-fixes.md` Fix #3

**Breaking Changes Review:**
- Check [System.Text.Json 9.0 release notes](https://learn.microsoft.com/dotnet/core/compatibility/serialization/9.0/overview)
- Verify JsonSerializerOptions compatibility
- Test custom converters if any

**Testing:**
- [ ] Serialization tests
- [ ] Deserialization tests
- [ ] Source generation (if used)

---

### Issue #13: [MEDIUM] Pin Dockerfile Base Images to Digests
**Priority:** P2 - Medium  
**Effort:** S (2-3 hours)  
**Assignee:** DevOps Team  
**Labels:** `security`, `container`, `supply-chain`, `medium`

**Description:**
Dockerfile uses rolling tags (`:9.0`) instead of pinned digests, allowing base image tampering and non-reproducible builds.

**Acceptance Criteria:**
- [ ] Base image digests retrieved for current `:9.0` tags
- [ ] Dockerfile updated with pinned digests
- [ ] CI pipeline builds successfully
- [ ] Image scanning confirms no regressions
- [ ] Quarterly digest update process documented

**Implementation:**
Follow `security-reports/pr-ready-fixes.md` Fix #6

**Digest Retrieval:**
```bash
docker pull mcr.microsoft.com/dotnet/aspnet:9.0
docker inspect --format='{{index .RepoDigests 0}}' mcr.microsoft.com/dotnet/aspnet:9.0
```

**Maintenance:**
Create quarterly calendar reminder to update digests when Microsoft releases patches

**Benefits:**
- Prevents supply chain attacks
- Reproducible container builds
- Easier vulnerability tracking

---

### Issue #14: [MEDIUM] Archive SBOM Artifacts for Release Versions
**Priority:** P2 - Medium  
**Effort:** M (3-4 hours)  
**Assignee:** DevOps Team  
**Labels:** `security`, `sbom`, `compliance`, `medium`

**Description:**
SBOM is currently generated on every build but not archived for releases. Implement release artifact archival for compliance and vulnerability tracking.

**Acceptance Criteria:**
- [ ] SBOM workflow updated to archive on tagged releases
- [ ] Artifacts stored with version number
- [ ] Retention policy configured (90 days recommended)
- [ ] Download process documented
- [ ] Sample SBOM validated for completeness

**Implementation:**
Apply `security-reports/pr-ready-fixes.md` Fix #7

**Testing:**
```bash
# Create test tag and verify artifact upload
git tag v1.0.0-test
git push origin v1.0.0-test
# Check Actions > SBOM workflow > Artifacts
```

**Compliance Use Case:**
- CVE-2024-XXXXX announced
- Download SBOM for production release v2.3.1
- Grep for vulnerable package: `grep -r "Microsoft.Data.SqlClient.*5.0.2" sbom-v2.3.1/`
- Determine impact and patching priority

---

## Sprint 3: Low Priority & Governance (Week 3-4)

### Issue #15: [LOW] Upgrade Azure.Identity to 1.14.0
**Priority:** P3 - Low  
**Effort:** XS (1 hour)  
**Assignee:** Development Team  
**Labels:** `security`, `sca`, `low`, `supply-chain`

**Description:**
`Azure.Identity 1.13.2` is one minor version behind current `1.14.0`. Upgrade for latest features and bug fixes.

**Acceptance Criteria:**
- [ ] Package upgraded to 1.14.0
- [ ] Authentication tests pass (Azure AD, Managed Identity)
- [ ] No breaking changes introduced

**Implementation:**
Part of `security-reports/pr-ready-fixes.md` Fix #3

**Testing:**
- [ ] Local development authentication works
- [ ] Managed Identity authentication in production
- [ ] Azure Key Vault access via identity

---

### Issue #16: [LOW] Add Non-Root User to Dockerfile
**Priority:** P3 - Low  
**Effort:** S (2-3 hours)  
**Assignee:** DevOps Team  
**Labels:** `security`, `container`, `low`

**Description:**
Container runs as root user by default. Add non-root user for defense-in-depth.

**Acceptance Criteria:**
- [ ] Non-root user created in Dockerfile
- [ ] Application runs as non-root
- [ ] File permissions correct
- [ ] Container security scan passes

**Proposed Implementation:**
```dockerfile
FROM mcr.microsoft.com/dotnet/aspnet:9.0@sha256:... AS base
WORKDIR /app
EXPOSE 8080
EXPOSE 8081

# Create non-root user
RUN groupadd -r appuser && useradd -r -g appuser appuser
RUN chown -R appuser:appuser /app

# ... rest of Dockerfile ...

FROM base AS final
WORKDIR /app
COPY --from=publish --chown=appuser:appuser /app/publish .
USER appuser
ENTRYPOINT ["dotnet", "webapp01.dll"]
```

**Testing:**
```bash
docker build -t webapp01:test .
docker run --rm webapp01:test id
# Should show uid=XXX(appuser) gid=XXX(appuser)
```

---

### Issue #17: [LOW] Enable GitHub Secret Scanning Push Protection
**Priority:** P3 - Low  
**Effort:** XS (30 minutes)  
**Assignee:** Security Team  
**Labels:** `security`, `repository-governance`, `low`

**Description:**
Enable GitHub Secret Scanning and Push Protection to prevent future accidental secret commits.

**Acceptance Criteria:**
- [ ] Secret Scanning enabled in repository settings
- [ ] Push Protection enabled (blocks commits with secrets)
- [ ] Team notified of new protection
- [ ] Bypass process documented for false positives

**Implementation:**
1. Navigate to: Repository > Settings > Code Security and Analysis
2. Enable "Secret Scanning"
3. Enable "Push Protection"
4. Configure custom patterns if needed (for `githubabcs_token_*` pattern)

**Team Communication:**
```markdown
## New Security Control: Push Protection

GitHub will now block commits containing secrets. If you encounter a block:

1. Remove the secret from your commit
2. Use User Secrets (dev) or Key Vault (prod)
3. If false positive, use bypass (requires justification)

Learn more: https://docs.github.com/code-security/secret-scanning/push-protection-for-repositories-and-organizations
```

**Custom Pattern (optional):**
```regex
githubabcs_token_[a-zA-Z0-9]{64}
```

---

### Issue #18: [LOW] Review and Update SECURITY.md
**Priority:** P3 - Low  
**Effort:** S (2 hours)  
**Assignee:** Security Team  
**Labels:** `security`, `documentation`, `low`

**Description:**
Current `SECURITY.md` contains template boilerplate. Update with actual supported versions and vulnerability reporting process.

**Acceptance Criteria:**
- [ ] Supported versions table updated with actual versions
- [ ] Vulnerability reporting process defined
- [ ] SLA for security issues documented
- [ ] Contact information provided
- [ ] Disclosure policy defined

**Proposed Content:**
```markdown
# Security Policy

## Supported Versions

| Version | Supported          | EOL Date    |
| ------- | ------------------ | ----------- |
| 1.x     | ✅ Yes             | TBD         |

## Reporting a Vulnerability

**DO NOT** create public GitHub issues for security vulnerabilities.

### Private Reporting
1. Use GitHub Security Advisories: [Report a vulnerability](../../security/advisories/new)
2. Or email: security@example.com (encrypted with PGP key)

### Response SLA
- **Critical (CVSS 9.0-10.0):** 24 hours
- **High (CVSS 7.0-8.9):** 48 hours
- **Medium (CVSS 4.0-6.9):** 1 week
- **Low (CVSS 0.1-3.9):** 2 weeks

### Disclosure Policy
We follow coordinated disclosure:
1. Issue acknowledged within 48 hours
2. Patch developed and tested
3. Public disclosure 90 days after fix, or sooner if exploited in the wild

### Security Advisories
View all advisories: [Security Advisories](../../security/advisories)
```

**Related:** Update contact email and PGP key as needed

---

## Backlog Summary

| Priority | Count | Total Effort Estimate |
|----------|-------|-----------------------|
| P0 - Critical | 5 | 12-19 hours (Sprint 1) |
| P1 - High | 5 | 15-24 hours (Sprint 1-2) |
| P2 - Medium | 4 | 9-13 hours (Sprint 2) |
| P3 - Low | 4 | 6-9 hours (Sprint 3) |
| **TOTAL** | **18** | **42-65 hours** (~1.5-2 sprints) |

---

## Sprint Roadmap

### Sprint 1 (Week 1-2): Critical Remediation
**Goal:** Eliminate active credential exposure and enable reproducible builds

- Issue #1: Rotate Azure Storage key
- Issue #2: Rotate GitHub token
- Issue #3: Update .gitignore
- Issue #4: Remove secrets from config
- Issue #5: Remove secrets from Git history
- Issue #6: Enable NuGet lockfile
- Issue #7: Configure Azure Key Vault

**Exit Criteria:**
- [ ] No hardcoded secrets in current code or history
- [ ] Reproducible builds via lockfile
- [ ] Key Vault operational

### Sprint 2 (Week 2-3): Package Updates & Hardening
**Goal:** Eliminate known CVEs and improve container security

- Issue #8: Upgrade Microsoft.Data.SqlClient (CVE)
- Issue #9: Remove SQL connection string from code
- Issue #10: Remove hardcoded password constant
- Issue #11: Upgrade Newtonsoft.Json
- Issue #12: Upgrade System.Text.Json
- Issue #13: Pin Dockerfile base images
- Issue #14: Archive SBOM artifacts

**Exit Criteria:**
- [ ] No HIGH or CRITICAL Dependabot alerts
- [ ] All packages current
- [ ] SBOM archival functional

### Sprint 3 (Week 3-4): Governance & Polish
**Goal:** Complete remaining items and establish ongoing processes

- Issue #15: Upgrade Azure.Identity
- Issue #16: Add non-root Dockerfile user
- Issue #17: Enable GitHub Push Protection
- Issue #18: Update SECURITY.md

**Exit Criteria:**
- [ ] All backlog items complete
- [ ] Security posture verified
- [ ] Documentation current

---

## Ongoing Maintenance

### Weekly
- [ ] Review Dependabot alerts
- [ ] Monitor secret scanning alerts

### Monthly
- [ ] Review and merge Dependabot PRs
- [ ] Audit Key Vault access logs
- [ ] Update `.gitignore` if new secret patterns found

### Quarterly
- [ ] Update Dockerfile base image digests
- [ ] Review SBOM completeness
- [ ] Security posture assessment

### Annually
- [ ] Rotate all secrets (even if not compromised)
- [ ] Review and update SECURITY.md
- [ ] Audit compliance (SLSA, SSDF)

---

**Document Version:** 1.0  
**Created:** May 8, 2026  
**Author:** SupplyChainSecurityAgent  
**Status:** Ready for Sprint Planning
