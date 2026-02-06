# Branch Protection Configuration

**Repository:** devopsabcs-engineering/gh-advsec-devsecops  
**Target Branch:** main  
**Last Updated:** 2026-02-04

## Configuration Instructions

GitHub branch protection rules must be configured through the web UI or API. Follow these steps:

### Web UI Configuration

1. Navigate to: **Repository → Settings → Branches**
2. Click **Add rule** (or edit existing rule for `main`)
3. Apply the following settings:

---

## Branch Protection Settings

### Branch Name Pattern
```
main
```

### Protect Matching Branches

#### ✅ Require a pull request before merging
- **Required number of approvals before merging:** `2`
- ✅ **Dismiss stale pull request approvals when new commits are pushed**
- ✅ **Require review from Code Owners**
- ✅ **Require approval of the most recent reviewable push**

#### ✅ Require status checks to pass before merging
- ✅ **Require branches to be up to date before merging**
- **Status checks that are required:**
  - `ci_build` (from .github/workflows/ci.yml)
  - `dependency-review` (from .github/workflows/SCA-GitHubAdvancedSecurity-DependencyReview.yml)
  - `CodeQL` (from .github/workflows/SAST-GitHubAdvancedSecurity-CodeQL.yml)

#### ✅ Require conversation resolution before merging

#### ✅ Require linear history

#### ⚠️ Require deployments to succeed before merging (optional)
- Configure after CD pipeline is established

#### ⚠️ Require signed commits (recommended but optional)
- Enable when team is ready to use GPG/SSH signing

#### ✅ Do not allow bypassing the above settings
- **IMPORTANT:** This applies to administrators and prevents emergency bypasses
- Only enable after testing that all required checks work properly

---

## API Configuration (Alternative)

Use GitHub CLI or REST API to configure programmatically:

### Using GitHub CLI

```bash
# Install GitHub CLI if needed: https://cli.github.com/

# Configure branch protection
gh api repos/devopsabcs-engineering/gh-advsec-devsecops/branches/main/protection \
  --method PUT \
  --field required_status_checks[strict]=true \
  --field required_status_checks[contexts][]=ci_build \
  --field required_status_checks[contexts][]=dependency-review \
  --field required_status_checks[contexts][]=CodeQL \
  --field enforce_admins=true \
  --field required_pull_request_reviews[dismissal_restrictions][]=null \
  --field required_pull_request_reviews[dismiss_stale_reviews]=true \
  --field required_pull_request_reviews[require_code_owner_reviews]=true \
  --field required_pull_request_reviews[required_approving_review_count]=2 \
  --field required_pull_request_reviews[require_last_push_approval]=true \
  --field restrictions=null \
  --field required_linear_history=true \
  --field allow_force_pushes=false \
  --field allow_deletions=false \
  --field required_conversation_resolution=true
```

### Using PowerShell with GitHub API

```powershell
# Set variables
$org = "devopsabcs-engineering"
$repo = "gh-advsec-devsecops"
$branch = "main"
$token = $env:GITHUB_TOKEN  # Set this environment variable first

# Branch protection configuration
$body = @{
    required_status_checks = @{
        strict = $true
        contexts = @("ci_build", "dependency-review", "CodeQL")
    }
    enforce_admins = $true
    required_pull_request_reviews = @{
        dismiss_stale_reviews = $true
        require_code_owner_reviews = $true
        required_approving_review_count = 2
        require_last_push_approval = $true
    }
    restrictions = $null
    required_linear_history = $true
    allow_force_pushes = $false
    allow_deletions = $false
    required_conversation_resolution = $true
} | ConvertTo-Json -Depth 10

# Apply configuration
$headers = @{
    "Authorization" = "Bearer $token"
    "Accept" = "application/vnd.github.v3+json"
}

Invoke-RestMethod `
    -Uri "https://api.github.com/repos/$org/$repo/branches/$branch/protection" `
    -Method Put `
    -Headers $headers `
    -Body $body `
    -ContentType "application/json"
```

---

## Verification

### Verify Configuration via CLI

```bash
# View current branch protection settings
gh api repos/devopsabcs-engineering/gh-advsec-devsecops/branches/main/protection | jq
```

### Verify Configuration via Web UI

1. Navigate to **Settings → Branches**
2. Verify `main` branch shows:
   - ✅ **2 approvals required**
   - ✅ **Code owners required**
   - ✅ **3 status checks required**
   - ✅ **Linear history required**
   - ✅ **Administrators not exempt**

### Test Protection Rules

```bash
# Test 1: Try to push directly to main (should fail)
git checkout main
git commit --allow-empty -m "test: direct push"
git push origin main
# Expected: ERROR - protected branch

# Test 2: Create PR without required checks passing (should block merge)
gh pr create --base main --head feature/test --title "Test PR"
# Expected: Merge blocked until checks pass

# Test 3: Create PR with only 1 approval (should block merge)
# Expected: Merge blocked until 2 approvals received
```

---

## Status Checks Configuration

Ensure these GitHub Actions workflows are properly configured:

### ci_build
- **Workflow:** `.github/workflows/ci.yml`
- **Job:** `ci_build`
- **Triggers:** `pull_request` on `main`
- **Status:** ✅ Active

### dependency-review
- **Workflow:** `.github/workflows/SCA-GitHubAdvancedSecurity-DependencyReview.yml`
- **Job:** `dependency-review`
- **Triggers:** `pull_request` on `main`
- **Status:** ✅ Active

### CodeQL
- **Workflow:** `.github/workflows/SAST-GitHubAdvancedSecurity-CodeQL.yml`
- **Job:** `analyze`
- **Triggers:** `pull_request` on `main`
- **Status:** ✅ Active (verify it runs on PRs)

---

## Troubleshooting

### Issue: Status checks not showing up

**Solution:**
1. Ensure workflows trigger on `pull_request` events targeting `main`
2. Create a test PR to trigger workflows
3. Wait for workflows to run at least once
4. Status checks will then appear in branch protection settings

### Issue: Cannot enable "Do not allow bypassing"

**Solution:**
1. First verify all required status checks pass on a test PR
2. Ensure CODEOWNERS file is valid
3. Test with bypass enabled first
4. Enable bypass protection after confirming everything works

### Issue: CODEOWNERS reviews not required

**Solution:**
1. Verify CODEOWNERS file is at `.github/CODEOWNERS`
2. Ensure syntax is correct (no markdown headers in CODEOWNERS)
3. Test by creating PR that modifies a protected path
4. Verify appropriate owners are auto-requested as reviewers

---

## Phased Rollout Plan

If enabling all protections at once is too disruptive, use this phased approach:

### Phase 1 (Week 1)
- ✅ Require pull requests
- ✅ Require 1 approval
- ✅ Require status checks (but allow bypass for admins)

### Phase 2 (Week 2)
- ✅ Increase to 2 approvals
- ✅ Enable CODEOWNERS requirement
- ✅ Enable stale review dismissal

### Phase 3 (Week 3)
- ✅ Enable linear history requirement
- ✅ Enable conversation resolution requirement
- ✅ Disable admin bypass

### Phase 4 (Week 4+)
- ⚠️ Consider enabling signed commits (requires team setup)
- ⚠️ Add deployment protection rules (when CD is ready)

---

## Exceptions & Bypassing

### Emergency Access Procedure

In case branch protection must be temporarily disabled:

1. **Document the reason** in security log
2. **Get approval** from security team (@CalinL)
3. **Disable protection** temporarily
4. **Make emergency change**
5. **Re-enable protection** immediately
6. **Create follow-up PR** with proper review process
7. **Document in incident log**

### Emergency CLI Commands

```bash
# Temporarily disable enforcement for admins only
gh api repos/devopsabcs-engineering/gh-advsec-devsecops/branches/main/protection \
  --method PUT \
  --field enforce_admins=false

# Make emergency change
# ...

# Re-enable enforcement
gh api repos/devopsabcs-engineering/gh-advsec-devsecops/branches/main/protection \
  --method PUT \
  --field enforce_admins=true
```

---

## Related Documentation

- [GitHub Branch Protection Rules](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches)
- [Required Status Checks](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches#require-status-checks-before-merging)
- [CODEOWNERS Documentation](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-code-owners)
- [Supply Chain Security Report](./SUPPLY-CHAIN-SECURITY-REPORT.md)
- [Remediation Guide](./SUPPLY-CHAIN-REMEDIATION.md)

---

**Configuration Owner:** @CalinL  
**Last Verified:** 2026-02-04  
**Next Review:** 2026-03-04
