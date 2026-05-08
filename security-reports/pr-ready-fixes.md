# PR-Ready Security Fixes - webapp01

This document contains baseline security fixes that can be implemented immediately to address critical supply chain vulnerabilities.

---

## Fix 1: Update .gitignore to Exclude Sensitive Files

**Priority:** CRITICAL  
**File:** `.gitignore`  
**Action:** Add patterns to prevent committing secrets

### Unified Diff

```diff
--- a/.gitignore
+++ b/.gitignore
@@ -360,3 +360,13 @@
 *.msi
 *.msix
 *.msm
+
+# Sensitive configuration files (Supply Chain Security)
+# Prevent accidental commit of secrets
+**/.env
+**/.env.*
+!**/.env.example
+**/appsettings.Development.json
+**/appsettings.Production.json
+**/appsettings.Staging.json
+**/appsettings.*.json
```

**Justification:** The repository currently lacks protection against committing sensitive configuration files containing secrets, API keys, and connection strings. This fix prevents future accidental commits.

**Note:** Files already committed (`appsettings.json`, `appsettings.Development.json`) must be separately addressed by rotating secrets and removing from Git history.

---

## Fix 2: Enable NuGet Package Lockfile

**Priority:** HIGH  
**File:** `src/webapp01/webapp01.csproj`  
**Action:** Enable reproducible builds with lockfile

### Unified Diff

```diff
--- a/src/webapp01/webapp01.csproj
+++ b/src/webapp01/webapp01.csproj
@@ -6,6 +6,8 @@
     <ImplicitUsings>enable</ImplicitUsings>
     <UserSecretsId>7f0355f0-e3cb-4a1e-bf2d-0431db9b93f8</UserSecretsId>
     <DockerDefaultTargetOS>Linux</DockerDefaultTargetOS>
     <DockerfileContext>.</DockerfileContext>
+    <RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>
+    <RestoreLockedMode Condition="'$(CI)' == 'true'">true</RestoreLockedMode>
   </PropertyGroup>
   <ItemGroup>
```

**Next Steps After Applying:**
```bash
cd src/webapp01
dotnet restore
git add packages.lock.json
git commit -m "Add NuGet lockfile for reproducible builds"
```

**Justification:** Prevents supply chain attacks by ensuring all environments use identical dependency versions.

---

## Fix 3: Upgrade Vulnerable NuGet Packages

**Priority:** HIGH  
**File:** `src/webapp01/webapp01.csproj`  
**Action:** Update packages with known vulnerabilities

### Unified Diff

```diff
--- a/src/webapp01/webapp01.csproj
+++ b/src/webapp01/webapp01.csproj
@@ -9,10 +9,10 @@
     <DockerfileContext>.</DockerfileContext>
   </PropertyGroup>
   <ItemGroup>
-    <PackageReference Include="Azure.Identity" Version="1.13.2" />
-    <PackageReference Include="Microsoft.Data.SqlClient" Version="5.0.2" />
+    <PackageReference Include="Azure.Identity" Version="1.14.0" />
+    <PackageReference Include="Microsoft.Data.SqlClient" Version="5.2.1" />
     <PackageReference Include="Microsoft.VisualStudio.Azure.Containers.Tools.Targets" Version="1.21.0" />
-    <PackageReference Include="System.Text.Json" Version="8.0.4" />
-    <PackageReference Include="Newtonsoft.Json" Version="13.0.1" />
+    <PackageReference Include="System.Text.Json" Version="9.0.0" />
+    <PackageReference Include="Newtonsoft.Json" Version="13.0.3" />
   </ItemGroup>
 
 </Project>
```

**Critical Update:** `Microsoft.Data.SqlClient` 5.0.2 → 5.2.1 addresses CVE-2024-0056

**Testing Required:**
- Unit tests pass
- Integration tests with SQL Server
- No breaking API changes (review [release notes](https://github.com/dotnet/SqlClient/releases))

**Justification:** Eliminates known CVEs and brings dependencies to latest stable versions compatible with .NET 9.0.

---

## Fix 4: Remove Secrets from Configuration Files

**Priority:** CRITICAL  
**Files:** 
- `src/webapp01/appsettings.json`
- `src/webapp01/appsettings.Development.json`

**Action:** Remove hardcoded secrets, document migration to secure storage

### Before Applying This Fix:
1. **ROTATE ALL SECRETS IMMEDIATELY** (Azure Storage keys, GitHub tokens)
2. **Set up Azure Key Vault** for production secrets
3. **Configure User Secrets** for development: `dotnet user-secrets init` (already configured with UserSecretsId)

### Unified Diff - appsettings.json

```diff
--- a/src/webapp01/appsettings.json
+++ b/src/webapp01/appsettings.json
@@ -6,7 +6,11 @@
     }
   },
-  "AllowedHosts": "*",
-  "STORAGE_TEST":"18gryvHXuSVGDBcdJ3+QhRypNi413Kri8oalcQPAAZ7UGMHjaTVpSq4R9fYqzCsmZDnvK6AaE8Ce+AStDHNkpQ==",
-  "CUSTOM_TEST":"githubabcs_token_aB3dE5gH7jK9mN1pQ3sT5vW7yZ0Ab2De4Fg6Hi8Jk0Lm2No4Pq6Rs8Tu0Vw2Xy4Z"
+  "AllowedHosts": "*"
+  // SECURITY: Secrets removed - see migration guide below
+  // Production: Use Azure Key Vault references
+  // Development: Use dotnet user-secrets
+  //
+  // Example Key Vault reference:
+  // "StorageConnectionString": "@Microsoft.KeyVault(SecretUri=https://myvault.vault.azure.net/secrets/storage-connection/)"
 }
```

### Unified Diff - appsettings.Development.json

```diff
--- a/src/webapp01/appsettings.Development.json
+++ b/src/webapp01/appsettings.Development.json
@@ -4,6 +4,10 @@
     "LogLevel": {
       "Default": "Information",
       "Microsoft.AspNetCore": "Warning"
     }
-  },
-  "STORAGE_TEST":"18gryvHXuSVGDBcdJ3+QhRypNi413Kri8oalcQPAAZ7UGMHjaTVpSq4R9fYqzCsmZDnvK6AaE8Ce+AStDHNkpQ=="
+  }
+  // SECURITY: Use User Secrets for development
+  // Command: dotnet user-secrets set "STORAGE_TEST" "your-dev-storage-key"
+  // Command: dotnet user-secrets set "CUSTOM_TEST" "your-dev-token"
 }
```

### Set Up User Secrets for Development

```bash
cd src/webapp01

# Set development secrets (replace with actual rotated values)
dotnet user-secrets set "STORAGE_TEST" "<new-development-storage-key>"
dotnet user-secrets set "CUSTOM_TEST" "<new-development-token>"

# Verify
dotnet user-secrets list
```

### Set Up Azure Key Vault for Production

```bash
# Create Key Vault (if not exists)
az keyvault create --name myapp-keyvault --resource-group myapp-rg --location eastus

# Add secrets
az keyvault secret set --vault-name myapp-keyvault --name "storage-connection" --value "<rotated-storage-key>"
az keyvault secret set --vault-name myapp-keyvault --name "github-token" --value "<rotated-github-token>"

# Grant App Service Managed Identity access
az keyvault set-policy --name myapp-keyvault \
  --object-id <app-service-managed-identity-object-id> \
  --secret-permissions get list
```

**Production appsettings.json (after Key Vault setup):**
```json
{
  "Logging": { ... },
  "AllowedHosts": "*",
  "STORAGE_TEST": "@Microsoft.KeyVault(SecretUri=https://myapp-keyvault.vault.azure.net/secrets/storage-connection/)",
  "CUSTOM_TEST": "@Microsoft.KeyVault(SecretUri=https://myapp-keyvault.vault.azure.net/secrets/github-token/)"
}
```

**Justification:** Eliminates hardcoded secrets from version control, implements secure secrets management pattern.

---

## Fix 5: Remove Git History of Committed Secrets

**Priority:** CRITICAL  
**Action:** Purge sensitive data from Git history

### Method 1: Using git-filter-repo (Recommended)

```bash
# Install git-filter-repo
pip install git-filter-repo

# Backup repository first!
git clone --mirror https://github.com/devopsabcs-engineering/gh-advsec-devsecops.git backup-repo

# Remove specific secrets from history
cd gh-advsec-devsecops
git filter-repo --replace-text <(cat <<EOF
18gryvHXuSVGDBcdJ3+QhRypNi413Kri8oalcQPAAZ7UGMHjaTVpSq4R9fYqzCsmZDnvK6AaE8Ce+AStDHNkpQ==***REMOVED***
githubabcs_token_aB3dE5gH7jK9mN1pQ3sT5vW7yZ0Ab2De4Fg6Hi8Jk0Lm2No4Pq6Rs8Tu0Vw2Xy4Z***REMOVED***
Server=localhost;Database=TestDB;User Id=admin;Password=SecretPassword123!;***REMOVED***
Pass@word1***REMOVED***
EOF
)

# Force push (WARNING: Destructive operation)
git push origin --force --all
git push origin --force --tags
```

### Method 2: Using BFG Repo-Cleaner (Alternative)

```bash
# Download BFG
wget https://repo1.maven.org/maven2/com/madgag/bfg/1.14.0/bfg-1.14.0.jar

# Create text file with secrets to remove
cat > secrets.txt <<EOF
18gryvHXuSVGDBcdJ3+QhRypNi413Kri8oalcQPAAZ7UGMHjaTVpSq4R9fYqzCsmZDnvK6AaE8Ce+AStDHNkpQ==
githubabcs_token_aB3dE5gH7jK9mN1pQ3sT5vW7yZ0Ab2De4Fg6Hi8Jk0Lm2No4Pq6Rs8Tu0Vw2Xy4Z
SecretPassword123!
Pass@word1
EOF

# Run BFG
java -jar bfg-1.14.0.jar --replace-text secrets.txt

# Clean up
git reflog expire --expire=now --all && git gc --prune=now --aggressive

# Force push
git push --force
```

**⚠️ WARNING:**
- Force pushing rewrites history and will cause issues for anyone with cloned repositories
- Notify all team members to re-clone after cleanup
- Consider rotating secrets **before** removing from history

**Post-Cleanup Actions:**
1. Verify secrets removed: `git log -p --all -S "18gryvHXu" --source --all`
2. Re-clone repository on all developer machines
3. Update CI/CD to re-clone

**Justification:** Committed secrets remain accessible in Git history even after removal from current files. Complete remediation requires history rewrite.

---

## Fix 6: Pin Dockerfile Base Images

**Priority:** MEDIUM  
**File:** `src/webapp01/Dockerfile`  
**Action:** Pin to specific digests for reproducible builds

### Get Current Digests

```bash
# Get current SHA256 digests
docker pull mcr.microsoft.com/dotnet/aspnet:9.0
docker pull mcr.microsoft.com/dotnet/sdk:9.0

docker inspect --format='{{index .RepoDigests 0}}' mcr.microsoft.com/dotnet/aspnet:9.0
docker inspect --format='{{index .RepoDigests 0}}' mcr.microsoft.com/dotnet/sdk:9.0
```

### Unified Diff (Example with May 2026 digests)

```diff
--- a/src/webapp01/Dockerfile
+++ b/src/webapp01/Dockerfile
@@ -1,10 +1,12 @@
 # See https://aka.ms/customizecontainer to learn how to customize your debug container and how Visual Studio uses this Dockerfile to build your images for faster debugging.
 
 # This stage is used when running from VS in fast mode (Default for Debug configuration)
-FROM mcr.microsoft.com/dotnet/aspnet:9.0 AS base
+# Pinned to digest (May 2026) - update quarterly or when security patches released
+FROM mcr.microsoft.com/dotnet/aspnet:9.0@sha256:abcdef1234567890... AS base
 WORKDIR /app
 EXPOSE 8080
 EXPOSE 8081
 
 # This stage is used to build the service project
-FROM mcr.microsoft.com/dotnet/sdk:9.0 AS build
+# Pinned to digest (May 2026)
+FROM mcr.microsoft.com/dotnet/sdk:9.0@sha256:1234567890abcdef... AS build
```

**Maintenance:** Update digests quarterly or when Microsoft releases security patches

**Justification:** Prevents supply chain attacks through base image tampering, ensures reproducible builds.

---

## Fix 7: Add SBOM to Release Artifacts

**Priority:** MEDIUM  
**File:** `.github/workflows/SCA-Microsoft-SBOM.yml`  
**Action:** Archive SBOM for compliance

### Unified Diff

```diff
--- a/.github/workflows/SCA-Microsoft-SBOM.yml
+++ b/.github/workflows/SCA-Microsoft-SBOM.yml
@@ -44,3 +44,13 @@ jobs:
     - name: SBOM upload 
       uses: advanced-security/spdx-dependency-submission-action@5530bab9ee4bbe66420ce8280624036c77f89746 # v0.1.1
       with:
         filePath: "buildOutput/_manifest/spdx_2.2/"
+
+    - name: Archive SBOM for Release
+      if: startsWith(github.ref, 'refs/tags/')
+      uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4.6.2
+      with:
+        name: sbom-${{ github.ref_name }}
+        path: buildOutput/_manifest/spdx_2.2/
+        retention-days: 90
+        if-no-files-found: error
```

**Trigger:** Only for tagged releases (`refs/tags/*`)  
**Retention:** 90 days (adjust based on compliance requirements)

**Justification:** Enables compliance audits and vulnerability tracking for released versions.

---

## Implementation Checklist

### Critical (Immediate - Today)
- [ ] **Rotate Azure Storage key** (appsettings.json)
- [ ] **Rotate GitHub token** (appsettings.json)
- [ ] Apply Fix 1: Update `.gitignore`
- [ ] Apply Fix 4: Remove secrets from config files
- [ ] Apply Fix 5: Remove secrets from Git history (after rotation)

### High Priority (This Week)
- [ ] Apply Fix 2: Enable NuGet lockfile
- [ ] Apply Fix 3: Upgrade vulnerable packages
- [ ] Set up Azure Key Vault for production
- [ ] Configure User Secrets for development
- [ ] Test application with new dependencies

### Medium Priority (This Sprint)
- [ ] Apply Fix 6: Pin Dockerfile base images
- [ ] Apply Fix 7: Archive SBOM artifacts
- [ ] Enable GitHub Secret Scanning & Push Protection
- [ ] Review Dependabot alerts

### Validation
- [ ] Run all unit tests
- [ ] Run integration tests
- [ ] Security scan passes (CodeQL, Dependabot)
- [ ] Application builds and deploys successfully
- [ ] No secrets detected in `git log`

---

**Document Version:** 1.0  
**Created:** May 8, 2026  
**Author:** SupplyChainSecurityAgent  
**Status:** Ready for Review
