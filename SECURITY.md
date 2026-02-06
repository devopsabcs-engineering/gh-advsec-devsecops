# Security Policy

## Supported Versions

This DevSecOps demonstration repository is actively maintained. Security updates are applied to:

| Component | Version | Supported          |
| --------- | ------- | ------------------ |
| Web App (ASP.NET Core) | 9.0.x   | :white_check_mark: |
| .NET SDK | 9.0.x   | :white_check_mark: |
| Docker Base Images | latest  | :white_check_mark: |
| Infrastructure (Bicep/Terraform) | latest  | :white_check_mark: |

## Reporting a Vulnerability

**Please report security vulnerabilities through [GitHub Security Advisories](../../security/advisories/new).**

### DO NOT:
- ❌ Open public issues for security vulnerabilities
- ❌ Disclose details publicly before a fix is available
- ❌ Share exploit code in public forums

### Expected Response Timeline:
- **Acknowledgment:** Within 48 hours
- **Initial Assessment:** Within 5 business days
- **Status Update:** Within 7 days
- **Fix Timeline:** Communicated within 14 days based on severity

### Severity Classification:
- **Critical:** Immediate fix (24-48 hours)
- **High:** Fix within 7 days
- **Medium:** Fix within 30 days
- **Low:** Fix in next planned release

## Security Measures

This repository implements:
- ✅ GitHub Advanced Security (secret scanning with push protection, code scanning, dependency scanning)
- ✅ Dependabot security updates (weekly)
- ✅ Required code review for all changes (CODEOWNERS enforcement)
- ✅ SBOM generation for all releases (SPDX 2.2 format)
- ✅ Multiple security scanning tools (CodeQL, Trivy, KICS, tfsec, Microsoft Security DevOps)
- ✅ OpenSSF Scorecard monitoring

## Secure Development Practices

### Secrets Management
- User Secrets for local development
- Azure Key Vault for production secrets
- No credentials in source control
- Secret scanning enabled with push protection

### Dependency Management
- Dependabot automated updates
- Dependency Review on pull requests
- Vulnerable dependency blocking (severity: moderate+)
- License compliance enforcement

### CI/CD Security
- Least privilege permissions (id-token: write, contents: read)
- OIDC federation for Azure authentication (no long-lived secrets)
- Multiple security gates in pipeline
- Artifact attestation and SBOM generation

## Contact

For security concerns, contact: @CalinL

**Repository Maintainer:** @CalinL  
**Last Updated:** 2026-02-04
