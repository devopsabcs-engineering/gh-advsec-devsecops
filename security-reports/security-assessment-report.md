# Security Assessment Report

**Repository:** gh-advsec-devsecops  
**Assessment Date:** February 9, 2026  
**Primary Application:** ASP.NET Core Razor Pages Web Application (`src/webapp01`)  
**Scope:** Application code, IaC (Terraform/Bicep), CI/CD pipelines, Kubernetes manifests

---

## Executive Summary

This security assessment has identified **CRITICAL vulnerabilities** in the repository that require immediate remediation. The assessment found:

- **5 CRITICAL** severity vulnerabilities
- **11 HIGH** severity vulnerabilities  
- **9 MEDIUM** severity vulnerabilities
- **3 LOW** severity vulnerabilities

### Top Risks

1. **Hardcoded secrets in source control** - Multiple API keys, tokens, and passwords committed to the repository
2. **Command injection vulnerability** - User input used in system commands without validation
3. **SQL injection risk** - Hardcoded connection strings with credentials in code
4. **Overly permissive network rules** - Infrastructure allows unrestricted access from the internet
5. **Weak cryptographic algorithms** - Use of broken hash functions (MD5, SHA1)

### Quick Wins

1. Remove all hardcoded secrets from [appsettings.json](c:\src\GitHub\devopsabcs-engineering\gh-advsec-devsecops\src\webapp01\appsettings.json) and [appsettings.Development.json](c:\src\GitHub\devopsabcs-engineering\gh-advsec-devsecops\src\webapp01\appsettings.Development.json)
2. Implement input validation in [Index.cshtml.cs](c:\src\GitHub\devopsabcs-engineering\gh-advsec-devsecops\src\webapp01\Pages\Index.cshtml.cs) to prevent command injection
3. Enable RBAC on AKS cluster in [aks.tf](c:\src\GitHub\devopsabcs-engineering\gh-advsec-devsecops\terraform\azure\aks.tf)
4. Restrict network rules to specific IP ranges in [networking.tf](c:\src\GitHub\devopsabcs-engineering\gh-advsec-devsecops\terraform\azure\networking.tf)
5. Enable SSL enforcement on database servers in [sql.tf](c:\src\GitHub\devopsabcs-engineering\gh-advsec-devsecops\terraform\azure\sql.tf)

---

## Findings (Prioritized by Severity)

### 🔴 CRITICAL Severity

#### 1. Hardcoded Secrets in Configuration Files

**Severity:** CRITICAL  
**Category:** CWE-798 (Use of Hard-coded Credentials)  
**OWASP:** A07:2021 - Identification and Authentication Failures

**Location:**
- [appsettings.json](c:\src\GitHub\devopsabcs-engineering\gh-advsec-devsecops\src\webapp01\appsettings.json#L9-L10)
- [appsettings.Development.json](c:\src\GitHub\devopsabcs-engineering\gh-advsec-devsecops\src\webapp01\appsettings.Development.json#L9)

**Description:**  
The application configuration files contain hardcoded sensitive credentials:
- `STORAGE_TEST`: Appears to be an Azure Storage Account access key (88 characters, base64-encoded)
- `CUSTOM_TEST`: Appears to be a GitHub token (`githubabcs_token_aB3dE5gH7jK9mN1pQ3sT5vW7yZ0Ab2De4Fg6Hi8Jk0Lm2No4Pq6Rs8Tu0Vw2Xy4Z`)

These secrets are committed to source control and could be used by attackers to access Azure storage resources and GitHub repositories.

**Impact:**  
- Unauthorized access to Azure Storage accounts
- Potential data exfiltration or modification
- Compromise of GitHub repositories and CI/CD pipelines
- Exposure of customer data

**Recommendation:**
```csharp
// SECURE - Use Azure Key Vault or User Secrets for development
// In Program.cs:
if (builder.Environment.IsDevelopment())
{
    builder.Configuration.AddUserSecrets<Program>();
}
else
{
    builder.Configuration.AddAzureKeyVault(
        new Uri($"https://{builder.Configuration["KeyVaultName"]}.vault.azure.net/"),
        new DefaultAzureCredential());
}

// Remove all secrets from appsettings.json
// Use managed identities for Azure resources
// Use environment variables or Key Vault for secrets
```

**Action Required:**
1. **IMMEDIATELY** rotate both credentials
2. Remove secrets from appsettings.json files
3. Add `appsettings.*.json` patterns to `.gitignore` or use User Secrets
4. Implement Azure Key Vault integration
5. Scan git history and remove sensitive data using `git filter-branch` or BFG Repo-Cleaner

---

#### 2. Command Injection Vulnerability

**Severity:** CRITICAL  
**Category:** CWE-78 (OS Command Injection)  
**OWASP:** A03:2021 - Injection

**Location:**
- [Index.cshtml.cs](c:\src\GitHub\devopsabcs-engineering\gh-advsec-devsecops\src\webapp01\Pages\Index.cshtml.cs#L20-L23)

**Description:**  
The `OnGet()` method in IndexModel accepts user input from the query string parameter "drive" and directly uses it to construct a system command string without any validation or sanitization:

```csharp
string drive = Request.Query.ContainsKey("drive") ? Request.Query["drive"] : "C";
var str = $"/C fsutil volume diskfree {drive}:";
_logger.LogInformation($"Command str: {str}");
```

While the command is only logged (not executed), this demonstrates an insecure pattern. If this command were executed using `Process.Start()` or similar, it would allow arbitrary command execution.

**Impact:**
- Arbitrary command execution on the server
- Remote code execution (RCE)
- Complete system compromise
- Data exfiltration or destruction

**Recommendation:**
```csharp
// SECURE - Validate and allowlist input
public void OnGet()
{
    // Allowlist valid drive letters
    string drive = Request.Query.ContainsKey("drive") ? Request.Query["drive"].ToString() : "C";
    
    // Validate that drive is a single letter A-Z (case insensitive)
    if (!Regex.IsMatch(drive, @"^[A-Za-z]$"))
    {
        _logger.LogWarning($"Invalid drive letter attempted: {drive}");
        drive = "C"; // Default to safe value
    }
    
    // Use parameterized approach or safe API instead of shell commands
    var driveInfo = new DriveInfo(drive);
    long freeSpace = driveInfo.AvailableFreeSpace;
    _logger.LogInformation($"Drive {drive}: has {freeSpace} bytes free");
}
```

**Alternative:** Use .NET DriveInfo API instead of shell commands entirely.

---

#### 3. Hardcoded Database Credentials in Code

**Severity:** CRITICAL  
**Category:** CWE-798 (Use of Hard-coded Credentials)  
**OWASP:** A07:2021 - Identification and Authentication Failures

**Location:**
- [DevSecOps.cshtml.cs](c:\src\GitHub\devopsabcs-engineering\gh-advsec-devsecops\src\webapp01\Pages\DevSecOps.cshtml.cs#L15)

**Description:**  
Database connection string with credentials hardcoded directly in source code:

```csharp
private const string CONNECTION_STRING = "Server=localhost;Database=TestDB;User Id=admin;Password=SecretPassword123!;";
```

**Impact:**
- Unauthorized database access
- Data breach
- Credentials exposed in compiled assemblies
- Cannot rotate credentials without code changes

**Recommendation:**
```csharp
// SECURE - Use configuration with Azure Key Vault
public class DevSecOpsModel : PageModel
{
    private readonly IConfiguration _configuration;
    
    public DevSecOpsModel(ILogger<DevSecOpsModel> logger, IConfiguration configuration)
    {
        _logger = logger;
        _configuration = configuration;
    }
    
    public void OnGet()
    {
        // Get connection string from configuration
        string connectionString = _configuration.GetConnectionString("DefaultConnection");
        
        // OR use Azure.Identity with SQL Server
        using var connection = new SqlConnection(connectionString);
        connection.AccessToken = await new DefaultAzureCredential().GetTokenAsync(
            new TokenRequestContext(new[] { "https://database.windows.net/.default" }));
    }
}
```

---

#### 4. Hardcoded Database Passwords in Terraform

**Severity:** CRITICAL  
**Category:** CWE-798 (Use of Hard-coded Credentials)  
**OWASP:** A07:2021 - Identification and Authentication Failures

**Location:**
- [sql.tf](c:\src\GitHub\devopsabcs-engineering\gh-advsec-devsecops\terraform\azure\sql.tf#L15)
- [sql.tf](c:\src\GitHub\devopsabcs-engineering\gh-advsec-devsecops\terraform\azure\sql.tf#L65)

**Description:**  
Database administrator passwords hardcoded in Terraform configuration:

```terraform
administrator_login_password = "Aa12345678"  # Line 15 and 65
```

These passwords are stored in:
1. Source control
2. Terraform state files (which may be in remote backends)
3. Plan files
4. Potentially in logs

**Impact:**
- Unauthorized database admin access
- Complete database compromise
- Passwords exposed in multiple locations
- Terraform state files contain plaintext passwords

**Recommendation:**
```terraform
# SECURE - Use random password with Key Vault storage
resource "random_password" "sql_admin_password" {
  length  = 32
  special = true
}

resource "azurerm_key_vault_secret" "sql_admin_password" {
  name         = "sql-admin-password"
  value        = random_password.sql_admin_password.result
  key_vault_id = azurerm_key_vault.example.id
}

resource "azurerm_sql_server" "example" {
  name                         = "terragoat-sqlserver-${var.environment}${random_integer.rnd_int.result}"
  resource_group_name          = azurerm_resource_group.example.name
  location                     = azurerm_resource_group.example.location
  version                      = "12.0"
  administrator_login          = "sqladmin"
  administrator_login_password = random_password.sql_admin_password.result
  
  # OR better: Use Azure AD authentication only
  azuread_administrator {
    login_username = "sql-admin-group"
    object_id      = var.sql_admin_group_object_id
  }
}
```

---

#### 5. SQL Security Alerts Disabled for Critical Threats

**Severity:** CRITICAL  
**Category:** CWE-778 (Insufficient Logging)  
**OWASP:** A09:2021 - Security Logging and Monitoring Failures

**Location:**
- [sql.tf](c:\src\GitHub\devopsabcs-engineering\gh-advsec-devsecops\terraform\azure\sql.tf#L28-L29)

**Description:**  
SQL Server security alert policy explicitly disables alerts for critical security events:

```terraform
disabled_alerts = [
  "Sql_Injection",
  "Data_Exfiltration"
]
```

**Impact:**
- No alerting for SQL injection attacks
- No alerting for data exfiltration attempts
- Attackers can operate undetected
- Compliance violations (PCI-DSS, HIPAA, SOC 2)

**Recommendation:**
```terraform
# SECURE - Enable all security alerts
resource "azurerm_mssql_server_security_alert_policy" "example" {
  resource_group_name        = azurerm_resource_group.example.name
  server_name                = azurerm_sql_server.example.name
  state                      = "Enabled"
  storage_endpoint           = azurerm_storage_account.example.primary_blob_endpoint
  storage_account_access_key = azurerm_storage_account.example.primary_access_key
  disabled_alerts            = []  # Enable all alerts
  retention_days             = 90   # Increase retention
  email_addresses            = ["security-team@example.com"]
  email_account_admins       = true
}
```

---

### 🟠 HIGH Severity

#### 6. Regular Expression Denial of Service (ReDoS)

**Severity:** HIGH  
**Category:** CWE-1333 (Inefficient Regular Expression Complexity)  
**OWASP:** A05:2021 - Security Misconfiguration

**Location:**
- [DevSecOps.cshtml.cs](c:\src\GitHub\devopsabcs-engineering\gh-advsec-devsecops\src\webapp01\Pages\DevSecOps.cshtml.cs#L18)

**Description:**  
Catastrophically vulnerable regex pattern that can cause exponential backtracking:

```csharp
private static readonly Regex VulnerableRegex = new Regex(@"^(a+)+$", RegexOptions.Compiled);
```

The pattern `(a+)+` with nested quantifiers causes exponential time complexity. Input like "aaaaaaaaaaaaaaaaaaaaX" can hang the server for seconds to minutes.

**Impact:**
- Denial of Service attacks
- Application unresponsiveness
- Server resource exhaustion
- Affects all users of the application

**Recommendation:**
```csharp
// SECURE - Avoid nested quantifiers, use atomic grouping or possessive quantifiers
private static readonly Regex SafeRegex = new Regex(@"^a+$", RegexOptions.Compiled, TimeSpan.FromMilliseconds(100));

// Or use built-in string methods when possible
public bool IsAllAs(string input)
{
    return !string.IsNullOrEmpty(input) && input.All(c => c == 'a');
}

// Always set a timeout for regex operations
private static readonly Regex SaferRegex = new Regex(
    @"^(?>a+)$",  // Atomic grouping prevents backtracking
    RegexOptions.Compiled,
    TimeSpan.FromMilliseconds(100)
);
```

---

#### 7. Unrestricted Network Access - SSH & RDP

**Severity:** HIGH  
**Category:** CWE-284 (Improper Access Control)  
**OWASP:** A01:2021 - Broken Access Control

**Location:**
- [networking.tf](c:\src\GitHub\devopsabcs-engineering\gh-advsec-devsecops\terraform\azure\networking.tf#L44-L68)
- [example-02.tf](c:\src\GitHub\devopsabcs-engineering\gh-advsec-devsecops\devsecops-demo-01\example-02.tf#L53-L63)

**Description:**  
Network security groups allow SSH (port 22) and RDP (port 3389) from any source IP address (`0.0.0.0/0`):

```terraform
security_rule {
  access                 = "Allow"
  direction              = "Inbound"
  name                   = "AllowSSH"
  priority               = 200
  protocol               = "TCP"
  source_address_prefix  = "*"  # ← Allows traffic from anywhere
  source_port_range      = "*"
  destination_port_range = "22-22"
  destination_address_prefix = "*"
}
```

**Impact:**
- Exposed management interfaces to internet-wide scanning and attacks
- Brute force attacks on SSH/RDP services
- Increased attack surface
- Potential for unauthorized access

**Recommendation:**
```terraform
# SECURE - Restrict to specific IP ranges or use Azure Bastion
resource "azurerm_network_security_group" "secure_sg" {
  location            = var.location
  name                = "terragoat-${var.environment}"
  resource_group_name = azurerm_resource_group.example.name

  # Option 1: Restrict to corporate IP ranges
  security_rule {
    access                     = "Allow"
    direction                  = "Inbound"
    name                       = "AllowSSHFromCorporate"
    priority                   = 200
    protocol                   = "TCP"
    source_address_prefixes    = ["203.0.113.0/24", "198.51.100.0/24"]  # Corporate IPs
    source_port_range          = "*"
    destination_port_range     = "22"
    destination_address_prefix = "*"
  }

  # Option 2: BETTER - Use Azure Bastion instead
  # Remove direct SSH/RDP rules and deploy Azure Bastion
  # Users connect through Azure Portal with Azure AD authentication
}

# Deploy Azure Bastion for secure access
resource "azurerm_bastion_host" "example" {
  name                = "bastion-${var.environment}"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  
  ip_configuration {
    name                 = "configuration"
    subnet_id            = azurerm_subnet.bastion_subnet.id
    public_ip_address_id = azurerm_public_ip.bastion_pip.id
  }
}
```

---

#### 8. SSL/TLS Encryption Disabled on Database Servers

**Severity:** HIGH  
**Category:** CWE-319 (Cleartext Transmission of Sensitive Information)  
**OWASP:** A02:2021 - Cryptographic Failures

**Location:**
- [sql.tf](c:\src\GitHub\devopsabcs-engineering\gh-advsec-devsecops\terraform\azure\sql.tf#L53) - MySQL
- [sql.tf](c:\src\GitHub\devopsabcs-engineering\gh-advsec-devsecops\terraform\azure\sql.tf#L68) - PostgreSQL

**Description:**  
SSL enforcement is explicitly disabled on MySQL and PostgreSQL servers:

```terraform
resource "azurerm_mysql_server" "example" {
  # ...
  ssl_enforcement_enabled = false  # ← INSECURE
}

resource "azurerm_postgresql_server" "example" {
  # ...
  ssl_enforcement_enabled = false  # ← INSECURE
}
```

**Impact:**
- Database credentials transmitted in plaintext
- Data transmitted unencrypted over the network
- Vulnerable to man-in-the-middle attacks
- Compliance violations (PCI-DSS requires encryption in transit)

**Recommendation:**
```terraform
# SECURE - Enable SSL enforcement
resource "azurerm_mysql_server" "example" {
  name                = "terragoat-mysql-${var.environment}${random_integer.rnd_int.result}"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name

  administrator_login          = "mysqladmin"
  administrator_login_password = random_password.mysql_password.result

  sku_name   = "GP_Gen5_2"  # Use General Purpose tier for better security
  storage_mb = 5120
  version    = "8.0"  # Use latest stable version

  auto_grow_enabled                 = true
  backup_retention_days             = 35  # Increase backup retention
  infrastructure_encryption_enabled = true
  public_network_access_enabled     = false  # Disable public access
  ssl_enforcement_enabled           = true   # ✓ Enable SSL
  ssl_minimal_tls_version_enforced  = "TLS1_2"  # Enforce TLS 1.2+
}
```

---

#### 9. Privileged Kubernetes Containers

**Severity:** HIGH  
**Category:** CWE-250 (Execution with Unnecessary Privileges)  
**OWASP K02:** (Kubernetes Top 10) - Supply Chain Vulnerabilities

**Location:**
- [critical-double.yaml](c:\src\GitHub\devopsabcs-engineering\gh-advsec-devsecops\manifests\critical-double.yaml#L9-L11)

**Description:**  
Kubernetes pod configured with both privileged mode and privilege escalation enabled:

```yaml
securityContext:
  allowPrivilegeEscalation: true
  privileged: true
```

This gives the container full access to the host system, bypassing all container isolation.

**Impact:**
- Container can access host filesystem
- Can load kernel modules
- Can access all host devices
- Complete host compromise possible
- Container escape to underlying node

**Recommendation:**
```yaml
# SECURE - Follow principle of least privilege
apiVersion: v1
kind: Pod
metadata:
  name: secure-pod
spec:
  containers:
  - name: secure-app
    image: gcr.io/google-samples/node-hello:1.0
    securityContext:
      allowPrivilegeEscalation: false
      privileged: false
      runAsNonRoot: true
      runAsUser: 1000
      readOnlyRootFilesystem: true
      capabilities:
        drop:
          - ALL
  # Add Pod Security Standard enforcement
  securityContext:
    seccompProfile:
      type: RuntimeDefault
```

Also implement Pod Security Standards at namespace level:
```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: production
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
```

---

#### 10. RBAC Disabled on AKS Cluster

**Severity:** HIGH  
**Category:** CWE-284 (Improper Access Control)  
**OWASP:** A01:2021 - Broken Access Control

**Location:**
- [aks.tf](c:\src\GitHub\devopsabcs-engineering\gh-advsec-devsecops\terraform\azure\aks.tf#L22-L24)

**Description:**  
Role-Based Access Control (RBAC) is explicitly disabled on the AKS cluster:

```terraform
role_based_access_control {
  enabled = false
}
```

**Impact:**
- All authenticated users have cluster-admin privileges
- No ability to implement principle of least privilege
- Cannot segregate duties between teams
- Difficult to implement compliance controls
- Audit trail is limited

**Recommendation:**
```terraform
# SECURE - Enable RBAC with Azure AD integration
resource "azurerm_kubernetes_cluster" "k8s_cluster" {
  dns_prefix          = "secure-cluster-${var.environment}"
  location            = var.location
  name                = "aks-cluster-${var.environment}"
  resource_group_name = azurerm_resource_group.example.name
  
  identity {
    type = "SystemAssigned"
  }
  
  default_node_pool {
    name       = "default"
    vm_size    = "Standard_D2_v2"
    node_count = 2
    
    # Enable security features on nodes
    upgrade_settings {
      max_surge = "33%"
    }
  }
  
  # Enable Azure AD integration
  azure_active_directory_role_based_access_control {
    managed                = true
    azure_rbac_enabled     = true
    admin_group_object_ids = [var.aks_admin_group_object_id]
  }

  # Enable monitoring
  oms_agent {
    log_analytics_workspace_id = azurerm_log_analytics_workspace.example.id
  }

  # Enable network policy
  network_profile {
    network_plugin = "azure"
    network_policy = "calico"  # or "azure"
  }

  # Disable Kubernetes dashboard (deprecated and insecure)
  addon_profile {
    kube_dashboard {
      enabled = false
    }
  }
}
```

---

#### 11. Weak Cryptographic Hash Functions

**Severity:** HIGH  
**Category:** CWE-327 (Use of Broken or Risky Cryptographic Algorithm)  
**OWASP:** A02:2021 - Cryptographic Failures

**Location:**
- [insecure-01.py](c:\src\GitHub\devopsabcs-engineering\gh-advsec-devsecops\devsecops-demo-01\insecure-01.py#L24-L25)

**Description:**  
Use of cryptographically broken hash functions MD5 and SHA1:

```python
print("MD5: " + hashlib.md5(s).hexdigest())
print("SHA1: " + hashlib.sha1(s).hexdigest())
```

MD5 has been broken since 2004, and SHA1 has been deprecated since 2017. Both are vulnerable to collision attacks.

**Impact:**
- If used for password hashing: easy to crack with rainbow tables
- If used for integrity verification: vulnerable to collision attacks
- If used for digital signatures: forgery is possible
- Compliance violations

**Recommendation:**
```python
# SECURE - Use modern hash functions
import hashlib

# For general-purpose hashing (file integrity, checksums)
hash_sha256 = hashlib.sha256(data).hexdigest()
hash_sha512 = hashlib.sha512(data).hexdigest()

# For password hashing, use dedicated password hash functions
import bcrypt
password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

# Or use Argon2 (winner of Password Hashing Competition)
from argon2 import PasswordHasher
ph = PasswordHasher()
password_hash = ph.hash(password)
```

---

#### 12. Log Injection/Forging Vulnerabilities

**Severity:** HIGH  
**Category:** CWE-117 (Improper Output Neutralization for Logs)  
**OWASP:** A09:2021 - Security Logging and Monitoring Failures

**Location:**
- [DevSecOps.cshtml.cs](c:\src\GitHub\devopsabcs-engineering\gh-advsec-devsecops\src\webapp01\Pages\DevSecOps.cshtml.cs#L27-L28)
- [DevSecOps.cshtml.cs](c:\src\GitHub\devopsabcs-engineering\gh-advsec-devsecops\src\webapp01\Pages\DevSecOps.cshtml.cs#L36)
- [DevSecOps.cshtml.cs](c:\src\GitHub\devopsabcs-engineering\gh-advsec-devsecops\src\webapp01\Pages\DevSecOps.cshtml.cs#L87)
- [Index.cshtml.cs](c:\src\GitHub\devopsabcs-engineering\gh-advsec-devsecops\src\webapp01\Pages\Index.cshtml.cs#L22-L23)

**Description:**  
User-controlled input is directly interpolated into log messages without sanitization:

```csharp
string userInput = Request.Query["user"].ToString() ?? "anonymous";
_logger.LogInformation($"User accessed DevSecOps page: {userInput}");
```

An attacker can inject newlines and fake log entries:
```
?user=admin%0A[ERROR] Authentication bypassed for admin
```

**Impact:**
- Log forgery - attacker can create fake log entries
- Security monitoring evasion
- SIEM/log analysis tools can be confused
- Forensic investigation can be compromised
- Compliance violations (log integrity requirements)

**Recommendation:**
```csharp
// SECURE - Use structured logging with sanitization
public void OnGet()
{
    string userInput = Request.Query.ContainsKey("user") 
        ? Request.Query["user"].ToString() ?? "anonymous" 
        : "anonymous";
    
    // Remove newlines and control characters
    userInput = Regex.Replace(userInput, @"[\r\n\t]", "");
    
    // Limit length
    if (userInput.Length > 100)
        userInput = userInput.Substring(0, 100);
    
    // Use structured logging (parameters are automatically escaped)
    _logger.LogInformation("User accessed DevSecOps page: {UserInput}", userInput);
    // NOT: _logger.LogInformation($"User: {userInput}");
}

// Better: Use structured logging throughout
_logger.LogInformation(
    "Page accessed by {User} from {IpAddress} at {Timestamp}",
    userInput,
    HttpContext.Connection.RemoteIpAddress,
    DateTime.UtcNow
);
```

---

#### 13. Public Network Access Enabled on Database

**Severity:** HIGH  
**Category:** CWE-284 (Improper Access Control)  
**OWASP:** A01:2021 - Broken Access Control

**Location:**
- [sql.tf](c:\src\GitHub\devopsabcs-engineering\gh-advsec-devsecops\terraform\azure\sql.tf#L51)

**Description:**  
MySQL server has public network access enabled, exposing the database to the internet:

```terraform
public_network_access_enabled = true
```

**Impact:**
- Database exposed to internet-wide scanning
- Increased attack surface for brute force attacks
- Higher risk of data breach
- Cannot enforce network segmentation

**Recommendation:**
```terraform
# SECURE - Disable public access, use private endpoints
resource "azurerm_mysql_server" "example" {
  name                = "mysql-${var.environment}"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name

  # ... other configuration ...

  public_network_access_enabled = false  # ✓ Disable public access
  ssl_enforcement_enabled        = true
  ssl_minimal_tls_version_enforced = "TLS1_2"
}

# Use private endpoint for access
resource "azurerm_private_endpoint" "mysql" {
  name                = "pe-mysql-${var.environment}"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  subnet_id           = azurerm_subnet.private_endpoint_subnet.id

  private_service_connection {
    name                           = "psc-mysql"
    private_connection_resource_id = azurerm_mysql_server.example.id
    is_manual_connection          = false
    subresource_names             = ["mysqlServer"]
  }
}

# Or use VNet rules for specific subnets
resource "azurerm_mysql_virtual_network_rule" "example" {
  name                = "mysql-vnet-rule"
  resource_group_name = azurerm_resource_group.example.name
  server_name         = azurerm_mysql_server.example.name
  subnet_id           = azurerm_subnet.app_subnet.id
}
```

---

#### 14. Hardcoded Default Password

**Severity:** HIGH  
**Category:** CWE-798 (Use of Hard-coded Credentials)  
**OWASP:** A07:2021 - Identification and Authentication Failures

**Location:**
- [Index.cshtml.cs](c:\src\GitHub\devopsabcs-engineering\gh-advsec-devsecops\src\webapp01\Pages\Index.cshtml.cs#L11)

**Description:**  
Default password hardcoded as a public constant:

```csharp
// TODO: Don't use this in production
public const string DEFAULT_PASSWORD = "Pass@word1";
```

**Impact:**
- Known default password
- Cannot be changed without recompiling
- Visible in compiled assemblies
- If used in production, provides easy access for attackers

**Recommendation:**
```csharp
// REMOVE the hardcoded password entirely
// Use proper authentication with ASP.NET Core Identity

// In Program.cs:
builder.Services.AddIdentity<ApplicationUser, IdentityRole>(options =>
{
    // Configure password requirements
    options.Password.RequireDigit = true;
    options.Password.RequireLowercase = true;
    options.Password.RequireUppercase = true;
    options.Password.RequireNonAlphanumeric = true;
    options.Password.RequiredLength = 12;
})
.AddEntityFrameworkStores<ApplicationDbContext>()
.AddDefaultTokenProviders();

// Never hardcode passwords in code
```

---

#### 15. Insecure Network Protocol Libraries

**Severity:** HIGH  
**Category:** CWE-319 (Cleartext Transmission of Sensitive Information)  
**OWASP:** A02:2021 - Cryptographic Failures

**Location:**
- [insecure-01.py](c:\src\GitHub\devopsabcs-engineering\gh-advsec-devsecops\devsecops-demo-01\insecure-01.py#L17-L18)

**Description:**  
Importing libraries for insecure cleartext protocols:

```python
import telnetlib  # Telnet - unencrypted
import ftplib     # FTP - unencrypted
```

**Impact:**
- Credentials transmitted in plaintext
- Data transmitted unencrypted
- Vulnerable to packet sniffing and MITM attacks

**Recommendation:**
```python
# SECURE - Use encrypted alternatives
import paramiko  # For SSH instead of Telnet

# For FTPS (FTP over TLS)
from ftplib import FTP_TLS
ftps = FTP_TLS('ftp.example.com')
ftps.login('user', 'pass')
ftps.prot_p()  # Enable encryption

# Better: Use SFTP via paramiko
ssh = paramiko.SSHClient()
ssh.connect('host', username='user', password='pass')
sftp = ssh.open_sftp()
```

---

#### 16. Unrestricted HTTP/HTTPS Access from Internet

**Severity:** HIGH  
**Category:** CWE-284 (Improper Access Control)  
**OWASP:** A01:2021 - Broken Access Control

**Location:**
- [example-02.tf](c:\src\GitHub\devopsabcs-engineering\gh-advsec-devsecops\devsecops-demo-01\example-02.tf#L29-L52)

**Description:**  
Network security group allows HTTP and HTTPS from any source (`*`), combined with dynamic public IP allocation:

```terraform
security_rule {
  name                       = "HTTP"
  priority                   = 100
  direction                  = "Inbound"
  access                     = "Allow"
  protocol                   = "Tcp"
  source_port_range          = "*"
  destination_port_range     = "80"
  source_address_prefix      = "*"  # Allows from anywhere
  destination_address_prefix = "*"
}
```

**Impact:**
While HTTP/HTTPS are typically public, this configuration:
- Lacks WAF protection
- No DDoS mitigation
- No rate limiting
- No geographic restrictions

**Recommendation:**
```terraform
# SECURE - Use Application Gateway with WAF
resource "azurerm_application_gateway" "example" {
  name                = "appgateway-${var.prefix}"
  resource_group_name = azurerm_resource_group.myresourcegroup.name
  location            = var.location

  sku {
    name     = "WAF_v2"
    tier     = "WAF_v2"
    capacity = 2
  }

  waf_configuration {
    enabled          = true
    firewall_mode    = "Prevention"
    rule_set_type    = "OWASP"
    rule_set_version = "3.2"
  }

  # ... gateway configuration ...
}

# Remove public IP from VMs, route through Application Gateway
# Use Azure Front Door for additional DDoS protection
resource "azurerm_frontdoor" "example" {
  name                = "fd-${var.prefix}"
  resource_group_name = azurerm_resource_group.myresourcegroup.name

  backend_pool_health_probe {
    name = "health-probe"
    path = "/health"
  }

  # WAF policy for Front Door
  web_application_firewall_policy_link_id = azurerm_frontdoor_firewall_policy.example.id
}
```

---

### 🟡 MEDIUM Severity

#### 17. Disk Encryption Disabled

**Severity:** MEDIUM  
**Category:** CWE-311 (Missing Encryption of Sensitive Data)  
**OWASP:** A02:2021 - Cryptographic Failures

**Location:**
- [storage.tf](c:\src\GitHub\devopsabcs-engineering\gh-advsec-devsecops\terraform\azure\storage.tf#L7-L9)

**Description:**  
Azure managed disk has encryption explicitly disabled:

```terraform
encryption_settings {
  enabled = false
}
```

**Impact:**
- Data at rest is not encrypted
- Physical theft of storage media exposes data
- Compliance violations (PCI-DSS, HIPAA)

**Recommendation:**
```terraform
# SECURE - Enable encryption at rest
resource "azurerm_managed_disk" "example" {
  name                 = "disk-${var.environment}"
  location             = var.location
  resource_group_name  = azurerm_resource_group.example.name
  storage_account_type = "Premium_LRS"  # Use Premium for better performance
  create_option        = "Empty"
  disk_size_gb         = 128
  
  encryption_settings {
    enabled = true
    disk_encryption_key {
      secret_url      = azurerm_key_vault_secret.disk_encryption_key.id
      source_vault_id = azurerm_key_vault.example.id
    }
  }
}

# Or use Azure Disk Encryption (ADE)
resource "azurerm_virtual_machine_extension" "disk_encryption" {
  name                 = "AzureDiskEncryption"
  virtual_machine_id   = azurerm_virtual_machine.example.id
  publisher            = "Microsoft.Azure.Security"
  type                 = "AzureDiskEncryption"
  type_handler_version = "2.2"

  settings = jsonencode({
    EncryptionOperation    = "EnableEncryption"
    KeyVaultURL           = azurerm_key_vault.example.vault_uri
    KeyVaultResourceId    = azurerm_key_vault.example.id
    VolumeType            = "All"
  })
}
```

---

#### 18. Network Flow Logs Disabled

**Severity:** MEDIUM  
**Category:** CWE-778 (Insufficient Logging)  
**OWASP:** A09:2021 - Security Logging and Monitoring Failures

**Location:**
- [networking.tf](c:\src\GitHub\devopsabcs-engineering\gh-advsec-devsecops\terraform\azure\networking.tf#L77-L84)

**Description:**  
NSG flow logs are disabled, preventing network traffic analysis:

```terraform
resource "azurerm_network_watcher_flow_log" "flow_log" {
  enabled = false
  # ...
  retention_policy {
    enabled = false
    days    = 10
  }
}
```

**Impact:**
- No visibility into network traffic patterns
- Cannot detect network-based attacks
- Difficult to troubleshoot connectivity issues
- Compliance violations (requires network logging)

**Recommendation:**
```terraform
# SECURE - Enable flow logs with traffic analytics
resource "azurerm_log_analytics_workspace" "example" {
  name                = "law-${var.environment}"
  location            = var.location
  resource_group_name = azurerm_resource_group.example.name
  sku                 = "PerGB2018"
  retention_in_days   = 90
}

resource "azurerm_network_watcher_flow_log" "flow_log" {
  enabled                   = true  # ✓ Enable flow logs
  network_security_group_id = azurerm_network_security_group.bad_sg.id
  network_watcher_name      = azurerm_network_watcher.network_watcher.name
  resource_group_name       = azurerm_resource_group.example.name
  storage_account_id        = azurerm_storage_account.example.id
  
  retention_policy {
    enabled = true  # ✓ Enable retention
    days    = 90     # ✓ Increase retention period
  }

  traffic_analytics {
    enabled               = true
    workspace_id          = azurerm_log_analytics_workspace.example.workspace_id
    workspace_region      = azurerm_log_analytics_workspace.example.location
    workspace_resource_id = azurerm_log_analytics_workspace.example.id
    interval_in_minutes   = 10
  }
}
```

---

#### 19. Kubernetes Dashboard Enabled (Deprecated)

**Severity:** MEDIUM  
**Category:** CWE-1188 (Insecure Default Initialization of Resource)  
**OWASP:** A05:2021 - Security Misconfiguration

**Location:**
- [aks.tf](c:\src\GitHub\devopsabcs-engineering\gh-advsec-devsecops\terraform\azure\aks.tf#L18-L20)

**Description:**  
Kubernetes Dashboard addon is enabled, despite being deprecated and having a history of security issues:

```terraform
addon_profile {
  kube_dashboard {
    enabled = true  # Deprecated and insecure
  }
}
```

**Impact:**
- Deprecated feature with known vulnerabilities
- Potential unauthorized access if misconfigured
- Microsoft recommends disabling this feature

**Recommendation:**
```terraform
# SECURE - Disable deprecated dashboard, use alternatives
resource "azurerm_kubernetes_cluster" "k8s_cluster" {
  # ... other configuration ...

  addon_profile {
    kube_dashboard {
      enabled = false  # ✓ Disable deprecated dashboard
    }
    oms_agent {
      enabled                    = true
      log_analytics_workspace_id = azurerm_log_analytics_workspace.example.id
    }
  }
}

# Use modern alternatives:
# 1. Azure Portal Kubernetes resources view
# 2. kubectl with Azure AD authentication
# 3. K9s or Lens for local dashboard
# 4. Azure Monitor for containers
```

---

#### 20. OMS Agent (Monitoring) Disabled on AKS

**Severity:** MEDIUM  
**Category:** CWE-778 (Insufficient Logging)  
**OWASP:** A09:2021 - Security Logging and Monitoring Failures

**Location:**
- [aks.tf](c:\src\GitHub\devopsabcs-engineering\gh-advsec-devsecops\terraform\azure\aks.tf#L15-L17)

**Description:**  
Container monitoring is disabled:

```terraform
addon_profile {
  oms_agent {
    enabled = false
  }
}
```

**Impact:**
- No container-level monitoring
- Cannot detect anomalous container behavior
- No visibility into resource usage
- Difficult to troubleshoot application issues

**Recommendation:**
```terraform
# SECURE - Enable container monitoring
resource "azurerm_log_analytics_workspace" "aks_monitoring" {
  name                = "law-aks-${var.environment}"
  location            = var.location
  resource_group_name = azurerm_resource_group.example.name
  sku                 = "PerGB2018"
  retention_in_days   = 90
}

resource "azurerm_kubernetes_cluster" "k8s_cluster" {
  # ... other configuration ...

  addon_profile {
    oms_agent {
      enabled                    = true  # ✓ Enable monitoring
      log_analytics_workspace_id = azurerm_log_analytics_workspace.aks_monitoring.id
    }
  }

  # Enable Azure Defender for Kubernetes
  microsoft_defender {
    log_analytics_workspace_id = azurerm_log_analytics_workspace.aks_monitoring.id
  }
}
```

---

#### 21. PostgreSQL Connection Throttling Disabled

**Severity:** MEDIUM  
**Category:** CWE-770 (Allocation of Resources Without Limits or Throttling)  
**OWASP:** A05:2021 - Security Misconfiguration

**Location:**
- [sql.tf](c:\src\GitHub\devopsabcs-engineering\gh-advsec-devsecops\terraform\azure\sql.tf#L71-L75)

**Description:**  
Connection throttling is disabled on PostgreSQL server:

```terraform
resource "azurerm_postgresql_configuration" "thrtottling_config" {
  name                = "connection_throttling"
  resource_group_name = azurerm_resource_group.example.name
  server_name         = azurerm_postgresql_server.example.name
  value               = "off"
}
```

**Impact:**
- No protection against connection exhaustion attacks
- Brute force attacks not rate-limited
- Potential denial of service
- Excessive resource consumption

**Recommendation:**
```terraform
# SECURE - Enable connection throttling
resource "azurerm_postgresql_configuration" "connection_throttling" {
  name                = "connection_throttling"
  resource_group_name = azurerm_resource_group.example.name
  server_name         = azurerm_postgresql_server.example.name
  value               = "on"  # ✓ Enable throttling
}

# Also enable other security configurations
resource "azurerm_postgresql_configuration" "log_checkpoints" {
  name                = "log_checkpoints"
  resource_group_name = azurerm_resource_group.example.name
  server_name         = azurerm_postgresql_server.example.name
  value               = "on"  # ✓ Enable checkpoint logging
}

resource "azurerm_postgresql_configuration" "log_connections" {
  name                = "log_connections"
  resource_group_name = azurerm_resource_group.example.name
  server_name         = azurerm_postgresql_server.example.name
  value               = "on"  # Enable connection logging
}

resource "azurerm_postgresql_configuration" "log_disconnections" {
  name                = "log_disconnections"
  resource_group_name = azurerm_resource_group.example.name
  server_name         = azurerm_postgresql_server.example.name
  value               = "on"  # Enable disconnection logging
}
```

---

#### 22. Checkpoint Logging Disabled on PostgreSQL

**Severity:** MEDIUM  
**Category:** CWE-778 (Insufficient Logging)  
**OWASP:** A09:2021 - Security Logging and Monitoring Failures

**Location:**
- [sql.tf](c:\src\GitHub\devopsabcs-engineering\gh-advsec-devsecops\terraform\azure\sql.tf#L77-L81)

**Description:**  
Checkpoint logging disabled, reducing visibility into database operations.

**Impact:**
- Reduced forensic capability
- Difficult to troubleshoot performance issues
- Cannot detect unusual database activity patterns

**Recommendation:**
See recommendation for Finding #21 above.

---

#### 23. Storage Account Logging Incomplete

**Severity:** MEDIUM  
**Category:** CWE-778 (Insufficient Logging)  
**OWASP:** A09:2021 - Security Logging and Monitoring Failures

**Location:**
- [storage.tf](c:\src\GitHub\devopsabcs-engineering\gh-advsec-devsecops\terraform\azure\storage.tf#L18-L20)

**Description:**  
Storage account queue logging has delete and read operations disabled:

```terraform
queue_properties {
  logging {
    delete = false  # Should be true
    read   = false  # Should be true
    write  = true
    # ...
  }
}
```

**Impact:**
- Cannot audit delete operations
- Cannot detect unauthorized read access
- Incomplete audit trail

**Recommendation:**
```terraform
# SECURE - Enable comprehensive logging
resource "azurerm_storage_account" "example" {
  name                     = "stg${var.environment}${random_integer.rnd_int.result}"
  resource_group_name      = azurerm_resource_group.example.name
  location                 = azurerm_resource_group.example.location
  account_tier             = "Standard"
  account_replication_type = "GRS"
  
  # Enable blob versioning for data protection
  blob_properties {
    versioning_enabled = true
    delete_retention_policy {
      days = 30
    }
    container_delete_retention_policy {
      days = 30
    }
  }
  
  queue_properties {
    logging {
      delete                = true  # ✓ Enable delete logging
      read                  = true  # ✓ Enable read logging
      write                 = true
      version               = "1.0"
      retention_policy_days = 90    # Increase retention
    }
    hour_metrics {
      enabled               = true
      include_apis          = true
      version               = "1.0"
      retention_policy_days = 90
    }
    minute_metrics {
      enabled               = true
      include_apis          = true
      version               = "1.0"
      retention_policy_days = 90
    }
  }

  # Enable Azure Defender for Storage
  # (Configured separately via Azure Security Center)
}
```

---

#### 24. Key Vault Missing Network Restrictions

**Severity:** MEDIUM  
**Category:** CWE-284 (Improper Access Control)  
**OWASP:** A01:2021 - Broken Access Control

**Location:**
- [key_vault.tf](c:\src\GitHub\devopsabcs-engineering\gh-advsec-devsecops\terraform\azure\key_vault.tf) (entire file)

**Description:**  
Key Vault configuration lacks:
- Network restrictions (no firewall rules)
- Purge protection
- Soft delete settings
- Private endpoint configuration

**Impact:**
- Key Vault accessible from any network
- Secrets can be permanently deleted
- No recovery option for accidental deletions

**Recommendation:**
```terraform
# SECURE - Comprehensive Key Vault security
resource "azurerm_key_vault" "example" {
  name                = "kv-${var.environment}-${random_integer.rnd_int.result}"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  tenant_id           = data.azurerm_client_config.current.tenant_id
  sku_name            = "premium"
  
  # Enable purge protection and soft delete
  purge_protection_enabled   = true
  soft_delete_retention_days = 90
  
  # Enable RBAC authorization (Azure AD)
  enable_rbac_authorization = true
  
  # Network restrictions
  network_acls {
    bypass         = "AzureServices"
    default_action = "Deny"  # Deny by default
    
    # Allow specific IP ranges
    ip_rules = ["203.0.113.0/24"]
    
    # Allow specific VNets
    virtual_network_subnet_ids = [
      azurerm_subnet.app_subnet.id
    ]
  }
  
  tags = {
    environment = var.environment
    compliance  = "required"
  }
}

# Use private endpoint for enhanced security
resource "azurerm_private_endpoint" "kv_endpoint" {
  name                = "pe-keyvault-${var.environment}"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  subnet_id           = azurerm_subnet.private_endpoint_subnet.id

  private_service_connection {
    name                           = "psc-keyvault"
    private_connection_resource_id = azurerm_key_vault.example.id
    is_manual_connection          = false
    subresource_names             = ["vault"]
  }
}

# Use RBAC assignments instead of access policies
resource "azurerm_role_assignment" "kv_admin" {
  scope                = azurerm_key_vault.example.id
  role_definition_name = "Key Vault Secrets Officer"
  principal_id         = data.azurerm_client_config.current.object_id
}
```

---

#### 25. Detailed Errors Enabled in Configuration

**Severity:** MEDIUM  
**Category:** CWE-209 (Generation of Error Message Containing Sensitive Information)  
**OWASP:** A05:2021 - Security Misconfiguration

**Location:**
- [appsettings.Development.json](c:\src\GitHub\devopsabcs-engineering\gh-advsec-devsecops\src\webapp01\appsettings.Development.json#L2)

**Description:**  
Detailed errors are enabled:

```json
{"DetailedErrors": true}
```

While acceptable in development, this setting can leak sensitive information if accidentally deployed to production.

**Impact:**
- Stack traces exposed to users
- Internal paths revealed
- Database schema information leaked
- Makes reconnaissance easier for attackers

**Recommendation:**
```json
// appsettings.Development.json - OK for development only
{
  "DetailedErrors": true,
  "Logging": {
    "LogLevel": {
      "Default": "Debug",
      "Microsoft.AspNetCore": "Debug"
    }
  }
}

// appsettings.Production.json - Must be restrictive
{
  "DetailedErrors": false,
  "Logging": {
    "LogLevel": {
      "Default": "Warning",
      "Microsoft.AspNetCore": "Warning"
    }
  }
}
```

In Program.cs, ensure environment-specific handling:
```csharp
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    // Do NOT call app.UseDeveloperExceptionPage() in production
    app.UseHsts();
}
```

**Add build-time check:**
```yaml
# In CI/CD pipeline
- name: Check for Production Misconfigurations
  run: |
    if grep -q '"DetailedErrors": true' src/webapp01/appsettings.json; then
      echo "ERROR: DetailedErrors is enabled in appsettings.json"
      exit 1
    fi
```

---

### 🔵 LOW Severity

#### 26. Bare Exception Handling

**Severity:** LOW  
**Category:** CWE-396 (Declaration of Catch for Generic Exception)  
**OWASP:** A09:2021 - Security Logging and Monitoring Failures

**Location:**
- [insecure-01.py](c:\src\GitHub\devopsabcs-engineering\gh-advsec-devsecops\devsecops-demo-01\insecure-01.py#L9)
- [insecure-01.py](c:\src\GitHub\devopsabcs-engineering\gh-advsec-devsecops\devsecops-demo-01\insecure-01.py#L15)

**Description:**  
Using bare `except:` clauses without specific exception types.

**Impact:**
- Catches all exceptions including system exits
- Makes debugging difficult
- Can mask serious errors

**Recommendation:**
```python
# SECURE - Catch specific exceptions
import logging

try:
    print(xs[7])
    print(xs[8])
except IndexError as e:
    logging.error(f"Index out of range: {e}")
except Exception as e:
    logging.error(f"Unexpected error: {e}")
    raise  # Re-raise if truly unexpected
```

---

#### 27. Silent Exception Suppression

**Severity:** LOW  
**Category:** CWE-778 (Insufficient Logging)  
**OWASP:** A09:2021 - Security Logging and Monitoring Failures

**Location:**
- [insecure-01.py](c:\src\GitHub\devopsabcs-engineering\gh-advsec-devsecops\devsecops-demo-01\insecure-01.py#L9)
- [insecure-01.py](c:\src\GitHub\devopsabcs-engineering\gh-advsec-devsecops\devsecops-demo-01\insecure-01.py#L15)

**Description:**  
Exceptions suppressed with `pass` and `continue` without logging.

**Impact:**
- Errors fail silently
- No audit trail
- Difficult troubleshooting

**Recommendation:**
See recommendation for Finding #26.

---

#### 28. Missing Security Headers

**Severity:** LOW  
**Category:** CWE-693 (Protection Mechanism Failure)  
**OWASP:** A05:2021 - Security Misconfiguration

**Location:**
- [Program.cs](c:\src\GitHub\devopsabcs-engineering\gh-advsec-devsecops\src\webapp01\Program.cs) (needs verification - headers not explicitly configured)

**Description:**  
Application does not explicitly configure security headers such as:
- Content-Security-Policy
- X-Content-Type-Options
- X-Frame-Options
- Referrer-Policy

**Impact:**
- Increased XSS risk
- Clickjacking vulnerability
- MIME-sniffing attacks

**Recommendation:**
```csharp
// In Program.cs, add security headers middleware
app.Use(async (context, next) =>
{
    context.Response.Headers.Add("X-Content-Type-Options", "nosniff");
    context.Response.Headers.Add("X-Frame-Options", "DENY");
    context.Response.Headers.Add("X-XSS-Protection", "1; mode=block");
    context.Response.Headers.Add("Referrer-Policy", "strict-origin-when-cross-origin");
    context.Response.Headers.Add("Content-Security-Policy", 
        "default-src 'self'; " +
        "script-src 'self'; " +
        "style-src 'self' 'unsafe-inline'; " +
        "img-src 'self' data:; " +
        "font-src 'self'; " +
        "connect-src 'self'; " +
        "frame-ancestors 'none'");
    
    await next();
});

// Or use NWebsec package for better header management
builder.Services.AddHsts(options =>
{
    options.MaxAge = TimeSpan.FromDays(365);
    options.IncludeSubDomains = true;
    options.Preload = true;
});
```

---

## Application-Specific Review: src/webapp01

### Authentication & Authorization

**Status:** ❌ **NOT IMPLEMENTED**

The application has no authentication or authorization configured:
- No `app.UseAuthentication()` in [Program.cs](c:\src\GitHub\devopsabcs-engineering\gh-advsec-devsecops\src\webapp01\Program.cs)
- `app.UseAuthorization()` is present but has no effect without authentication
- All pages are publicly accessible
- Hardcoded credentials suggest authentication was planned but not implemented

**Recommendation:** Implement ASP.NET Core Identity or Azure AD B2C for authentication.

---

### HTTPS & HSTS

**Status:** ✅ **PARTIALLY IMPLEMENTED**

- HTTPS redirection: ✅ Enabled via `app.UseHttpsRedirection()`
- HSTS: ✅ Enabled for non-development environments with 30-day max-age

**Recommendation:** Increase HSTS max-age to 1 year for production:
```csharp
app.UseHsts(options => 
{
    options.MaxAge(days: 365);
    options.IncludeSubdomains();
    options.Preload();
});
```

---

### Cookie Security

**Status:** ⚠️ **NEEDS VERIFICATION**

The application uses Razor Pages which create antiforgery tokens in cookies. Default cookie settings need verification.

**Recommendation:**
```csharp
builder.Services.Configure<CookiePolicyOptions>(options =>
{
    options.MinimumSameSitePolicy = SameSiteMode.Strict;
    options.HttpOnly = HttpOnlyPolicy.Always;
    options.Secure = CookieSecurePolicy.Always;
});

builder.Services.ConfigureApplicationCookie(options =>
{
    options.Cookie.HttpOnly = true;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.Cookie.SameSite = SameSiteMode.Strict;
    options.ExpireTimeSpan = TimeSpan.FromMinutes(30);
    options.SlidingExpiration = true;
});
```

---

### CSRF Protection (Antiforgery)

**Status:** ✅ **ENABLED BY DEFAULT**

Razor Pages have antiforgery tokens enabled by default for POST requests. The application includes `_ValidationScriptsPartial.cshtml` for client-side validation.

**Needs verification:** Confirm all POST handlers use `[ValidateAntiForgeryToken]` or rely on default Razor Pages behavior.

---

### Input Validation & Output Encoding

**Status:** ❌ **CRITICAL ISSUES**

- **Input validation:** Nearly absent (see Command Injection finding)
- **Output encoding:** Razor Pages auto-encode by default, but news items in DevSecOps page need verification
- **Model validation:** Not implemented on page models

**Recommendation:**
```csharp
public class SecurePageModel : PageModel
{
    [BindProperty]
    [Required]
    [StringLength(100, MinimumLength = 3)]
    [RegularExpression(@"^[a-zA-Z0-9\s]*$")]
    public string UserInput { get; set; }

    public IActionResult OnPost()
    {
        if (!ModelState.IsValid)
        {
            return Page();
        }
        
        // Process validated input
        return RedirectToPage("Success");
    }
}
```

---

### Error Handling

**Status:** ✅ **CONFIGURED**

- Production: Custom error page (`/Error`)
- Development: Likely uses developer exception page (default behavior)
- HSTS enabled for production

**Configuration appears secure.**

---

### Logging

**Status:** ⚠️ **INSECURE PATTERNS**

Logging is configured, but contains multiple log injection vulnerabilities (see Findings #12).

**Recommendation:** Use structured logging throughout the application.

---

## Dependency Review

### NuGet Packages (webapp01.csproj)

| Package | Current Version | Status | Recommendation |
|---------|----------------|--------|----------------|
| Azure.Identity | 1.13.2 | ⚠️ Check for updates | Update to 1.14.x if available |
| Microsoft.Data.SqlClient | 5.0.2 | ❌ **OUTDATED** | Update to 5.2.x (contains security fixes) |
| System.Text.Json | 8.0.4 | ⚠️ Check for updates | Update to latest 8.0.x |
| Newtonsoft.Json | 13.0.1 | ⚠️ Old version | Consider replacing with System.Text.Json, or update to 13.0.3+ |

**Target Framework:** .NET 9.0 ✅ (Current LTS version)

### Critical Actions:
1. Update `Microsoft.Data.SqlClient` to latest version (5.0.2 has known vulnerabilities)
2. Run `dotnet list package --vulnerable` to check for known CVEs
3. Run `dotnet list package --outdated` to see available updates

### Automated Scanning:
Enable Dependabot or GitHub Advanced Security Dependency Review in the repository settings.

---

## Infrastructure as Code Review

### Terraform (terraform/azure/)

**Overall Assessment:** ❌ **MULTIPLE CRITICAL ISSUES**

The Terraform configuration appears to be intentionally insecure (possibly for training or testing security tools, given the "terragoat" naming):

#### Critical Issues Summary:
- ✅ **Uses Terraform properly** (resources, modules, variables)
- ❌ Hardcoded credentials (5 instances)
- ❌ Disabled security features (7 instances)
- ❌ Overly permissive network rules (3 instances)
- ❌ Missing encryption (2 instances)
- ❌ No network segmentation
- ❌ No WAF/DDoS protection

**If this is production code:** Requires complete security review and remediation before deployment.

**If this is demo/training code:** Should be clearly labeled as insecure examples and isolated from production infrastructure.

---

### Bicep (blueprints/gh-aspnet-webapp/bicep/)

**Overall Assessment:** ✅ **REASONABLE - MINOR IMPROVEMENTS NEEDED**

The Bicep configuration for the actual web app deployment is significantly more secure than the Terraform examples:

#### Positive Features:
- Uses managed identities (no hardcoded credentials)
- Proper parameterization
- Subscription-scoped deployment with resource groups
- Unique naming with suffix generation
- Good documentation

#### Areas for Improvement:

1. **ACR SKU:** Uses 'Basic' - should use 'Standard' or 'Premium' for production
   ```bicep
   @allowed(['Basic', 'Standard', 'Premium'])
   param acrSku string = 'Standard'  // Change default
   ```

2. **Missing Network Restrictions:** No VNet integration specified
3. **No Private Endpoints:** ACR and App Service should use private endpoints
4. **Missing Diagnostic Settings:** No logging to Log Analytics configured

**Recommendation:** Add the following to resources.bicep:
```bicep
// Add VNet integration for App Service
resource vnet 'Microsoft.Network/virtualNetworks@2021-02-01' = {
  name: '${webAppName}-vnet'
  location: location
  properties: {
    addressSpace: {
      addressPrefixes: ['10.0.0.0/16']
    }
    subnets: [
      {
        name: 'app-subnet'
        properties: {
          addressPrefix: '10.0.1.0/24'
          delegations: [
            {
              name: 'delegation'
              properties: {
                serviceName: 'Microsoft.Web/serverFarms'
              }
            }
          ]
        }
      }
    ]
  }
}

// Add diagnostic settings for App Service
resource appServiceDiagnostics 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'appServiceDiagnostics'
  scope: webApp
  properties: {
    workspaceId: logAnalyticsWorkspace.id
    logs: [
      {
        category: 'AppServiceHTTPLogs'
        enabled: true
      }
      {
        category: 'AppServiceConsoleLogs'
        enabled: true
      }
    ]
    metrics: [
      {
        category: 'AllMetrics'
        enabled: true
      }
    ]
  }
}
```

---

### Kubernetes Manifests (manifests/)

**Overall Assessment:** ❌ **HIGHLY INSECURE**

The manifests contain intentionally insecure configurations (likely for security scanning demos):

- [critical-double.yaml](c:\src\GitHub\devopsabcs-engineering\gh-advsec-devsecops\manifests\critical-double.yaml): Privileged container (see Finding #9)
- [score-5-pod-serviceaccount.yaml](c:\src\GitHub\devopsabcs-engineering\gh-advsec-devsecops\manifests\score-5-pod-serviceaccount.yaml): Needs verification - likely contains service account issues

**Recommendation:** If these are test files, add clear warnings:
```yaml
# WARNING: This manifest contains INTENTIONALLY INSECURE configurations
# for testing security scanning tools. DO NOT use in production.
apiVersion: v1
kind: Pod
metadata:
  name: security-test-insecure-example
  labels:
    security-test: "true"
    DO-NOT-DEPLOY: "true"
# ...
```

---

## CI/CD Pipeline Review (.github/workflows/)

**Overall Assessment:** ✅ **SECURE WITH GOOD PRACTICES**

Reviewed workflow: [cicd.yml](c:\src\GitHub\devopsabcs-engineering\gh-advsec-devsecops\.github\workflows\cicd.yml)

### Security Strengths:
1. ✅ Uses OIDC authentication (Workload Identity Federation) - no long-lived secrets
2. ✅ Proper permissions scoping (`id-token: write`, `contents: write`, etc.)
3. ✅ Secrets stored in GitHub Secrets (AZURE_CLIENT_ID, AZURE_TENANT_ID, AZURE_SUBSCRIPTION_ID)
4. ✅ Attestation support enabled
5. ✅ Multiple security scanning workflows present (see additional workflows)

### Additional Security Workflows Present:
- ✅ CodeQL SAST scanning
- ✅ Dependency Review (GitHub Advanced Security)
- ✅ Container scanning (Trivy, Grype)
- ✅ IaC scanning (Checkmarx KICS, tfsec)
- ✅ SBOM generation (Syft, Microsoft SBOM)
- ✅ OpenSSF Scorecard
- ✅ Microsoft Security DevOps
- ✅ DAST testing (ZAP)

**This is an impressive security scanning setup.**

### Minor Recommendations:

1. **Pin Action Versions:** Pin actions to SHAs for supply chain security
   ```yaml
   # Current
   - uses: actions/checkout@v5
   
   # More secure
   - uses: actions/checkout@v4.1.1  # With specific version
   # Or even better
   - uses: actions/checkout@8e5e7e5ab8b370d6c329ec480221332ada57f0ab  # Pinned SHA
   ```

2. **Add Workflow Security:**
   ```yaml
   permissions:
     contents: read  # Minimize permissions
   ```

3. **Secure Artifact Handling:** If workflows create artifacts, ensure they're scanned before deployment

---

## Action Items (Prioritized)

### 🔥 IMMEDIATE (Within 24 Hours)

1. **Rotate All Exposed Credentials**
   - Revoke Azure Storage key in appsettings.json
   - Revoke GitHub token in appsettings.json
   - Generate new credentials using Azure Key Vault
   - Scan git history and remove secrets using BFG Repo-Cleaner

2. **Fix Command Injection in Index.cshtml.cs**
   - Implement input validation on "drive" parameter
   - Use DriveInfo API instead of command construction

3. **Remove All Hardcoded Passwords**
   - DevSecOps.cshtml.cs: Remove CONNECTION_STRING
   - Index.cshtml.cs: Remove DEFAULT_PASSWORD
   - sql.tf: Use random_password resource

4. **Enable SQL Security Alerts**
   - Remove disabled_alerts from security_alert_policy
   - Configure email notifications

---

### ⚠️ HIGH PRIORITY (Within 1 Week)

5. **Fix ReDoS Vulnerability**
   - Replace vulnerable regex pattern in DevSecOps.cshtml.cs
   - Add regex timeouts

6. **Restrict Network Access**
   - Update networking.tf to remove wildcard source addresses
   - Implement Azure Bastion for management access
   - Consider Azure Firewall or WAF

7. **Enable Database Security**
   - Enable SSL enforcement on MySQL and PostgreSQL
   - Disable public network access
   - Implement private endpoints

8. **Secure AKS Cluster**
   - Enable RBAC with Azure AD integration
   - Disable Kubernetes dashboard
   - Enable OMS agent for monitoring
   - Add network policies

9. **Fix Kubernetes Manifests**
   - Remove privileged mode from containers
   - Add security contexts with least privilege
   - Implement Pod Security Standards

10. **Update Dependencies**
    - Update Microsoft.Data.SqlClient to latest version
    - Update other outdated packages
    - Enable Dependabot alerts

---

### 📋 MEDIUM PRIORITY (Within 2 Weeks)

11. **Fix Log Injection Vulnerabilities**
    - Update all logging statements to use structured logging
    - Sanitize user input in logs

12. **Enable Encryption**
    - Enable disk encryption on Azure Managed Disks
    - Configure Azure Key Vault for encryption keys

13. **Enable Monitoring**
    - Enable network flow logs
    - Enable storage logging for all operations
    - Configure Log Analytics workspace

14. **Enhance Key Vault Security**
    - Add network restrictions
    - Enable purge protection
    - Implement private endpoints

15. **Implement Authentication**
    - Add ASP.NET Core Identity or Azure AD B2C
    - Protect pages with authorization attributes
    - Configure secure cookie settings

---

### ✅ LOW PRIORITY (Within 1 Month)

16. **Add Security Headers**
    - Implement Content-Security-Policy
    - Add X-Frame-Options, X-Content-Type-Options
    - Configure HSTS with longer max-age

17. **Improve Exception Handling**
    - Replace bare except clauses with specific exceptions
    - Add logging to exception handlers

18. **Harden CI/CD Pipeline**
    - Pin GitHub Actions to commit SHAs
    - Add artifact scanning
    - Implement signing for container images

19. **Code Quality Improvements**
    - Add input validation to all page models
    - Implement comprehensive unit tests
    - Add integration tests for security features

20. **Documentation**
    - Document which files are intentionally insecure (training/demo)
    - Create security runbook
    - Document incident response procedures

---

## Risk Matrix

| Risk Level | Count | Immediate Action Required |
|------------|-------|--------------------------|
| CRITICAL   | 5     | Yes - Within 24 hours    |
| HIGH       | 11    | Yes - Within 1 week      |
| MEDIUM     | 9     | Yes - Within 2 weeks     |
| LOW        | 3     | Yes - Within 1 month     |
| **TOTAL**  | **28**| **Comprehensive remediation needed** |

---

## Compliance Impact

These findings may impact compliance with:

- **PCI-DSS:** Findings #1, #4, #5, #8, #17, #23 (encryption, logging, access control)
- **HIPAA:** Findings #1, #4, #8, #17 (data protection, encryption)
- **SOC 2:** Findings #5, #12, #18, #20, #23 (logging and monitoring)
- **GDPR:** Findings #1, #4, #8, #13, #25 (data protection, breach prevention)
- **ISO 27001:** Multiple findings across access control, cryptography, logging

---

## Positive Findings

Despite the critical vulnerabilities, the repository demonstrates some security-conscious practices:

1. ✅ Comprehensive security scanning workflows (CodeQL, Trivy, KICS, etc.)
2. ✅ OIDC authentication in CI/CD (no long-lived secrets in workflows)
3. ✅ Bicep infrastructure follows reasonable practices
4. ✅ .NET 9.0 (current version) with HTTPS/HSTS enabled
5. ✅ Antiforgery protection enabled by default in Razor Pages
6. ✅ User Secrets ID configured for development

---

## Notes

**Important Context:** Based on file naming ("terragoat", "insecure-01", "devsecops-demo"), portions of this repository appear to contain **intentionally vulnerable code** for training or testing security tools. If this is the case:

1. **Clearly label** all insecure demo code as such
2. **Segregate** demo code from production code
3. **Document** the purpose and intended usage
4. **Prevent** accidental deployment to production environments

**For Production Use:** The findings in the ASP.NET Core application (`src/webapp01`) and infrastructure code must be remediated before any production deployment. The hardcoded secrets in particular represent an immediate and critical risk.

---

## Conclusion

This security assessment identified **28 security vulnerabilities** across the repository, including **5 critical** and **11 high-severity** issues. The most critical risks involve hardcoded credentials, command injection vulnerability, and insecure infrastructure configurations.

**IMMEDIATE ACTION Required:**
1. Rotate all exposed credentials (CRITICAL)
2. Fix command injection vulnerability (CRITICAL)
3. Remove hardcoded database passwords (CRITICAL)

The repository demonstrates good security practices in CI/CD and demonstrates awareness of security through comprehensive scanning workflows. However, the application code and infrastructure configurations require significant hardening before production deployment.

Remediation should follow the prioritized action items above, starting with the immediate actions to address critical vulnerabilities.

---

**Assessment Conducted By:** Security Agent  
**Date:** February 9, 2026  
**Methodology:** Manual code review, SAST analysis, IaC security review  
**Scope:** Application code, infrastructure as code, CI/CD pipelines, Kubernetes manifests

---

THIS ASSESSMENT CONTAINS A CRITICAL VULNERABILITY
