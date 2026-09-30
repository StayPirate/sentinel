# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 0.x.y   | Latest release only |

Sentinel is in pre-1.0 development.
Security fixes are applied to the latest release only.
Once the project reaches 1.0, this table will be updated to reflect the long-term support policy.

## Reporting a Vulnerability

If you discover a security vulnerability in Sentinel, please report it responsibly.
**Do not open a public GitHub issue for security vulnerabilities.**

### How to report

Send an email to **security@suse.com** (or **security@suse.de**) with:

- A description of the vulnerability
- Steps to reproduce the issue
- The affected version(s)
- Any potential impact assessment

We strongly encourage encrypting your report with the SUSE Security Team GPG key.
Note that GPG encryption does not cover the email subject or names of attached files — avoid putting confidential information there.

The current GPG key and full reporting guidelines are published at:
<https://www.suse.com/support/security/contact/>

### What to expect

The SUSE Security Team will review and address the reported vulnerability.
Please refer to the [SUSE Security Contacts](https://www.suse.com/support/security/contact/) page for the official acknowledgment policy and response timelines.

### Scope

The following are in scope for security reports:

- Authentication and authorization bypasses
- SQL injection, command injection, or other injection vulnerabilities
- Sensitive data exposure (credentials, PII, internal infrastructure details)
- Cross-site scripting (XSS) or cross-site request forgery (CSRF) in API responses
- Denial of service vulnerabilities in the API or background tasks
- Insecure default configurations
- Dependency vulnerabilities with a demonstrated exploit path

### Out of scope

- Vulnerabilities in dependencies without a demonstrated impact on Sentinel
- Issues that require physical access to the server
- Social engineering attacks
- Denial of service attacks that require significant resources

## Security Measures

Sentinel employs the following security practices:

- **Static analysis**: ruff, bandit, and mypy (strict mode) run on every pull request
- **Dependency auditing**: GitHub Dependabot alerts monitor dependencies for known vulnerabilities, Renovate raises fix pull requests, and pip-audit blocks dependency changes and releases that contain known vulnerabilities
- **Container scanning**: Trivy scans the Docker image weekly
- **Release transparency**: versioned images include a CycloneDX SBOM and
  signed SBOM/build-provenance attestations; see
  [Release Supply-Chain Artifacts](docs/deployment.md#release-supply-chain-artifacts)
- **Secret detection**: gitleaks runs in pre-commit hooks to prevent accidental secret commits
- **Type safety**: strict static type checking catches type-related bugs before runtime
