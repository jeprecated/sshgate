# Security Policy

## Supported Versions

Only the latest release is supported with security updates.

| Version | Supported |
| ------- | --------- |
| latest  | Yes       |
| < latest | No       |

## Reporting a Vulnerability

Please report security vulnerabilities through GitHub Security Advisories:

https://github.com/ohare93/sshgate/security/advisories

### Scope

The following are in scope for security reports:

- Access model bypasses (running commands without human approval)
- Socket privilege escalation
- Symlink or race condition attacks on runtime directories
- Command injection through argument handling

### What to Expect

- Acknowledgment within 48 hours
- Status update within 7 days
- Security fixes are prioritized over feature work

### Out of Scope

- SSH protocol vulnerabilities (report to OpenSSH)
- Denial-of-service through resource exhaustion
- Social engineering the human operator
