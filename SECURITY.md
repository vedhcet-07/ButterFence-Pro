# Security Policy

## Supported Versions

We release patches for security vulnerabilities for the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 0.3.x   | :white_check_mark: |
| < 0.3.0 | :x:                |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, please report them via one of the following methods:

### Option 1: GitHub Security Advisories (Preferred)

1. Go to the repository's Security tab
2. Click "Report a vulnerability"
3. Fill out the vulnerability report form

### Option 2: Email

Send an email to the maintainers with the following information:

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### What to Expect

- **Acknowledgment**: We will acknowledge receipt of your vulnerability report within 48 hours
- **Updates**: We will send you regular updates about our progress
- **Timeline**: We aim to release a fix within 7 days for critical issues, 30 days for others
- **Credit**: We will credit you in the security advisory unless you prefer to remain anonymous

## Security Best Practices for Users

### API Key Management

- **Never commit API keys** to version control
- Store keys in environment variables or secure key management systems
- Use the `BUTTERFENCE_API_KEY` environment variable instead of hardcoded values
- Generate secure random keys:
  ```bash
  python -c 'import secrets; print(secrets.token_urlsafe(32))'
  ```

### Production Deployment

- Always set `BUTTERFENCE_API_KEY` environment variable
- Use strong, randomly generated API keys (minimum 32 bytes)
- Rotate API keys regularly
- Enable HTTPS for API endpoints
- Review and audit whitelist patterns in `.butterfence.yaml`

### Database Security

- The SQLite database contains security audit logs
- Protect the `.butterfence/` directory with appropriate file permissions
- Regularly back up the database
- Consider encrypting the database at rest for sensitive environments

### Dependency Security

- Keep ButterFence and its dependencies up to date
- Run `safety check` to scan for known vulnerabilities
- Review dependency changes in pull requests

## Vulnerability Disclosure Policy

When we receive a security bug report, we will:

1. Confirm the problem and determine affected versions
2. Audit code to find similar problems
3. Prepare fixes for all supported releases
4. Release new security patch versions as soon as possible
5. Publish a security advisory

## Security Features

ButterFence Pro includes several security features:

### 1. Secure API Key Storage

- Keys stored with restricted file permissions (0600 on Unix)
- Secure deletion with null byte overwriting
- Never logged or displayed in output

### 2. Constant-Time Comparison

- API key verification uses `hmac.compare_digest()` to prevent timing attacks
- SHA-256 hashing before comparison

### 3. Audit Trail

- Tamper-evident audit log with SHA-256 chain checksums
- All security events logged to SQLite database
- Comprehensive logging of threat detections

### 4. Input Validation

- Pattern matching with regex timeout protection
- Entropy-based secret detection
- Obfuscation detection for evasion attempts

### 5. Whitelist Engine

- Glob-pattern based false positive suppression
- Prevents over-blocking while maintaining security

## Known Limitations

### 1. Local Storage

- API keys and configuration stored locally in `~/.butterfence/`
- On shared systems, ensure proper file permissions
- Consider using environment variables instead of stored keys

### 2. Database Integrity

- SQLite database not encrypted by default
- Chain checksums detect tampering but don't prevent it
- For high-security environments, implement database encryption

### 3. Regex Performance

- Complex patterns may cause performance issues on very large inputs
- ReDoS (Regular Expression Denial of Service) protection via timeouts

### 4. Edge Mode Limitations

- ONNX models require platform-specific wheels
- NPU support limited to AMD Ryzen AI processors
- Fallback to CPU or heuristic mode on unsupported hardware

## Security Audit History

- **2026-03**: Initial security review and hardening
  - Removed hardcoded default API keys
  - Added GitHub Actions security scanning
  - Implemented pre-commit security hooks

## Third-Party Security Tools

We use the following tools for security:

- **Bandit**: Security linter for Python code
- **Safety**: Dependency vulnerability scanner
- **GitHub Dependabot**: Automated dependency updates
- **CodeQL**: Semantic code analysis (planned)

## Contact

For security concerns, please contact the maintainers through GitHub Security Advisories or open an issue (for non-sensitive security discussions).

---

Last Updated: March 2026
