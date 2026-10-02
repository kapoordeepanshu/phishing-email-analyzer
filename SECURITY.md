# Security Policy

## Reporting a vulnerability

If you find a security issue **in this tool itself** (for example, a crafted email that causes script execution in the
web app, a crash/denial of service in the parser, or a way to make the tool fetch or execute content), please report it
privately using GitHub's
**[Report a vulnerability](https://github.com/kapoordeepanshu/phishing-email-analyzer/security/advisories/new)** form.

Please include steps to reproduce and, if possible, a minimal synthetic `.eml` file. Don't send real emails containing
personal data. You can expect an acknowledgement within a few days.

## Detection misses are not vulnerabilities

Phishing emails the analyzer fails to flag (false negatives) or legitimate emails it flags (false positives) are
welcome as regular [issues](https://github.com/kapoordeepanshu/phishing-email-analyzer/issues/new?template=detection-report.md).
