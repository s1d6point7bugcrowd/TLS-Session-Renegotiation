# TLS Session Renegotiation Vulnerability

## Info

- **Name:** TLS Session Renegotiation Vulnerability
- **Author:** s1d6p01nt7
- **Severity:** Medium
- **Description:** This template detects the presence of the TLS session renegotiation vulnerability, which allows attackers to inject arbitrary content into ongoing TLS sessions, potentially leading to man-in-the-middle attacks.
- **Remediation:** Disable TLS renegotiation on the server side or upgrade to a version of the TLS library that properly handles renegotiation securely.

## TCP Configuration

- **Host:** `{{Hostname}}`
- **Port:** 443

https://wiki.owasp.org/images/f/f8/OWASP_-_TLS_Renegotiation_Vulnerability.pdf
