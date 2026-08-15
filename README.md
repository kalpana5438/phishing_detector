# Phishing URL Detector

A heuristic-based command-line security tool designed to identify potential phishing and malicious URLs. It parses URLs and scores them based on known red flags, such as IP hosting, character stuffing, suspicious TLDs, subdomains, and brand spoofing.

---

## Features

- **Heuristic Threat Engine**: Evaluates domain, path, and parameters using rule-based scoring.
- **IP Address Hosting Detection**: Identifies URLs bypassing DNS names.
- **Domain Anomaly Scans**: Flags lookalike domains using hyphens, excessive subdomains, or suspicious TLDs.
- **Obfuscation Detection**: Detects URL masking using `@` symbols.
- **Keyword & Brand Spoofing Engine**: Scans for high-risk words (e.g., `paypal`, `secure`, `banking`, `metamask`) in untrusted domains.
- **False-Positive Mitigation**: Employs built-in domain whitelisting for major legitimate platforms.
- **Interactive Menu & Test Cases**: Enter custom URLs or run analysis on preloaded samples.

---

## Installation

Ensure you have **Python 3.8+** installed. This project has no external dependencies.

1. Clone this repository:
   ```bash
   git clone https://github.com/kalpana5438/phishing_detector.git
   cd phishing_detector
   ```

2. Run the tool:
   ```bash
   python main.py
   ```

---

## Technical Detection Rules

The engine calculates a threat score using the following metrics:
- **IP in Hostname** (+4 points): Accessing a site via IP address rather than a domain name.
- **At Symbol `@`** (+4 points): Masking the true host.
- **Excessive Subdomains** (+3 points): Having 4 or more subdomains (e.g., `login.verification.support.paypal.com.example.com`).
- **High-Risk TLD** (+3 points): Using TLDs like `.xyz`, `.top`, `.zip`, `.mov`, etc.
- **Suspicious Keywords** (+2 points per keyword): Words like `verify`, `upgrade`, `signin`, or spoofed brand names.
- **Dash `-` in Domain** (+2 points): Typical of lookalike domains (e.g., `amazon-security-login.com`).
- **URL Length**: URL exceeds 75 characters (+2 points) or 54 characters (+1 point).

### Risk Classification
- **Score < 3**: **SAFE (Low Risk)**
- **Score 3 - 5**: **SUSPICIOUS (Medium Risk)**
- **Score >= 6**: **PHISHING (High Risk)**

---

## Usage Example

Upon launching:
```text
============================================================
                   PHISHING URL DETECTOR                    
============================================================
1. Enter a custom URL to analyze
2. Run analysis on built-in test URLs
3. Exit

Select an option (1-3): 1
Enter URL to check: http://paypal-update-security-alert.net/login.php?user=verify
```

### Result:
```text
============================================================
                 URL THREAT ANALYSIS REPORT                 
============================================================
Analyzed URL:   http://paypal-update-security-alert.net/login.php?user=verify
Target Domain:  paypal-update-security-alert.net
Whitelisted:    No
Threat Score:   7 pts
Risk Level:     PHISHING (High Risk)
------------------------------------------------------------

Detected Security Indicators / Red Flags:
  ! [FLAG] URL is exceptionally long (77 chars), typical of phishing redirection.
  ! [FLAG] Domain contains '-' (commonly used to build lookalike domains).
  ! [FLAG] Contains high-risk keywords or brand names: spoofed-paypal, verify, login

Recommended Actions:
  ⚠ DO NOT enter credentials, personal data, or click links on this page.
  ⚠ Block/Report the site if received via email/SMS.
============================================================
```

---

## License

This project is open-source and licensed under the [MIT License](LICENSE).
