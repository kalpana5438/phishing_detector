import re
from urllib.parse import urlparse

class PhishingURLDetector:
    # High-risk keywords commonly found in phishing URLs
    SUSPICIOUS_KEYWORDS = {
        "login", "signin", "verify", "secure", "update", "account", "webscr", 
        "banking", "ebayisapi", "free", "giftcard", "reset", "password", 
        "support", "verification", "service", "claim", "refund", "gift", 
        "bonus", "upgrade", "wallet", "crypto", "coindesk", "binance",
        "metamask", "paypal", "netflix", "microsoft", "amazon", "google", 
        "apple", "icloud", "dropbox", "facebook", "instagram"
    }

    # Common legitimate domains to avoid false positives (whitelisting top domains)
    WHITELISTED_DOMAINS = {
        "google.com", "github.com", "microsoft.com", "amazon.com", "netflix.com",
        "paypal.com", "apple.com", "dropbox.com", "facebook.com", "instagram.com",
        "twitter.com", "linkedin.com", "youtube.com", "wikipedia.org", "yahoo.com"
    }

    def __init__(self, url: str):
        self.url = url.strip()
        # Ensure url has a scheme for parsing
        if not re.match(r'^https?://', self.url, re.IGNORECASE):
            self.parsed_url = urlparse("http://" + self.url)
        else:
            self.parsed_url = urlparse(self.url)
        
        self.domain = self.parsed_url.netloc.lower()
        self.path = self.parsed_url.path.lower()
        self.query = self.parsed_url.query.lower()

    def has_ip_address(self) -> bool:
        # Regex to detect IPv4 address in hostname
        ip_pattern = r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$'
        # Detect IPv6 or IPv4 with port
        hostname = self.domain.split(':')[0]
        return bool(re.match(ip_pattern, hostname))

    def get_url_length(self) -> int:
        return len(self.url)

    def count_subdomains(self) -> int:
        # Remove 'www.' if present
        domain = self.domain
        if domain.startswith("www."):
            domain = domain[4:]
        
        # Split by dot
        parts = domain.split(".")
        # Typically domain.com has 2 parts, sub.domain.com has 3.
        # We return the number of dots
        return len(parts) - 1

    def has_at_symbol(self) -> bool:
        return "@" in self.url

    def has_suspicious_tld(self) -> bool:
        # High-risk TLDs according to security reports
        high_risk_tlds = {".zip", ".mov", ".fit", ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".work", ".buzz", ".cn"}
        return any(self.domain.endswith(tld) for tld in high_risk_tlds)

    def has_dash_in_domain(self) -> bool:
        # Phishers often use dashes to mimic real brands (e.g., paypal-security.com)
        return "-" in self.domain

    def count_special_chars(self) -> dict:
        chars = {".": 0, "-": 0, "_": 0, "/": 0, "?": 0, "=": 0, "&": 0}
        for char in chars:
            chars[char] = self.url.count(char)
        return chars

    def check_suspicious_keywords(self) -> list:
        found = []
        # Check path and query
        text_to_check = self.path + " " + self.query
        for word in self.SUSPICIOUS_KEYWORDS:
            if word in text_to_check:
                found.append(word)
            
            # Check domain for spoofed brands (e.g., paypal-update.com)
            # but avoid matching if the domain is the actual whitelisted domain
            if word in self.domain and self.domain not in self.WHITELISTED_DOMAINS:
                # Make sure it's not a subdomain of the real brand (e.g., support.paypal.com)
                if not self.domain.endswith("." + word + ".com") and self.domain != f"{word}.com":
                    if word not in found:
                        found.append(f"spoofed-{word}")
        return found

    def analyze(self) -> dict:
        score = 0
        indicators = []
        
        # 1. IP Address check
        if self.has_ip_address():
            score += 4
            indicators.append("Contains IP address instead of domain name (highly suspicious).")

        # 2. URL Length check
        length = self.get_url_length()
        if length > 75:
            score += 2
            indicators.append(f"URL is exceptionally long ({length} chars), typical of phishing redirection.")
        elif length > 54:
            score += 1
            indicators.append(f"URL is moderately long ({length} chars).")

        # 3. Subdomain check
        subdomains = self.count_subdomains()
        if subdomains >= 4:
            score += 3
            indicators.append(f"Excessive subdomains ({subdomains}), often used to mimic trusted domains.")
        elif subdomains == 3:
            score += 1
            indicators.append(f"Multiple subdomains ({subdomains}).")

        # 4. At Symbol check
        if self.has_at_symbol():
            score += 4
            indicators.append("Contains '@' symbol (ignores preceding authority, common spoofing technique).")

        # 5. Dash in domain
        if self.has_dash_in_domain():
            score += 2
            indicators.append("Domain contains '-' (commonly used to build lookalike domains).")

        # 6. Suspicious TLD
        if self.has_suspicious_tld():
            score += 3
            indicators.append(f"Uses high-risk/suspicious Top Level Domain (TLD).")

        # 7. Special character counts
        special_chars = self.count_special_chars()
        if special_chars["."] > 5:
            score += 2
            indicators.append(f"High number of periods ({special_chars['.']}).")
        if special_chars["="] > 3:
            score += 1
            indicators.append(f"Multiple parameter assignments ({special_chars['=']}).")

        # 8. Keywords check
        keywords = self.check_suspicious_keywords()
        if keywords:
            score += min(4, len(keywords) * 2)
            indicators.append(f"Contains high-risk keywords or brand names: {', '.join(keywords)}")

        # Check whitelist to reduce false positives
        is_whitelisted = self.domain in self.WHITELISTED_DOMAINS or any(self.domain.endswith("." + d) for d in self.WHITELISTED_DOMAINS)
        if is_whitelisted:
            score = max(0, score - 5)

        # Classification
        if score >= 6:
            risk = "PHISHING (High Risk)"
        elif score >= 3:
            risk = "SUSPICIOUS (Medium Risk)"
        else:
            risk = "SAFE (Low Risk)"

        return {
            "url": self.url,
            "domain": self.domain,
            "score": score,
            "risk": risk,
            "indicators": indicators,
            "is_whitelisted": is_whitelisted
        }
