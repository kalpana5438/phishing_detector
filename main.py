import sys
from detector import PhishingURLDetector

# ANSI escape codes for coloring terminal output
RESET = "\033[0m"
BOLD = "\033[1m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
WHITE = "\033[97m"

def print_header(title):
    print(f"\n{CYAN}{BOLD}{'=' * 60}")
    print(f" {title.center(58)}")
    print(f"{'=' * 60}{RESET}")

def get_risk_color(risk: str) -> str:
    if "PHISHING" in risk:
        return RED
    elif "SUSPICIOUS" in risk:
        return YELLOW
    return GREEN

def display_results(res: dict):
    color = get_risk_color(res["risk"])
    
    print_header("URL THREAT ANALYSIS REPORT")
    print(f"{BOLD}Analyzed URL:{RESET}   {res['url']}")
    print(f"{BOLD}Target Domain:{RESET}  {res['domain']}")
    print(f"{BOLD}Whitelisted:{RESET}    {'Yes (Legitimate Site)' if res['is_whitelisted'] else 'No'}")
    print(f"{BOLD}Threat Score:{RESET}   {res['score']} pts")
    print(f"{BOLD}Risk Level:{RESET}     {color}{BOLD}{res['risk']}{RESET}")
    print("-" * 60)

    if res["indicators"]:
        print(f"\n{RED}{BOLD}Detected Security Indicators / Red Flags:{RESET}")
        for indicator in res["indicators"]:
            print(f"  {RED}![FLAG]{RESET} {indicator}")
    else:
        print(f"\n{GREEN}{BOLD}✓ No security red flags detected. The URL appears normal.{RESET}")

    # Recommendations based on risk level
    print(f"\n{BOLD}Recommended Actions:{RESET}")
    if "PHISHING" in res["risk"]:
        print(f"  {RED}⚠ DO NOT enter credentials, personal data, or click links on this page.{RESET}")
        print(f"  {RED}⚠ Block/Report the site if received via email/SMS.{RESET}")
    elif "SUSPICIOUS" in res["risk"]:
        print(f"  {YELLOW}⚠ Verify SSL certificate and official brand before interaction.{RESET}")
        print(f"  {YELLOW}⚠ Double check the spelling of the domain.{RESET}")
    else:
        print(f"  {GREEN}✓ Normal browsing rules apply.{RESET}")

    print(f"\n{CYAN}{BOLD}{'=' * 60}{RESET}")

def main():
    # Enable ANSI terminal colors on Windows if supported
    if sys.platform == "win32":
        try:
            import colorama
            colorama.init()
        except ImportError:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)

    # Sample URLs for demonstration
    sample_urls = [
        "https://www.google.com",
        "http://paypal-update-security-alert.net/login.php?user=verify",
        "http://192.168.1.55/admin/login.html",
        "https://secure-login.amazon.support-services-xyz.top/update",
        "https://github.com/login"
    ]

    while True:
        print_header("PHISHING URL DETECTOR")
        print("1. Enter a custom URL to analyze")
        print("2. Run analysis on built-in test URLs")
        print("3. Exit")
        
        choice = input(f"\n{BOLD}Select an option (1-3): {RESET}").strip()
        
        if choice == "1":
            url = input(f"\nEnter URL to check (e.g., paypal-verify.com): {RESET}").strip()
            if not url:
                print(f"{RED}URL cannot be empty!{RESET}")
                continue
            
            detector = PhishingURLDetector(url)
            results = detector.analyze()
            display_results(results)
            
        elif choice == "2":
            print_header("RUNNING DEMO ANALYSIS ON TEST CASES")
            for url in sample_urls:
                detector = PhishingURLDetector(url)
                results = detector.analyze()
                color = get_risk_color(results["risk"])
                print(f"{BOLD}URL:{RESET}  {url}")
                print(f"{BOLD}Risk:{RESET} {color}{BOLD}{results['risk']}{RESET} (Score: {results['score']} pts)")
                if results["indicators"]:
                    print(f"  {RED}↳ Flags:{RESET} {results['indicators'][0]} " + (f"(and {len(results['indicators'])-1} more)" if len(results['indicators']) > 1 else ""))
                print("-" * 60)
            
        elif choice == "3":
            print(f"\n{CYAN}Exiting Phishing URL Detector. Browse safely!{RESET}\n")
            break
        else:
            print(f"{RED}Invalid option, please choose 1, 2, or 3.{RESET}")

if __name__ == "__main__":
    main()
