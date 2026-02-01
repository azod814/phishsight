#!/usr/bin/env python3
import sys
import os
import argparse
import requests
import re
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from colorama import Fore, Style, init
from difflib import SequenceMatcher

# --- Auto-reset colorama for Windows/Linux compatibility ---
init(autoreset=True)

# --- Constants for Brand Detection ---
KNOWN_BRANDS = ["google", "facebook", "instagram", "microsoft", "linkedin", "twitter", "x.com", "apple", "amazon", "netflix", "paypal", "yahoo", "gmail", "outlook"]
SUSPICIOUS_TLDS = ['.tk', '.ml', '.ga', '.cf', '.gq']

# --- Helper Functions for Styling ---
def style_text(text, color=Fore.WHITE, bold=False, italic=False):
    """Applies colorama styles to text."""
    styled_text = f"{color}{text}"
    if bold:
        styled_text = Style.BRIGHT + styled_text
    # Note: Italic is not universally supported in all terminals, but we'll add the ANSI code.
    if italic:
        styled_text = "\x1B[3m" + styled_text
    return styled_text + Style.RESET_ALL

def print_banner():
    """Prints a cool, colorful banner."""
    banner = r"""
    ==========================================
     _   _            _                      _   
    | | | | __ _  ___| | ____ _ _ __   __ _| |_ 
    | |_| |/ _` |/ __| |/ / _` | '_ \ / _` | __|
    |  _  | (_| | (__|   < (_| | | | | (_| | |_ 
    |_| |_|\__,_|\___|_|\_\__,_|_| |_|\__,_|\__|
                                            
    Local Phishing Page Analyzer & Deceptor
    Author: [azod814]
    Version: 1.0
    ==========================================
    """
    print(style_text(banner, color=Fore.CYAN, bold=True))
    print(style_text("[*] Starting analysis...", color=Fore.YELLOW))

# --- Core Analysis Functions ---
def is_suspicious_url(url):
    """Analyzes the URL for common phishing patterns."""
    parsed_url = urlparse(url)
    domain = parsed_url.netloc.lower()
    indicators = []

    # 1. Typosquatting
    for brand in KNOWN_BRANDS:
        similarity = SequenceMatcher(None, domain, brand).ratio()
        if brand not in domain and 0.6 < similarity < 0.9:
            indicators.append(f"Typosquatting for '{brand}'")
            break

    # 2. Suspicious TLDs
    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            indicators.append(f"Uses suspicious TLD '{tld}'")
            break
    
    # 3. IP Address as domain
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\$", domain):
        indicators.append("Domain is an IP address")

    return indicators

def analyze_page_content(soup, url):
    """Analyzes the HTML content for brand targeting and malicious elements."""
    analysis = {
        "brand_target": "Unknown",
        "indicators": [],
        "forms": []
    }

    # Brand Targeting
    page_text = soup.get_text().lower()
    title = soup.title.string.lower() if soup.title else ""
    
    for brand in KNOWN_BRANDS:
        if brand in title or brand in page_text:
            analysis["brand_target"] = brand.capitalize()
            break

    # Malicious Indicators
    scripts = soup.find_all('script')
    for script in scripts:
        if script.string and ('eval(' in script.string or 'atob(' in script.string or 'String.fromCharCode' in script.string):
            analysis["indicators"].append("Obfuscated JavaScript detected")
            break
    
    # Form Analysis
    for form in soup.find_all('form'):
        action = form.get('action', '').lower()
        form_info = {'action': action, 'is_malicious': False}
        
        # Check if form action is external or suspicious
        if action.startswith('http'):
            parsed_action = urlparse(action)
            if parsed_action.netloc != urlparse(url).netloc:
                form_info['is_malicious'] = True
                analysis["indicators"].append(f"Form submits to external domain: {parsed_action.netloc}")
        elif not action or action == '#':
            # Could be a harmless form, or one handled by JS
            pass
        else:
            # Relative path, likely safe
            pass
            
        analysis["forms"].append(form_info)

    return analysis

def generate_decoy(soup, output_path):
    """Creates a sanitized version of the page."""
    decoy_soup = BeautifulSoup(soup.prettify(), 'html.parser')

    # Remove all <script> tags
    for script in decoy_soup(['script', 'noscript']):
        script.decompose()

    # Sanitize all forms
    for form in decoy_soup.find_all('form'):
        form['action'] = '#'  # Make it do nothing
        form['method'] = 'get' # Change method to be harmless
        # Clear all input fields
        for input_tag in form.find_all('input'):
            if input_tag.get('type') not in ['submit', 'button']:
                input_tag['value'] = ''
    
    # Write the decoy page
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(str(decoy_soup))
    
    return True

# --- Main Logic ---
def main():
    parser = argparse.ArgumentParser(
        description="PhishSight: A local tool to analyze phishing pages and generate harmless decoys.",
        epilog="Example: python3 phishsight.py -u http://example.com --decoy"
    )
    parser.add_argument('-u', '--url', required=True, help="The URL of the suspicious page to analyze.")
    parser.add_argument('--decoy', action='store_true', help="Generate a harmless decoy HTML page.")
    parser.add_argument('--output', default='./decoy_pages', help="Output directory for the decoy page (default: ./decoy_pages).")
    
    args = parser.parse_args()
    
    print_banner()

    try:
        # 1. Fetch the page
        print(style_text(f"\n[*] Fetching page from: {args.url}", color=Fore.YELLOW))
        response = requests.get(args.url, timeout=10, headers={'User-Agent': 'Mozilla/5.0'})
        response.raise_for_status() # Raise an exception for bad status codes (4xx or 5xx)
        print(style_text("[+] Page fetched successfully.", color=Fore.GREEN, bold=True))
        
        soup = BeautifulSoup(response.content, 'html.parser')

        # 2. Perform Analysis
        print(style_text("\n[*] Performing analysis...", color=Fore.YELLOW))
        
        url_indicators = is_suspicious_url(args.url)
        content_analysis = analyze_page_content(soup, args.url)
        
        # 3. Print Report
        print(style_text("\n--- [ ANALYSIS REPORT ] ---", color=Fore.MAGENTA, bold=True))
        
        print(style_text("\n[!] URL Indicators:", color=Fore.CYAN, bold=True))
        if url_indicators:
            for indicator in url_indicators:
                print(f"    - {style_text(indicator, color=Fore.RED)}")
        else:
            print(style_text("    - No obvious URL-based threats found.", color=Fore.GREEN))
            
        print(style_text("\n[!] Brand Target:", color=Fore.CYAN, bold=True))
        print(f"    - Likely Target: {style_text(content_analysis['brand_target'], color=Fore.YELLOW, italic=True)}")

        print(style_text("\n[!] Malicious Indicators:", color=Fore.CYAN, bold=True))
        if content_analysis['indicators']:
            for indicator in content_analysis['indicators']:
                print(f"    - {style_text(indicator, color=Fore.RED)}")
        else:
            print(style_text("    - No direct malicious code or data-stealing forms found.", color=Fore.GREEN))

        # 4. Generate Decoy if requested
        if args.decoy:
            print(style_text("\n[*] Generating decoy page...", color=Fore.YELLOW))
            os.makedirs(args.output, exist_ok=True)
            # Use a safe filename based on the domain
            domain = urlparse(args.url).netloc.replace('.', '_')
            filename = f"{domain}_decoy.html"
            output_path = os.path.join(args.output, filename)
            
  if generate_decoy(soup, output_path):
    print(style_text(f"[+] Decoy page generated successfully!", color=Fore.GREEN, bold=True))
    print(style_text(f"    Saved at: {output_path}", color=Fore.YELLOW))
    print(style_text(
        "\n[*] You can open this file in a browser to view the harmless version.",
        color=Fore.CYAN
    ))


            else:
                print(style_text("[-] Failed to generate decoy page.", color=Fore.RED))

        print(style_text("\n--- [ END OF REPORT ] ---\n", color=Fore.MAGENTA, bold=True))

    except requests.exceptions.RequestException as e:
        print(style_text(f"\n[!] Error: Could not fetch the URL. {e}", color=Fore.RED, bold=True))
        sys.exit(1)
    except Exception as e:
        print(style_text(f"\n[!] An unexpected error occurred: {e}", color=Fore.RED, bold=True))
        sys.exit(1)

if __name__ == "__main__":
    main()
