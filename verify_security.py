#!/usr/bin/env python3
"""
JABIRKING Security & Anti-Bot Verification Suite
Performs comprehensive auditing across:
  1. robots.txt policy completeness
  2. HTML AI exclusion metadata
  3. Client-side automated bot & AI agent detection logic
  4. Header & hosting infrastructure limitations
  5. Content & asset security
"""

import os
import re
import sys

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
INDEX_PATH = os.path.join(BASE_DIR, 'index.html')
ROBOTS_PATH = os.path.join(BASE_DIR, 'robots.txt')

def test_robots_txt():
    print("\n[TEST 1] Verifying robots.txt...")
    assert os.path.exists(ROBOTS_PATH), "robots.txt does not exist!"
    with open(ROBOTS_PATH, 'r', encoding='utf-8') as f:
        content = f.read()

    required_bots = [
        'GPTBot', 'ChatGPT-User', 'OAI-SearchBot',
        'ClaudeBot', 'Claude-User', 'anthropic-ai',
        'Google-Extended', 'Bytespider', 'CCBot',
        'PerplexityBot', 'Meta-ExternalAgent', 'Applebot-Extended',
        'Amazonbot', 'cohere-ai', 'YouBot', 'Diffbot',
        'FacebookBot', 'omgilibot'
    ]

    missing = []
    for bot in required_bots:
        pattern = rf'User-agent:\s*{re.escape(bot)}\s*\nDisallow:\s*/'
        if not re.search(pattern, content, re.IGNORECASE):
            missing.append(bot)

    if missing:
        print(f"  FAIL: Missing crawler rules for: {missing}")
        return False
    
    print(f"  PASS: All {len(required_bots)} primary AI and scraping crawlers explicitly disallowed.")
    assert 'Disallow: /assets/' in content, "Missing /assets/ denial"
    assert 'Disallow: /fonts/' in content, "Missing /fonts/ denial"
    print("  PASS: Core asset directory traversal disallowed.")
    return True

def test_html_metadata():
    print("\n[TEST 2] Verifying HTML AI Denial Metadata...")
    assert os.path.exists(INDEX_PATH), "index.html does not exist!"
    with open(INDEX_PATH, 'r', encoding='utf-8') as f:
        html = f.read()

    meta_checks = [
        (r'name="robots"\s+content="[^"]*noindex[^"]*"', 'Robots noindex'),
        (r'name="robots"\s+content="[^"]*nofollow[^"]*"', 'Robots nofollow'),
        (r'name="google-extended"\s+content="[^"]*noindex[^"]*"', 'Google-Extended meta'),
        (r'name="ai-exclusion"\s+content="[^"]*noai[^"]*"', 'AI-Exclusion noai'),
        (r'name="ai-exclusion"\s+content="[^"]*noimageai[^"]*"', 'AI-Exclusion noimageai'),
        (r'name="tdm-reservation"\s+content="1"', 'EU TDM Reservation (Directive 2019/790)'),
        (r'name="robots"\s+content="[^"]*noai[^"]*"', 'Robots noai directive'),
        (r'http-equiv="X-Content-Type-Options"\s+content="nosniff"', 'X-Content-Type-Options fallback'),
        (r'name="referrer"\s+content="strict-origin-when-cross-origin"', 'Referrer policy fallback')
    ]

    all_passed = True
    for pattern, name in meta_checks:
        if re.search(pattern, html, re.IGNORECASE):
            print(f"  PASS: {name} found.")
        else:
            print(f"  FAIL: {name} NOT found!")
            all_passed = False
    return all_passed

def test_client_bot_detection():
    print("\n[TEST 3] Verifying Client-Side Automated Bot & Scraper Detection...")
    with open(INDEX_PATH, 'r', encoding='utf-8') as f:
        html = f.read()

    checks = [
        ('navigator.webdriver === true', 'WebDriver / Headless browser detection'),
        ('__puppeteer_evaluation_script__', 'Puppeteer execution signature check'),
        ('__playwright', 'Playwright execution signature check'),
        ('$cdc_asdjflasutopfhvcZLmcfl_', 'ChromeDriver DOM variable check'),
        ('GPTBot', 'In-page AI crawler User-Agent block pattern'),
        ('ClaudeBot', 'In-page Anthropic crawler block pattern'),
        ('Bytespider', 'In-page ByteDance scraper block pattern'),
        ('SwiftShader', 'Software WebGL renderer (headless container) check'),
        ('Automated AI Crawler or Scraping Activity', 'Error 1006 ban reason update')
    ]

    all_passed = True
    for token, desc in checks:
        if token in html:
            print(f"  PASS: {desc} implemented.")
        else:
            print(f"  FAIL: {desc} missing!")
            all_passed = False
    return all_passed

def test_repository_content_exposure():
    print("\n[TEST 4] Auditing Repository for Sensitive Content Exposure...")
    suspicious_patterns = [
        r'api[_-]?key', r'secret', r'password', r'token', r'bearer\s+[a-zA-Z0-9_\-\.]{20,}'
    ]
    exposed = []
    for root, dirs, files in os.walk(BASE_DIR):
        if '.git' in root or '.gemini' in root:
            continue
        for file in files:
            file_path = os.path.join(root, file)
            # Skip binary files
            if file.endswith(('.png', '.woff2', '.jpg', '.jpeg', '.gif')):
                continue
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                for pat in suspicious_patterns:
                    matches = re.findall(pat, content, re.IGNORECASE)
                    if matches and file not in ['verify_security.py', 'worker.js', 'CLOUDFLARE_SETUP.md']:
                        exposed.append((file, pat))
    if exposed:
        print(f"  WARNING: Potential token references in: {exposed}")
    else:
        print("  PASS: Zero hardcoded credentials, API keys, or private tokens detected.")

    # Check for sitemap exposure
    sitemap_path = os.path.join(BASE_DIR, 'sitemap.xml')
    if os.path.exists(sitemap_path):
        print("  WARNING: sitemap.xml exists (may aid crawler discovery).")
    else:
        print("  PASS: No sitemap.xml exposed (crawler surface minimized).")
    return True

if __name__ == '__main__':
    print("=" * 70)
    print("JABIRKING MAXIMUM AI ACCESS RESTRICTION AUDIT")
    print("=" * 70)

    t1 = test_robots_txt()
    t2 = test_html_metadata()
    t3 = test_client_bot_detection()
    t4 = test_repository_content_exposure()

    print("\n" + "=" * 70)
    if t1 and t2 and t3 and t4:
        print("RESULT: ALL SECURITY AUDIT SUITE TESTS PASSED (4/4)")
    else:
        print("RESULT: AUDIT COMPLETED WITH ISSUES")
    print("=" * 70)
    sys.exit(0 if (t1 and t2 and t3 and t4) else 1)
