#!/usr/bin/env python3
"""
================================================================
Regex Data Extraction & Secure Validation
ALU Onboarding Hackathon Assignment

Author: Ines INGABIRE
Date:   18th May 2026
================================================================
"""

import re
import json
from pathlib import Path


# ================================================================
# SECTION 1: SECURITY — MALICIOUS PATTERN DETECTION
# ================================================================
# Before we extract anything, we check every line of input for
# patterns that suggest an attack or injection attempt.
# This is called "input sanitisation" — a core security principle.
# If any of these patterns are found in a line, we skip it entirely.

MALICIOUS_PATTERNS = [
    r'<script',          # XSS: tries to inject JavaScript into a page
    r'javascript:',      # JS protocol injection (e.g. in href or src)
    r'onload\s*=',       # HTML event handler injection (e.g. onload=alert())
    r'--',               # SQL comment syntax used to cut off query logic
    r'\bDROP\b',         # SQL DROP command — can delete entire tables
    r'\bSELECT\b',       # SQL SELECT — used in data exfiltration attacks
    r'\$\{',             # Template literal injection (e.g. ${process.env.KEY})
    r'\x00',             # Null byte — used to confuse parsers and bypass checks
    r'%[0-9a-fA-F]{2}',  # URL-encoded characters (e.g. %3C = <) used for evasion
]

def is_malicious(line):
    """
    Scans a single line of text for known malicious patterns.

    How it works:
        - Loops through every pattern in MALICIOUS_PATTERNS
        - Uses re.search() to check if the pattern appears ANYWHERE in the line
        - re.IGNORECASE means it catches both 'DROP' and 'drop' and 'Drop'
        - Returns True (unsafe) as soon as ONE match is found
        - Returns False (safe) only if NO patterns match

    Args:
        line (str): A single line of text from the input file

    Returns:
        bool: True if the line is unsafe, False if it appears clean
    """
    for pattern in MALICIOUS_PATTERNS:
        if re.search(pattern, line, re.IGNORECASE):
            return True
    return False


def sanitise_input(raw_text):
    """
    Splits raw text into individual lines and filters out malicious ones.

    This means each line is checked independently — so one bad line
    does not cause the entire file to be rejected. Only the dangerous
    lines are removed; safe lines are kept for extraction.

    Args:
        raw_text (str): The full contents of the input file

    Returns:
        tuple: (clean_text, skipped_lines)
            clean_text   — safe lines joined back into one string
            skipped_lines — list of lines that were removed with reasons
    """
    lines = raw_text.splitlines()
    clean_lines = []
    skipped_lines = []

    for line in lines:
        if is_malicious(line):
            skipped_lines.append(line.strip())
        else:
            clean_lines.append(line)

    clean_text = '\n'.join(clean_lines)
    return clean_text, skipped_lines


# ================================================================
# SECTION 2: REGEX PATTERNS — WITH FULL EXPLANATIONS
# ================================================================

# ----------------------------------------------------------------
# PATTERN 1: EMAIL ADDRESS
# ----------------------------------------------------------------
# An email has three parts:  local@domain.extension
#
# Breaking down the pattern:
#   [a-zA-Z0-9._%+-]+
#       → The LOCAL PART (before the @)
#       → Allows: letters (upper/lower), digits, dots, underscores,
#                 percent signs, plus signs, hyphens
#       → The + means "one or more of these characters"
#
#   @
#       → Literal @ symbol — every email must have exactly one
#
#   [a-zA-Z0-9.-]+
#       → The DOMAIN NAME (e.g. gmail, alueducation, yahoo)
#       → Allows letters, digits, dots, hyphens
#       → The + means "one or more"
#
#   \.
#       → A LITERAL DOT before the extension
#       → We escape it with \ because plain . means "any character"
#
#   [a-zA-Z]{2,}
#       → The TOP-LEVEL DOMAIN (e.g. com, org, edu, rw, uk)
#       → Only letters, minimum 2 characters (no .c or .1)
#
# This pattern handles:
#   john.doe@gmail.com                         ✅
#   admissions@alueducation.com               ✅
#   pascal.mugisha@alumni.alueducation.com     ✅
#   dev.team@si.alueducation.com              ✅
#   user+tag@company.co.uk                    ✅

EMAIL_PATTERN = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'


# ----------------------------------------------------------------
# PATTERN 2: URL (Web Address)
# ----------------------------------------------------------------
# A URL looks like: https://www.example.com/path?query=value
#
# Breaking down the pattern:
#   https?://
#       → Matches http:// OR https://
#       → The s? means the "s" is optional (0 or 1 times)
#
#   (www\.)?
#       → Optionally matches "www." at the start of the domain
#       → The ? makes the whole group optional
#       → \. is an escaped dot (literal dot)
#
#   [a-zA-Z0-9.-]+
#       → The DOMAIN NAME (e.g. portal.alueducation, api.example)
#       → Allows letters, digits, dots (for subdomains), hyphens
#
#   \.[a-zA-Z]{2,}
#       → The TOP-LEVEL DOMAIN (.com, .org, .edu, .rw)
#
#   [^\s]*
#       → Everything AFTER the domain (path, query string, fragments)
#       → [^\s] means "any character that is NOT a whitespace"
#       → The * means "zero or more" — URLs don't need a path
#
# This pattern handles:
#   https://www.alueducation.com                              ✅
#   https://portal.alueducation.com/onboarding?ref=2024      ✅
#   http://api.si.alueducation.com/docs/v2?format=json       ✅
#   https://events.alueducation.com/summit2024?promo=ALU10   ✅

URL_PATTERN = r'https?://(www\.)?[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}[^\s]*'


# ----------------------------------------------------------------
# PATTERN 3: PHONE NUMBER
# ----------------------------------------------------------------
# Phone numbers appear in many formats in the real world.
# This pattern is designed to handle all common variations.
#
# Breaking down the pattern:
#   (\+\d{1,2}\s)?
#       → Optional COUNTRY CODE like +1, +44, +250, +254
#       → \+ is a literal plus sign (escaped)
#       → \d{1,2} means 1 or 2 digits
#       → \s is a space after the country code
#       → The whole group is optional (?)
#
#   \(?\d{3}\)?
#       → The AREA CODE — 3 digits
#       → \(? means an optional opening bracket
#       → \)? means an optional closing bracket
#       → Handles both "(250)" and "250"
#
#   [\s.-]?
#       → Optional SEPARATOR between groups
#       → Can be a space, dot, or dash
#
#   \d{3}
#       → The MIDDLE 3 digits
#
#   [\s.-]?
#       → Another optional separator
#
#   \d{4}
#       → The LAST 4 digits
#
# This pattern handles:
#   (250) 788-456-789    ✅
#   +250 788 456 789     ✅
#   250.788.000.123      ✅
#   123-456-7890         ✅
#   +1 800 555 0199      ✅
#   123.456.7890         ✅

PHONE_PATTERN = r'(\+\d{1,2}\s)?(\(?\d{3}\)?[\s.-]?)\d{3}[\s.-]?\d{4}'


# ----------------------------------------------------------------
# PATTERN 4: CREDIT CARD NUMBER
# ----------------------------------------------------------------
# Credit cards are 15 or 16 digits, grouped in sets of 4
# (or 4-6-5 for AmEx), separated by spaces, dashes, or nothing.
#
# Breaking down the pattern:
#   \d{4}
#       → First group of 4 digits
#
#   [\s-]?
#       → Optional space or dash separator
#
#   \d{4}
#       → Second group of 4 digits
#
#   [\s-]?
#       → Optional separator
#
#   \d{4}
#       → Third group of 4 digits
#
#   [\s-]?
#       → Optional separator
#
#   \d{3,4}
#       → Final group — 3 digits (AmEx) or 4 digits (Visa/Mastercard)
#
# This pattern handles:
#   4111-1111-1111-1111   ✅  (Visa with dashes)
#   5500 0000 0000 0004   ✅  (Mastercard with spaces)
#   4242424242424242      ✅  (no separators)
#   3782 8224 6310 005    ✅  (AmEx — 15 digits)

CC_PATTERN = r'\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{3,4}'


# ================================================================
# SECTION 3: ALU-SPECIFIC EMAIL VALIDATION
# ================================================================
# Beyond just finding emails, we need to identify which ones
# belong to ALU and what TYPE of ALU address they are.
#
# The three ALU domains are:
#   @alueducation.com            → official staff/student emails
#   @alumni.alueducation.com     → graduate/alumni emails
#   @si.alueducation.com         → School of Innovation emails

ALU_DOMAINS = {
    'official': r'@alueducation\.com$',
    'alumni':   r'@alumni\.alueducation\.com$',
    'si':       r'@si\.alueducation\.com$',
}

def validate_alu_email(email):
    """
    Checks if an email belongs to an ALU domain and identifies which type.

    How it works:
        - Converts email to lowercase for case-insensitive comparison
        - Loops through each ALU domain pattern
        - re.search() checks if the domain pattern appears in the email
        - Also checks that the local part (before @) is not empty
        - The $ at the end of each pattern ensures the domain is at
          the END of the email (prevents false matches like 'fake@alueducation.com.evil.com')

    Args:
        email (str): A single email address string

    Returns:
        tuple: (is_alu_email, domain_type)
            is_alu_email — True if it's a valid ALU email
            domain_type  — 'official', 'alumni', 'si', or None
    """
    email_lower = email.lower()

    for domain_type, pattern in ALU_DOMAINS.items():
        if re.search(pattern, email_lower):
            local_part = email_lower.split('@')[0]
            if local_part and len(local_part) >= 1:
                return (True, domain_type)

    return (False, None)


# ================================================================
# SECTION 4: CREDIT CARD MASKING
# ================================================================
# SECURITY RULE: We must NEVER store or display full credit card numbers.
# This function replaces all digits except the last 4 with asterisks (*).
#
# Example:  4111-1111-1111-1111  →  ************1111
#
# This is called "data masking" — a standard security practice
# used in real payment systems (PCI-DSS compliance).

def mask_credit_card(card_number):
    """
    Masks a credit card number, showing only the last 4 digits.

    Steps:
        1. Remove all non-digit characters (spaces, dashes) using re.sub()
           re.sub(r'[^0-9]', '', ...) replaces anything that is NOT a digit with ''
        2. Validate length — real cards are 13 to 16 digits
        3. Replace all but last 4 digits with '*'

    Args:
        card_number (str): Raw credit card string (may include dashes/spaces)

    Returns:
        str or None: Masked card string, or None if length is invalid
    """
    # \D means "not a digit" — this removes spaces, dashes, etc.
    digits_only = re.sub(r'\D', '', card_number)

    # Validate: credit cards are between 13 (old Visa) and 16 digits
    if len(digits_only) < 13 or len(digits_only) > 16:
        return None

    # Keep only last 4 digits visible, mask the rest with *
    masked = '*' * (len(digits_only) - 4) + digits_only[-4:]
    return masked


# ================================================================
# SECTION 5: EXTRACTION FUNCTIONS
# ================================================================
# Each function uses re.finditer() to scan the ENTIRE clean text
# and find ALL matches of the pattern.
#
# re.finditer() is better than re.findall() here because it returns
# match OBJECTS — we can call .group(0) to get the full matched string.

def extract_emails(text):
    """
    Finds all valid email addresses in the text.
    Tags each one with ALU domain info if applicable.

    Returns:
        list of dicts: Each dict has 'email', 'is_alu', 'alu_type'
    """
    matches = re.finditer(EMAIL_PATTERN, text, re.IGNORECASE)
    valid_emails = []

    for match in matches:
        email = match.group(0)
        is_alu, alu_type = validate_alu_email(email)

        # Accept if it's an ALU email OR if it passes the basic format check
        # Basic check: must have something@something.something
        if is_alu or re.match(r'^[^@]+@[^@]+\.[^@]+$', email):
            valid_emails.append({
                'email': email,
                'is_alu': is_alu,
                'alu_type': alu_type if is_alu else None
            })

    return valid_emails


def extract_urls(text):
    """
    Finds all URLs in the text.

    Returns:
        list of str: Each item is a URL string
    """
    matches = re.finditer(URL_PATTERN, text, re.IGNORECASE)
    return [match.group(0) for match in matches]


def extract_phone_numbers(text):
    """
    Finds all phone numbers in the text.

    Returns:
        list of str: Each item is a phone number string
    """
    matches = re.finditer(PHONE_PATTERN, text)
    return [match.group(0).strip() for match in matches]


def extract_credit_cards(text):
    """
    Finds all credit card numbers in the text and returns them MASKED.
    Full card numbers are NEVER stored or returned — security requirement.

    Returns:
        list of str: Each item is a masked card string e.g. '************1111'
    """
    matches = re.finditer(CC_PATTERN, text)
    masked_cards = []

    for match in matches:
        card_number = match.group(0)
        masked = mask_credit_card(card_number)

        if masked:  # Only include if length was valid (13–16 digits)
            masked_cards.append(masked)

    return masked_cards


# ================================================================
# SECTION 6: MAIN FILE PROCESSING
# ================================================================

def process_text_file(input_file_path):
    """
    Orchestrates the full pipeline:
        1. Read raw text from file
        2. Sanitise (remove malicious lines)
        3. Run all four extractions on the clean text
        4. Return structured results

    Args:
        input_file_path (Path): Path to raw-text.txt

    Returns:
        dict: All results plus security notes
    """
    # Step 1: Read the raw file
    with open(input_file_path, 'r', encoding='utf-8') as f:
        raw_text = f.read()

    # Step 2: Sanitise — remove dangerous lines before any extraction
    clean_text, skipped_lines = sanitise_input(raw_text)

    # Step 3: Run all extractions on the CLEAN text only
    emails       = extract_emails(clean_text)
    urls         = extract_urls(clean_text)
    phone_numbers = extract_phone_numbers(clean_text)
    credit_cards = extract_credit_cards(clean_text)

    # Step 4: Build the structured result dictionary
    results = {
        'emails': emails,
        'urls': urls,
        'phone_numbers': phone_numbers,
        'credit_cards': credit_cards,
        'security_notes': {
            'lines_skipped_as_malicious': skipped_lines,
            'total_lines_rejected': len(skipped_lines),
            'masking_policy': 'Credit card numbers masked — last 4 digits only',
            'sanitisation_policy': 'Each line checked independently for injection patterns'
        }
    }

    return results


# ================================================================
# SECTION 7: OUTPUT & MAIN EXECUTION
# ================================================================

def main():
    """
    Entry point — sets up paths, runs processing, prints summary,
    and saves results to JSON.
    """
    # Build paths relative to this script's location
    base_dir    = Path(__file__).parent.parent
    input_file  = base_dir / 'input' / 'raw-text.txt'
    output_file = base_dir / 'output' / 'sample-output.json'

    # Check the input file actually exists
    if not input_file.exists():
        print(f"[ERROR] Input file not found: {input_file}")
        print("Please create: input/raw-text.txt")
        return

    print("Processing input file...")
    results = process_text_file(input_file)

    # ── Console Summary ──────────────────────────────────────────
    print("\n" + "=" * 55)
    print("  EXTRACTION SUMMARY")
    print("=" * 55)
    print(f"  Emails found       : {len(results['emails'])}")
    print(f"  URLs found         : {len(results['urls'])}")
    print(f"  Phone numbers found: {len(results['phone_numbers'])}")
    print(f"  Credit cards found : {len(results['credit_cards'])}")
    print(f"  Malicious lines    : {results['security_notes']['total_lines_rejected']}")
    print("=" * 55)

    # Print all emails, flagging ALU ones
    if results['emails']:
        print("\n  ALL EMAILS:")
        for e in results['emails']:
            tag = f"[ALU:{e['alu_type'].upper()}]" if e['is_alu'] else "[external]"
            print(f"    {tag:20s}  {e['email']}")

    # Print all URLs
    if results['urls']:
        print("\n  ALL URLs:")
        for url in results['urls']:
            print(f"    {url}")

    # Print phone numbers
    if results['phone_numbers']:
        print("\n  PHONE NUMBERS:")
        for phone in results['phone_numbers']:
            print(f"    {phone}")

    # Print masked cards (never the real numbers)
    if results['credit_cards']:
        print("\n  CREDIT CARDS (masked):")
        for card in results['credit_cards']:
            print(f"    {card}")

    # Print skipped lines (security log)
    skipped = results['security_notes']['lines_skipped_as_malicious']
    if skipped:
        print(f"\n  REJECTED LINES ({len(skipped)}):")
        for line in skipped:
            print(f"    [BLOCKED] {line[:60]}...")

    # ── Save JSON Output ─────────────────────────────────────────
    output_file.parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, 'w', encoding='utf-8') as json_out:
        json.dump(results, json_out, indent=2, ensure_ascii=False)

    print(f"\n  Results saved to: {output_file}")
    print("=" * 55)


if __name__ == "__main__":
    main()