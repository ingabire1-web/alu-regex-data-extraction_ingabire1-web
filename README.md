# alu-regex-data-extraction_ingabire1-web
# ALU Regex Data Extraction & Secure Validation

**ALU Onboarding Hackathon Assignment**  
Author: Ines INGABIRE 
Date: 17 May 2026

---

## What This Program Does

This program reads a raw text file (simulating messy, real-world API output) and extracts four types of structured data using **regular expressions (regex)**:

1. **Email addresses** — with ALU-specific domain classification
2. **URLs** — including paths and query parameters
3. **Phone numbers** — multiple real-world formats
4. **Credit card numbers** — extracted and immediately masked for security

It also detects and **rejects malicious input** such as SQL injection, XSS scripts, and template injection attempts before any extraction occurs.

---

## Project Structure

```
alu-regex-data-extraction/
├── input/
│   └── raw-text.txt          # Realistic messy input (simulated API dump)
├── src/
│   └── main.py               # All regex patterns, extraction & security logic
├── output/
│   └── sample-output.json    # Structured JSON results from running the program
└── README.md                 # This file
```

---

## How to Run

### Requirements
- Python 3.6 or higher
- No external libraries needed (uses only `re`, `json`, `pathlib` — all built-in)

### Steps

1. Clone or download this repository
2. Make sure `input/raw-text.txt` exists (it is included)
3. From the **root of the project**, run:

```bash
python3 src/main.py
```

4. Results will be printed to the console and saved to `output/sample-output.json`

---

## Regex Patterns Explained

### Email Pattern
```
[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}
```
- `[a-zA-Z0-9._%+-]+` — local part (before the @): letters, digits, dots, underscores, etc.
- `@` — literal @ symbol
- `[a-zA-Z0-9.-]+` — domain name
- `\.` — literal dot (escaped)
- `[a-zA-Z]{2,}` — top-level domain (com, org, edu — minimum 2 letters)

### URL Pattern
```
https?://(www\.)?[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}[^\s]*
```
- `https?://` — http or https (s is optional)
- `(www\.)?` — optional www.
- `[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}` — domain and extension
- `[^\s]*` — optional path/query (anything until whitespace)

### Phone Number Pattern
```
(\+\d{1,2}\s)?(\(?\d{3}\)?[\s.-]?)\d{3}[\s.-]?\d{4}
```
- `(\+\d{1,2}\s)?` — optional country code (+1, +250)
- `\(?\d{3}\)?` — area code with optional brackets
- `[\s.-]?` — optional separator (space, dot, or dash)
- `\d{3}[\s.-]?\d{4}` — remaining digits with optional separator

### Credit Card Pattern
```
\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{3,4}
```
- Four groups of digits separated by optional spaces or dashes
- Last group is 3–4 digits to handle both Visa (16) and AmEx (15)

---

## ALU Email Validation

Three ALU domain types are recognised and classified:

| Type | Domain | Example |
|------|--------|---------|
| `official` | @alueducation.com | admissions@alueducation.com |
| `alumni` | @alumni.alueducation.com | pascal@alumni.alueducation.com |
| `si` | @si.alueducation.com | dev@si.alueducation.com |

The `$` anchor at the end of each domain pattern ensures the domain appears at the **end** of the email — preventing false matches like `fake@alueducation.com.evil.com`.

---

## Security Design

### Input Sanitisation
Every line of input is scanned **before extraction** for the following threats:

| Pattern | Attack Type |
|---------|-------------|
| `<script` | Cross-site scripting (XSS) |
| `javascript:` | JavaScript protocol injection |
| `onload=` | HTML event handler injection |
| `--` | SQL comment injection |
| `DROP`, `SELECT` | SQL keyword injection |
| `${` | Template literal injection |
| `\x00` | Null byte injection |
| `%xx` | URL-encoded character evasion |

Lines containing any of these patterns are **skipped entirely** and logged in the output under `security_notes.lines_skipped_as_malicious`.

### Credit Card Masking
Full credit card numbers are **never stored or displayed**. All cards are masked immediately after extraction:

```
4111-1111-1111-1111  →  ************1111
```

Only the last 4 digits are preserved. This follows the PCI-DSS data security standard used in real payment systems.

---

## Sample Output (summary)

```json
{
  "emails": [
    { "email": "admissions@alueducation.com", "is_alu": true, "alu_type": "official" },
    { "email": "john.kariuki@gmail.com", "is_alu": false, "alu_type": null }
  ],
  "urls": [
    "https://portal.alueducation.com/onboarding?ref=2024&lang=en"
  ],
  "phone_numbers": [
    "+1 800 555 0199",
    "123-456-7890"
  ],
  "credit_cards": [
    "************1111",
    "************0004"
  ],
  "security_notes": {
    "lines_skipped_as_malicious": ["..."],
    "total_lines_rejected": 12,
    "masking_policy": "Credit card numbers masked — last 4 digits only"
  }
}
```

---

## Notes

- Input text was designed to resemble a real internal communications log with realistic emails, payments, and API responses
- The malicious section at the bottom of the input file simulates raw unfiltered API data — it is intentionally included to demonstrate security filtering
- All regex patterns were written and tested manually without AI code generation