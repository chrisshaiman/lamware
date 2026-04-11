"""
fake_credentials.py — Provably fake credential sets for malware analysis.

Used by vm_agent_cape.py to enter realistic-looking but forensically safe
credentials into prompts during malware detonation. This triggers credential
harvester C2 callbacks, banking trojan overlays, and phishing kit exfil
mechanisms that would otherwise remain dormant.

All values here are intentionally fake:
  - Email domain: contoso.com (Microsoft's official fictitious domain)
  - Credit card: Luhn-valid test numbers that no bank will accept
  - SSN: 000-prefix (SSA never issues 000-xx-xxxx)
  - Phone: 555 numbers (reserved fictitious range)

Every credential entry is logged with a before/after screenshot and tagged
in the Cape report so analysts can correlate network captures with agent actions.

Author: Christopher Shaiman
License: Apache 2.0
"""

# ---------------------------------------------------------------------------
# Guest identity — matches the Packer guest image baked-in identity (ADR-012)
# ---------------------------------------------------------------------------
GUEST_IDENTITY = {
    "first_name":   "John",
    "last_name":    "Smith",
    "full_name":    "John Smith",
    "username":     "jsmith",
    "email":        "jsmith@contoso.com",
    "email_alt":    "john.smith@contoso.com",
    "password":     "Password123!",
    "password_alt": "Summer2024!",
    "phone":        "555-867-5309",
    "dob":          "1985-06-15",       # YYYY-MM-DD
    "dob_mm":       "06",
    "dob_dd":       "15",
    "dob_yyyy":     "1985",
    "address":      "123 Main Street",
    "city":         "Springfield",
    "state":        "IL",
    "zip":          "62701",
    "country":      "US",
}

# ---------------------------------------------------------------------------
# Financial — Luhn-valid test numbers, no real bank will accept these
# ---------------------------------------------------------------------------
FINANCIAL = {
    # Visa test number (Luhn valid, universally used in payment testing)
    "cc_number":      "4111111111111111",
    "cc_number_fmt":  "4111 1111 1111 1111",
    "cc_expiry":      "12/28",
    "cc_expiry_mm":   "12",
    "cc_expiry_yy":   "28",
    "cc_expiry_yyyy": "2028",
    "cc_cvv":         "123",
    "cc_name":        "JOHN SMITH",

    # Mastercard test number
    "cc_number_mc":   "5500005555555559",

    # Bank account (ABA routing + fictitious account)
    "routing":        "021000021",    # JPMorgan Chase ABA (public/known)
    "account":        "000123456789",
    "bank_name":      "First National Bank",

    # SSN — 000 prefix is never issued by SSA
    "ssn":            "000-12-3456",
    "ssn_nodash":     "000123456",

    # Tax ID / EIN (fictitious)
    "ein":            "00-1234567",
}

# ---------------------------------------------------------------------------
# Windows / network credentials
# ---------------------------------------------------------------------------
WINDOWS = {
    "domain":         "CONTOSO",
    "username":       "jsmith",
    "password":       "Password123!",
    "domain_user":    "CONTOSO\\jsmith",
    "upn":            "jsmith@contoso.com",
}

# ---------------------------------------------------------------------------
# Prompt type → credential mapping
# Used by vm_agent_cape.py to select the right credential set based on
# what Claude vision identifies on screen.
# ---------------------------------------------------------------------------
PROMPT_CREDENTIALS = {
    # Generic email/password login form
    "login_email_password": {
        "fields": [
            {"label": "email",    "value": GUEST_IDENTITY["email"]},
            {"label": "password", "value": GUEST_IDENTITY["password"]},
        ]
    },

    # Windows Security / NTLM credential dialog
    "windows_credential_dialog": {
        "fields": [
            {"label": "username", "value": WINDOWS["domain_user"]},
            {"label": "password", "value": WINDOWS["password"]},
        ]
    },

    # Credit card / payment form
    "payment_form": {
        "fields": [
            {"label": "card_number", "value": FINANCIAL["cc_number_fmt"]},
            {"label": "expiry",      "value": FINANCIAL["cc_expiry"]},
            {"label": "cvv",         "value": FINANCIAL["cc_cvv"]},
            {"label": "name",        "value": FINANCIAL["cc_name"]},
        ]
    },

    # Banking / financial login
    "banking_login": {
        "fields": [
            {"label": "username", "value": GUEST_IDENTITY["username"]},
            {"label": "password", "value": GUEST_IDENTITY["password"]},
            {"label": "account",  "value": FINANCIAL["account"]},
        ]
    },

    # Personal info / registration form
    "personal_info_form": {
        "fields": [
            {"label": "first_name", "value": GUEST_IDENTITY["first_name"]},
            {"label": "last_name",  "value": GUEST_IDENTITY["last_name"]},
            {"label": "email",      "value": GUEST_IDENTITY["email"]},
            {"label": "phone",      "value": GUEST_IDENTITY["phone"]},
            {"label": "address",    "value": GUEST_IDENTITY["address"]},
            {"label": "city",       "value": GUEST_IDENTITY["city"]},
            {"label": "zip",        "value": GUEST_IDENTITY["zip"]},
        ]
    },

    # SSN / identity verification prompt
    "ssn_prompt": {
        "fields": [
            {"label": "ssn", "value": FINANCIAL["ssn"]},
        ]
    },
}
