import re


# ============================================================
# PDLR ADVANCED DETECTION ENGINE
# ============================================================

PATTERNS = {

    # --------------------------------------------------------
    # IDENTITY
    # --------------------------------------------------------

    "PAN Card": {
        "pattern": r"\b[A-Z]{5}[0-9]{4}[A-Z]\b",
        "severity": "Critical",
        "confidence": 0.98
    },

    "Aadhaar Number": {
    "pattern": r"(?<!\d{4}\s)\b\d{4}\s\d{4}\s\d{4}\b(?!\s\d{4}\b)",
    "severity": "Critical",
    "confidence": 0.97
    },

    "Passport Number": {
        "pattern": r"\b[A-Z][0-9]{7}\b",
        "severity": "High",
        "confidence": 0.82
    },

    # --------------------------------------------------------
    # CONTACT
    # --------------------------------------------------------

    "Phone Number": {
        "pattern": r"\b(?:\+91[-\s]?)?[6-9]\d{9}\b",
        "severity": "High",
        "confidence": 0.95
    },

    "Email Address": {
        "pattern": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
        "severity": "Medium",
        "confidence": 0.99
    },

    # --------------------------------------------------------
    # FINANCIAL
    # --------------------------------------------------------

    "Credit/Debit Card": {
        "pattern": r"\b(?:\d{4}[-\s]?){3}\d{4}\b",
        "severity": "Critical",
        "confidence": 0.96
    },

   "UPI ID": {
    "pattern": r"\b[A-Za-z0-9._-]+@(?:oksbi|ybl|ibl|axl|upi|paytm|apl|sbi|hdfcbank|icicic|okaxis|okhdfbank|okicici)\b",
    "severity": "High",
    "confidence": 0.94
    },

    # --------------------------------------------------------
    # CLOUD / API SECRETS
    # --------------------------------------------------------

    "AWS Access Key": {
        "pattern": r"\bAKIA[0-9A-Z]{16}\b",
        "severity": "Critical",
        "confidence": 0.99
    },

    "AWS Temporary Access Key": {
        "pattern": r"\bASIA[0-9A-Z]{16}\b",
        "severity": "Critical",
        "confidence": 0.99
    },
    "GitHub Token": {
        "pattern": r"\b(?:ghp|gho|ghu|ghs|ghr)[_@][A-Za-z0-9_@]{15,}\b",
        "severity": "Critical",
        "confidence": 0.99
    },

    "GitHub Fine-grained Token": {
        "pattern": r"\bgithub_pat_[A-Za-z0-9_]{20,}\b",
        "severity": "Critical",
        "confidence": 0.99
    },

    # --------------------------------------------------------
    # JWT
    # --------------------------------------------------------

    "JWT Token": {
        "pattern": r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b",
        "severity": "Critical",
        "confidence": 0.97
    },

    # --------------------------------------------------------
    # PRIVATE KEYS
    # --------------------------------------------------------

    "Private Key": {
        "pattern": r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
        "severity": "Critical",
        "confidence": 0.99
    }
}


# ============================================================
# CONTEXT-BASED PATTERNS
# ============================================================

CONTEXT_PATTERNS = {

    "Bank Account Number": {
        "pattern": r"(?i)(?:bank\s*)?(?:account(?:\s+number|\s+no\.?)?|a/c)\s*[:#-]?\s*(\d{9,18})",
        "severity": "Critical",
        "confidence": 0.90
    },

    "Driving Licence": {
    "pattern": r"(?i)(?:driving\s*licen[cs]e|dl\s*(?:no|number)?)\s*[:#-]?\s*([A-Z]{2}[-\s]?\d{2}[-\s]?\d{6,14})",
    "severity": "High",
    "confidence": 0.88
    },

    "Password": {
    "pattern": r"(?i)(?:password|passwd|pwd)\s*[:=]\s*([^\s,;]{4,})",
    "severity": "Critical",
    "confidence": 0.90
    },

    "API Key": {
    "pattern": r"(?i)(?:api[_\s-]?key|api[_\s-]?token)\s*[:=]?\s*([A-Za-z0-9_@.\-]+(?:\s+[A-Za-z0-9_@.\-]+){0,4})(?=\s+(?:Password|passwd|pwd|Driving|Licence|$))",
    "severity": "Critical",
    "confidence": 0.91
},
}


# ============================================================
# NORMALIZATION
# ============================================================

def normalize_match(value):
    return str(value).strip()


# ============================================================
# STANDARD PATTERN DETECTION
# ============================================================

def detect_standard_patterns(text):

    findings = []

    for data_type, info in PATTERNS.items():

        matches = re.findall(
            info["pattern"],
            text
        )

        for match in matches:

            if isinstance(match, tuple):
                match = match[0]

            value = normalize_match(match)

            if not value:
                continue

            findings.append({
                "type": data_type,
                "value": value,
                "severity": info["severity"],
                "confidence": info["confidence"],
                "source": "Pattern Detection"
            })

    return findings


# ============================================================
# CONTEXT DETECTION
# ============================================================

def detect_context_patterns(text):

    findings = []

    for data_type, info in CONTEXT_PATTERNS.items():

        matches = re.findall(
            info["pattern"],
            text
        )

        for match in matches:

            if isinstance(match, tuple):
                value = match[-1]
            else:
                value = match

            value = normalize_match(value)

            if not value:
                continue

            findings.append({
                "type": data_type,
                "value": value,
                "severity": info["severity"],
                "confidence": info["confidence"],
                "source": "Context + Pattern Detection"
            })

    return findings


# ============================================================
# REMOVE DUPLICATES
# ============================================================

def remove_duplicates(findings):

    unique = []
    seen = set()

    for finding in findings:

        key = (
            finding["type"],
            finding["value"]
        )

        if key not in seen:

            seen.add(key)
            unique.append(finding)

    return unique


# ============================================================
# MAIN DETECTOR
# ============================================================

def detect_sensitive_data(text):

    if not text:
        return []

    text = str(text)

    findings = []

    findings.extend(
        detect_standard_patterns(text)
    )

    findings.extend(
        detect_context_patterns(text)
    )

    findings = remove_duplicates(
        findings
    )

    return findings