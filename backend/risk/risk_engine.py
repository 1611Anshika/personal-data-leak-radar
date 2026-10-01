# ============================================================
# PDLR SMART RISK ENGINE
# ============================================================

SEVERITY_SCORES = {
    "Critical": 30,
    "High": 20,
    "Medium": 10,
    "Low": 5
}


# Categories that deserve additional weight because
# exposure can have a stronger security/privacy impact.

CATEGORY_WEIGHTS = {

    "AWS Access Key": 1.30,
    "AWS Temporary Access Key": 1.30,
    "GitHub Token": 1.30,
    "GitHub Fine-grained Token": 1.30,
    "JWT Token": 1.20,
    "Private Key": 1.30,
    "Password": 1.25,
    "API Key": 1.25,

    "PAN Card": 1.15,
    "Aadhaar Number": 1.15,
    "Credit/Debit Card": 1.20,
    "Bank Account Number": 1.15,

    "Passport Number": 1.10,
    "Driving Licence": 1.10,

    "Phone Number": 1.00,
    "Email Address": 0.90,
    "UPI ID": 1.00
}


# Some sharing contexts make certain information
# particularly relevant to the privacy assessment.
#
# These are contextual modifiers, not a decision about
# whether the user should share the file.

CONTEXT_WEIGHTS = {

    "Social Media": {
        "PAN Card": 1.20,
        "Aadhaar Number": 1.20,
        "Phone Number": 1.10,
        "Email Address": 1.05,
        "Bank Account Number": 1.20,
        "Credit/Debit Card": 1.20,
        "AWS Access Key": 1.30
    },

    "Job Application": {
        "PAN Card": 1.05,
        "Aadhaar Number": 1.10,
        "Phone Number": 0.95,
        "Email Address": 0.90,
        "AWS Access Key": 1.30,
        "Password": 1.30
    },

    "Customer Support": {
        "Credit/Debit Card": 1.20,
        "Bank Account Number": 1.15,
        "Password": 1.30,
        "AWS Access Key": 1.30
    },

    "College": {
        "Aadhaar Number": 1.10,
        "PAN Card": 1.05,
        "Phone Number": 0.95,
        "Email Address": 0.90,
        "AWS Access Key": 1.30
    },

    "Verification": {
        "Aadhaar Number": 1.05,
        "PAN Card": 1.05,
        "Passport Number": 1.05,
        "Driving Licence": 1.05,
        "AWS Access Key": 1.30
    },

    "Work": {
        "AWS Access Key": 1.30,
        "GitHub Token": 1.30,
        "API Key": 1.30,
        "Private Key": 1.30,
        "Password": 1.30
    }
}


def get_context_weight(data_type, sharing_context):
    """
    Returns an optional context-specific multiplier.
    """

    if not sharing_context:
        return 1.0

    context_data = CONTEXT_WEIGHTS.get(
        sharing_context,
        {}
    )

    return context_data.get(
        data_type,
        1.0
    )


def calculate_finding_score(
    finding,
    sharing_context=None
):
    """
    Calculate the contribution of one finding.
    """

    data_type = finding.get(
        "type",
        "Unknown"
    )

    severity = finding.get(
        "severity",
        "Low"
    )

    confidence = finding.get(
        "confidence",
        1.0
    )

    # Keep confidence within a safe range.
    try:
        confidence = float(confidence)
    except (TypeError, ValueError):
        confidence = 1.0

    confidence = max(
        0.0,
        min(1.0, confidence)
    )

    base_score = SEVERITY_SCORES.get(
        severity,
        5
    )

    category_weight = CATEGORY_WEIGHTS.get(
        data_type,
        1.0
    )

    context_weight = get_context_weight(
        data_type,
        sharing_context
    )

    score = (
        base_score
        * confidence
        * category_weight
        * context_weight
    )

    return round(
        score,
        2
    )


def calculate_risk(
    findings,
    sharing_context=None
):
    """
    Calculate the overall PDLR privacy risk.

    Returns:
        score
        level
        reasons
        breakdown
    """

    if not findings:

        return {
            "score": 0,
            "level": "LOW",
            "reasons": [],
            "breakdown": []
        }

    total_score = 0

    reasons = []
    breakdown = []

    for finding in findings:

        data_type = finding.get(
            "type",
            "Unknown"
        )

        severity = finding.get(
            "severity",
            "Low"
        )

        confidence = finding.get(
            "confidence",
            1.0
        )

        contribution = calculate_finding_score(
            finding,
            sharing_context
        )

        total_score += contribution

        breakdown.append({
            "type": data_type,
            "severity": severity,
            "confidence": confidence,
            "score_contribution": contribution
        })

        reasons.append(
            f"{data_type} detected "
            f"({severity}, "
            f"{round(float(confidence) * 100)}% confidence)"
        )

    # Keep score within 0–100.
    total_score = min(
        round(total_score),
        100
    )

    if total_score >= 70:

        level = "CRITICAL"

    elif total_score >= 40:

        level = "HIGH"

    elif total_score > 0:

        level = "MEDIUM"

    else:

        level = "LOW"

    return {
        "score": total_score,
        "level": level,
        "reasons": reasons,
        "breakdown": breakdown
    }