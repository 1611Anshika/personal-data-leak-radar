import os
import json
import boto3


# AWS configuration
AWS_REGION = os.getenv("AWS_REGION", "eu-central-1")

# We can change this model later if needed.
BEDROCK_MODEL_ID = os.getenv(
    "BEDROCK_MODEL_ID",
    "eu.amazon.nova-2-lite-v1:0"
)


# Create Bedrock Runtime client
bedrock_client = boto3.client(
    "bedrock-runtime",
    region_name=AWS_REGION
)


def analyze_findings(
    findings,
    filename=None,
    sharing_context=None
):
    """
    Send detected findings to Amazon Bedrock for
    contextual explanation and protection recommendations.
    """

    if not findings:
        return {
            "summary": "No sensitive information was detected.",
            "risk_explanation": "No detected sensitive elements require protection.",
            "recommendations": []
        }

    # Prepare only the information Bedrock needs.
    finding_summary = []

    for finding in findings:
        finding_summary.append({
            "type": finding.get("type"),
            "severity": finding.get("severity")
        })

    prompt = f"""
You are the AI privacy analysis component of a security
application called Personal Data Leak Radar (PDLR).

Analyze the following detected sensitive information.

File:
{filename or "Unknown file"}

Sharing context:
{sharing_context or "Not specified"}

Detected findings:
{json.dumps(finding_summary, indent=2)}

Provide a concise privacy-risk analysis.
Consider the sharing context when explaining:
1. Which detected information may be necessary for the stated context.
2. Which detected information may be unnecessary.
3. What should be protected before sharing.

Do not decide whether the user should share the file.
Provide factual privacy guidance and let the user make the final decision.

Explain:
1. What kind of sensitive information was detected.
2. Why exposing it could create a privacy or security risk.
3. Which findings should be protected first.
4. What type of protection is appropriate.

Return ONLY valid JSON in this format:

{{
    "summary": "short overall explanation",
    "risk_explanation": "short explanation of the main risks",
    "priority_findings": [
        "finding type 1",
        "finding type 2"
    ],
    "recommendations": [
        "recommendation 1",
        "recommendation 2"
    ]
}}

Do not invent findings that are not present in the input.
Do not expose or repeat the actual sensitive values.
Do not assume that a detected credential is active.
If a credential-like value is detected, recommend verification
and rotation only if it is confirmed to be active or exposed.
"""


    try:

        response = bedrock_client.converse(
            modelId=BEDROCK_MODEL_ID,
            messages=[
                {
                    "role": "user",
                    "content": [
                        {
                            "text": prompt
                        }
                    ]
                }
            ],
            inferenceConfig={
                "maxTokens": 500,
                "temperature": 0.2
            }
        )

        response_text = (
            response["output"]["message"]["content"][0]["text"]
        )

        # Remove markdown code fences if the model adds them.
        response_text = response_text.strip()

        if response_text.startswith("```"):
            response_text = response_text.replace(
                "```json", ""
            ).replace(
                "```", ""
            ).strip()

        ai_result = json.loads(response_text)

        return ai_result

    except Exception as error:

        print("Bedrock analysis error:", error)

        return {
            "summary": "AI analysis is currently unavailable.",
            "risk_explanation": (
                "The deterministic detection engine "
                "completed successfully."
            ),
            "priority_findings": [],
            "recommendations": [],
            "ai_status": "unavailable"
        }