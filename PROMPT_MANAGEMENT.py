from colorama import Fore

# ─────────────────────────────────────────────────────────────────────────────
# FORMATTING INSTRUCTIONS
# Defines the JSON schema the AI must return.
# Injected into every user message so the model always knows the output shape.
# ─────────────────────────────────────────────────────────────────────────────

FORMATTING_INSTRUCTIONS = """
Return your findings in the following format:
{
  "findings": [
    <finding 1>,
    <finding 2>,
    ...
    <finding n>
  ]
}

If there are no findings, return an empty array:
{
  "findings": []
}

Here is the schema — it contains an example of a single finding:
{
  "findings": [
    {
      "title": "Brief title describing the attack",
      "description": "Detailed explanation with evidence from the logs",
      "attack_type": "BruteForce | PasswordSpray | CredentialStuffing | SuspiciousLogon | Benign",
      "source_ips": ["x.x.x.x"],
      "targeted_accounts": ["username"],
      "failed_attempt_count": 0,
      "success_after_failure": true,
      "mitre": {
        "tactic": "Credential Access",
        "technique": "Brute Force",
        "sub_technique": "e.g., T1110.001",
        "id": "T1110",
        "description": "Description of the MITRE technique or sub-technique"
      },
      "log_lines": [
        "Relevant line(s) from the logs that triggered the finding"
      ],
      "confidence": "Low | Medium | High",
      "recommendations": [
        "isolate",
        "disable account",
        "block IP at NSG/firewall",
        "monitor",
        "ignore"
      ],
      "indicators_of_compromise": [
        "IP address, account name, device name, etc."
      ],
      "tags": [
        "brute force",
        "password spray",
        "credential stuffing",
        "suspicious logon",
        "lateral movement",
        "credential access"
      ],
      "notes": "Optional analyst notes or assumptions made during detection"
    }
  ]
}
———————————
logs below:
"""

# ─────────────────────────────────────────────────────────────────────────────
# SYSTEM PROMPT
# Defines the AI's role and detection logic.
# Passed as the system message in every OpenAI call.
# ─────────────────────────────────────────────────────────────────────────────

SYSTEM_PROMPT = {
    "role": "system",
    "content": (
        "You are an expert SOC Analyst AI specializing in brute force and credential-based attack detection "
        "using Microsoft Defender for Endpoint (MDE) logon telemetry.\n\n"

        "You will be provided with DeviceLogonEvents log data in CSV format. "
        "Your job is to analyze it for signs of brute force, password spray, credential stuffing, "
        "or other credential-based attack patterns.\n\n"

        "Detection approach:\n"
        "- Do NOT rely on fixed thresholds. Use analytical judgment.\n"
        "- Look for: high volumes of LogonFailed from the same IP or against the same account\n"
        "- Look for: failed logons followed by a successful logon (key compromise indicator)\n"
        "- Look for: short time gaps between attempts (automation / tooling)\n"
        "- Look for: multiple accounts targeted from a single IP (password spray pattern)\n"
        "- Look for: unusual hours or unexpected source IPs for the logon context\n\n"

        "MITRE ATT&CK mapping:\n"
        "- Map findings to T1110 and relevant sub-techniques:\n"
        "  - T1110.001: Password Guessing\n"
        "  - T1110.002: Password Cracking\n"
        "  - T1110.003: Password Spraying\n"
        "  - T1110.004: Credential Stuffing\n\n"

        "Output rules:\n"
        "- Return ONLY valid JSON matching the schema provided in the user message.\n"
        "- Do not hallucinate log data or fabricate findings not grounded in the input.\n"
        "- Do not include explanatory prose outside the JSON structure.\n"
        "- If no suspicious activity is found, return: { \"findings\": [] }\n\n"

        "You are assisting skilled analysts. Be concise, evidence-driven, and specific."
    )
}

# ─────────────────────────────────────────────────────────────────────────────
# USER MESSAGE BUILDER
# Constructs the user turn for each analysis call.
# Injects: the analyst's target context + formatting schema + raw log CSV.
# ─────────────────────────────────────────────────────────────────────────────

def build_brute_force_prompt(device_name: str, log_csv: str) -> dict:
    """
    Builds the user message for the brute force analysis call.

    Args:
        device_name: The device being investigated (for context).
        log_csv:     Raw DeviceLogonEvents data as a CSV string.

    Returns:
        A dict with role='user' and the full prompt as content.
    """

    print(f"{Fore.LIGHTGREEN_EX}Building brute force analysis prompt...\n")

    full_prompt = (
        f"Analyze the following DeviceLogonEvents from device '{device_name}' "
        f"for brute force or credential-based attack activity.\n\n"
        f"Formatting Instructions:\n{FORMATTING_INSTRUCTIONS}\n\n"
        f"{log_csv}"
    )

    return {"role": "user", "content": full_prompt}