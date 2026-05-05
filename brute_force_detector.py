# Standard library
import time
import json
from datetime import timedelta

# Third-party
from colorama import Fore, Style, init
from openai import OpenAI, RateLimitError, OpenAIError
from azure.identity import DefaultAzureCredential
from azure.monitor.query import LogsQueryClient
import pandas as pd

# Local modules
import _keys
import EXECUTOR
import GUARDRAILS
import MODEL_MANAGEMENT

init(autoreset=True)


# CLIENTS


law_client = LogsQueryClient(credential=DefaultAzureCredential())
openai_client = OpenAI(api_key=_keys.OPENAI_API_KEY)
model = MODEL_MANAGEMENT.DEFAULT_MODEL


# SYSTEM PROMPT

SYSTEM_PROMPT = {
    "role": "system",
    "content": """You are an expert SOC Analyst AI specializing in brute force and credential attack detection.

Analyze the provided logon event logs and determine whether a brute force or
credential-based attack is occurring. Use your judgment — don't rely on a fixed
threshold. Look for patterns like:
- High volume of ActionType: LogonFailed from the same IP or against the same account
- Failed logons followed by a successful logon (compromise indicator)
- Short time gaps between attempts (suggests automation / tooling)
- Multiple accounts targeted from a single IP (password spray pattern)
- Unusual hours or geolocation for the logon source

Map findings to MITRE ATT&CK T1110 and sub-techniques where applicable.

Return ONLY valid JSON in this exact schema:

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
        "id": "T1110"
      },
      "confidence": "Low | Medium | High",
      "recommendations": ["isolate", "disable account", "monitor", "ignore"],
      "indicators_of_compromise": ["IP address", "account name"],
      "notes": "Optional analyst notes or assumptions"
    }
  ]
}

If no suspicious activity is found, return: { "findings": [] }
"""
}


# STEP 1 — Get target from user


def get_target():
    print(f"{Fore.LIGHTGREEN_EX}{'='*51}")
    print(f"{Fore.LIGHTGREEN_EX}   Brute Force Detector — Powered by OpenAI + MDE")
    print(f"{Fore.LIGHTGREEN_EX}{'='*51}\n")

    device = input(f"{Fore.WHITE}Enter the device name to investigate (e.g. windows-target-1): ").strip()
    hours_input = input(f"{Fore.WHITE}How many hours back to search? (default 24): ").strip()
    hours = int(hours_input) if hours_input.isdigit() else 24

    return device, hours


# STEP 2 — Query DeviceLogonEvents from Log Analytics


def query_logon_events(device_name, timerange_hours):
    """
    Queries DeviceLogonEvents for all logon activity on the target device.
    Returns both failed and successful logons so the AI can spot
    failed-then-success patterns (key brute force indicator).
    """

    fields = "TimeGenerated, AccountName, DeviceName, ActionType, RemoteIP, RemoteDeviceName"

    kql = f"""DeviceLogonEvents
| where DeviceName startswith "{device_name}"
| project {fields}
| order by TimeGenerated asc"""

    print(f"\n{Fore.LIGHTGREEN_EX}Constructed KQL Query:")
    print(f"{Fore.WHITE}{kql}\n")
    print(f"{Fore.LIGHTGREEN_EX}Querying Log Analytics Workspace ID: '{_keys.LOG_ANALYTICS_WORKSPACE_ID}'...")

    response = law_client.query_workspace(
        workspace_id=_keys.LOG_ANALYTICS_WORKSPACE_ID,
        query=kql,
        timespan=timedelta(hours=timerange_hours)
    )

    if not response.tables or len(response.tables[0].rows) == 0:
        return {"records": "", "count": 0}

    table = response.tables[0]
    df = pd.DataFrame(table.rows, columns=table.columns)
    records = df.to_csv(index=False)

    return {"records": records, "count": len(df)}


# STEP 3 — Send logs to OpenAI for brute force analysis

def analyze_for_brute_force(log_csv, device_name, openai_model):
    """
    Passes raw logon events to OpenAI.
    The AI decides whether brute force is happening — no hardcoded thresholds.
    Returns structured JSON findings.
    """

    user_message = {
        "role": "user",
        "content": (
            f"Analyze the following logon events from device '{device_name}' "
            f"for brute force or credential-based attack activity:\n\n{log_csv}"
        )
    }

    messages = [SYSTEM_PROMPT, user_message]

    # Count tokens + pick the right model (reuses your existing MODEL_MANAGEMENT logic)
    token_count = MODEL_MANAGEMENT.count_tokens(messages, openai_model)
    openai_model = MODEL_MANAGEMENT.choose_model(openai_model, token_count)

    # Validate model against allowlist (reuses your GUARDRAILS)
    GUARDRAILS.validate_model(openai_model)

    print(f"\n{Fore.LIGHTGREEN_EX}Initiating cognitive brute force analysis...\n")
    start = time.time()

    try:
        response = openai_client.chat.completions.create(
            model=openai_model,
            messages=messages,
            response_format={"type": "json_object"}
        )

        elapsed = time.time() - start
        results = json.loads(response.choices[0].message.content)
        finding_count = len(results.get("findings", []))

        print(
            f"{Fore.WHITE}Analysis complete. Took {elapsed:.2f}s — "
            f"found {Fore.LIGHTRED_EX}{finding_count}{Fore.WHITE} potential threat(s).\n"
        )

        return results

    except RateLimitError as e:
        print(f"{Fore.LIGHTRED_EX}{Style.BRIGHT}Rate limit hit — input may be too large.\n{e}")
        return None

    except OpenAIError as e:
        print(f"{Fore.RED}Unexpected OpenAI error:\n{e}")
        return None


# STEP 4 — Display findings


def display_findings(findings):
    for i, finding in enumerate(findings, 1):
        confidence = finding.get("confidence", "").lower()

        if confidence == "high":
            color = Fore.LIGHTRED_EX
        elif confidence == "medium":
            color = Fore.LIGHTYELLOW_EX
        else:
            color = Fore.LIGHTBLUE_EX

        print(f"\n{'='*51}")
        print(f"{Fore.LIGHTCYAN_EX}Threat #{i}: {finding.get('title')}{Fore.RESET}\n")
        print(f"{Fore.WHITE}{finding.get('description')}\n")
        print(f"{color}Confidence:        {finding.get('confidence')}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}Attack Type:       {finding.get('attack_type')}")
        print(f"Failed Attempts:   {finding.get('failed_attempt_count')}")
        print(f"Success After Fail:{finding.get('success_after_failure')}")

        print(f"\nSource IPs:")
        for ip in finding.get("source_ips", []):
            print(f"  - {ip}")

        print(f"\nTargeted Accounts:")
        for acct in finding.get("targeted_accounts", []):
            print(f"  - {acct}")

        mitre = finding.get("mitre", {})
        print(f"\nMITRE ATT&CK:")
        print(f"  Tactic:    {mitre.get('tactic')}")
        print(f"  Technique: {mitre.get('technique')}")
        print(f"  ID:        {mitre.get('id')}")

        print(f"\nIOCs:")
        for ioc in finding.get("indicators_of_compromise", []):
            print(f"  - {ioc}")

        print(f"\nRecommendations:")
        for rec in finding.get("recommendations", []):
            print(f"  - {rec}")

        print(f"\nNotes: {finding.get('notes')}")
        print("=" * 51)

# STEP 5 — Remediation (same pattern as _main.py VM isolation)


def remediate(findings, device_name):
    """
    For each high-confidence finding, prompt the analyst to isolate the VM.
    Reuses EXECUTOR functions from the existing project — no duplication.
    """

    token = EXECUTOR.get_bearer_token()
    machine_is_isolated = False

    for finding in findings:
        if finding.get("confidence", "").lower() != "high":
            continue

        if machine_is_isolated:
            # Already isolated this session — skip to avoid wasted API calls
            break

        print(f"\n{Fore.YELLOW}[!] High confidence threat detected on host: {device_name}")
        print(f"{Fore.LIGHTRED_EX}{finding.get('title')}")

        confirm = input(
            f"{Fore.RED}{Style.BRIGHT}Would you like to isolate this VM? (yes/no): {Style.RESET_ALL}"
        ).strip().lower()

        if confirm.startswith("y"):
            machine_id = EXECUTOR.get_mde_workstation_id_from_name(
                token=token,
                device_name=device_name
            )
            machine_is_isolated = EXECUTOR.quarantine_virtual_machine(
                token=token,
                machine_id=machine_id
            )

            if machine_is_isolated:
                print(f"{Fore.GREEN}[+] VM successfully isolated.{Style.RESET_ALL}")
                print(
                    f"{Fore.CYAN}Reminder: Release isolation when ready at: "
                    f"{Style.RESET_ALL}https://security.microsoft.com/"
                )
        else:
            print(f"{Fore.CYAN}[i] Isolation skipped by analyst.{Style.RESET_ALL}")


# MAIN


def main():

    # 1. Get target device and time range from analyst
    device_name, hours = get_target()

    # 2. Validate table + fields against GUARDRAILS allowlist
    GUARDRAILS.validate_tables_and_fields(
        "DeviceLogonEvents",
        "TimeGenerated, AccountName, DeviceName, ActionType, RemoteIP, RemoteDeviceName"
    )

    # 3. Query Log Analytics
    results = query_logon_events(device_name, hours)

    if results["count"] == 0:
        print(f"\n{Fore.WHITE}No logon events found for '{device_name}' in the last {hours} hour(s). Exiting.")
        return

    print(f"{Fore.WHITE}{results['count']} logon event(s) returned.\n")

    # 4. AI analysis
    input(f"Press {Fore.LIGHTGREEN_EX}[Enter]{Fore.WHITE} to begin AI analysis.")
    hunt = analyze_for_brute_force(results["records"], device_name, model)

    if not hunt or not hunt.get("findings"):
        print(f"\n{Fore.WHITE}No brute force activity detected. Exiting.")
        return

    # 5. Display findings
    input(f"\nPress {Fore.LIGHTGREEN_EX}[Enter]{Fore.WHITE} to view findings.")
    display_findings(hunt["findings"])

    # 6. Remediation — isolate VM if high confidence
    remediate(hunt["findings"], device_name)


if __name__ == "__main__":
    main()
