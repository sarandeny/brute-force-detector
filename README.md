# 🛡 Brute Force Detector

An AI-powered credential attack detection platform built for SOC analysts. Connects to **Microsoft Defender for Endpoint** via **Azure Log Analytics**, queries `DeviceLogonEvents` using KQL, and passes the raw log data to **OpenAI** for intelligent brute force analysis — no hardcoded thresholds, no rules engine. Just AI-driven judgment.

Results are surfaced through a clean **Flask web UI** with collapsible findings, MITRE ATT&CK mapping, IOC extraction, and one-click **VM isolation** via the MDE API.

---

## Screenshot

<img width="1915" height="726" alt="image" src="https://github.com/user-attachments/assets/fbc1ec4e-cb71-42d6-a965-86fa783e2037" />


---

## How It Works

```
Analyst enters device name + time range
        ↓
Flask backend validates table/fields via GUARDRAILS
        ↓
KQL query runs against Azure Log Analytics (DeviceLogonEvents)
        ↓
Raw CSV logs sent to OpenAI for brute force analysis
        ↓
Structured JSON findings returned: attack type, IOCs, MITRE, confidence
        ↓
Results rendered in browser — isolate VM if high confidence
```

---

## Features

- **AI-driven detection** — OpenAI analyzes log patterns without fixed thresholds
- **Pattern recognition** — detects brute force, password spray, credential stuffing, and suspicious logons
- **MITRE ATT&CK mapping** — findings mapped to T1110 and sub-techniques (T1110.001–T1110.004)
- **IOC extraction** — source IPs, targeted accounts, log lines surfaced per finding
- **Confidence scoring** — High / Medium / Low with analyst notes
- **VM isolation** — one-click device isolation via the MDE API directly from the UI
- **Guardrails** — allowlisted KQL tables, fields, and OpenAI models enforced at runtime
- **Model management** — token counting, cost estimation, and interactive model switching

---

## Tech Stack

| Layer | Technology |
|---|---|
| Language | Python 3.11 |
| Web framework | Flask |
| AI | OpenAI API (gpt-5-mini default) |
| Log source | Azure Log Analytics — DeviceLogonEvents |
| Auth | Azure DefaultAzureCredential |
| Endpoint actions | Microsoft Defender for Endpoint API |
| Token counting | tiktoken |
| Frontend | Vanilla HTML/CSS/JS |

---

## Project Structure

```
brute_force_minimal/
├── flask_app.py          # Flask backend — routes, API calls, orchestration
├── brute_force_detector.py  # Original CLI version
├── EXECUTOR.py           # Azure auth, MDE API, Log Analytics queries
├── GUARDRAILS.py         # Allowlisted tables, fields, and models
├── MODEL_MANAGEMENT.py   # Token counting, cost estimation, model selection
├── PROMPT_MANAGEMENT.py  # System prompt, formatting schema, message builder
├── _keys.py              # API keys and workspace ID (not committed)
├── templates/
│   └── index.html        # Web UI
└── requirements.txt
```

---

## Prerequisites

- Python 3.11
- An **Azure subscription** with:
  - Microsoft Defender for Endpoint enabled
  - A Log Analytics Workspace connected to MDE
  - Azure CLI installed and logged in (`az login`)
- An **OpenAI API key**

---

## Setup

### 1. Clone the repository

```bash
git clone https://github.com/YOUR_USERNAME/brute-force-detector.git
cd brute-force-detector
```

### 2. Install dependencies

```bash
pip install flask openai azure-identity azure-monitor-query pandas colorama tiktoken
```

Or if using the requirements file:

```bash
pip install -r requirements.txt
```

### 3. Configure your keys

Create a `_keys.py` file in the project root:

```python
OPENAI_API_KEY = "sk-..."
LOG_ANALYTICS_WORKSPACE_ID = "your-workspace-id-here"
```

> **Never commit `_keys.py` to GitHub.** It is listed in `.gitignore`.

To find your Log Analytics Workspace ID:
- Go to **Azure Portal** → **Log Analytics Workspaces** → select your workspace → **Overview** → copy the **Workspace ID**

### 4. Authenticate with Azure

The app uses `DefaultAzureCredential`. The easiest way to authenticate locally is via the Azure CLI:

```bash
az login
```

### 5. Run the app

```bash
python flask_app.py
```

The browser will open automatically at `http://127.0.0.1:5000`.

---

## Usage

1. Enter the **device name** you want to investigate (prefix match — e.g. `windows-target-1`)
2. Set the **time range** in hours (default: 24)
3. Click **Run Analysis**
4. The app queries `DeviceLogonEvents` from your Log Analytics workspace
5. Logs are sent to OpenAI for analysis
6. Findings appear with confidence level, attack type, MITRE mapping, IOCs, and recommendations
7. For **High confidence** findings, an **Isolate Device** button appears — this calls the MDE API to fully isolate the VM

---

## Detection Logic

The AI looks for the following patterns without relying on fixed thresholds:

| Pattern | Indicator |
|---|---|
| High volume of `LogonFailed` from same IP | Brute force |
| Multiple accounts targeted from one IP | Password spray (T1110.003) |
| Failed logons followed by success | Likely compromise |
| Short time gaps between attempts | Automation / tooling |
| Unusual hours or unexpected source IPs | Suspicious logon |

All findings are mapped to **MITRE ATT&CK T1110** (Brute Force) and relevant sub-techniques.

---

## GUARDRAILS

The `GUARDRAILS.py` module enforces security boundaries at runtime:

- Only **allowlisted KQL tables** can be queried (e.g. `DeviceLogonEvents`, `DeviceNetworkEvents`)
- Only **allowlisted fields** per table are permitted
- Only **allowlisted OpenAI models** can be used, with token limits and cost tracking per tier

If any validation fails, the app exits before making any API calls.

---

## Environment Variables (Alternative to `_keys.py`)

You can use environment variables instead of `_keys.py`:

```bash
export OPENAI_API_KEY="sk-..."
export LOG_ANALYTICS_WORKSPACE_ID="your-workspace-id"
```

Then update `_keys.py` to read from `os.environ`.

---

## Roadmap

- [ ] Multi-device investigation in a single run
- [ ] Export findings to PDF / CSV
- [ ] Alert creation in Microsoft Sentinel
- [ ] Support for additional tables (SigninLogs, AzureActivity)
- [ ] Dark/light theme toggle

---

## Author

**Saran Deny**
Cybersecurity Support Analyst · TryHackMe Top 1% · CompTIA Security+

[LinkedIn](https://linkedin.com/in/saran-deny) · [GitHub](https://github.com/sarandeny)

---

## Disclaimer

This tool is intended for authorized security investigations only. Always ensure you have permission to query and act on the systems you are investigating. VM isolation is a disruptive action — use with care.
