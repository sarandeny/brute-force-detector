import json
import os
import webbrowser
import threading
from flask import Flask, render_template, request, jsonify, redirect, url_for

import EXECUTOR
import GUARDRAILS
import PROMPT_MANAGEMENT
import MODEL_MANAGEMENT

from openai import OpenAI, RateLimitError, OpenAIError
from azure.identity import DefaultAzureCredential
from azure.monitor.query import LogsQueryClient

app = Flask(__name__, template_folder=os.path.join(os.path.dirname(__file__), 'templates'))

# ── Key storage — saved locally next to the exe / script ─────────────────────
KEYS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".config.json")

def load_keys():
    if os.path.exists(KEYS_FILE):
        with open(KEYS_FILE, "r") as f:
            return json.load(f)
    return {}

def save_keys(openai_key, workspace_id):
    with open(KEYS_FILE, "w") as f:
        json.dump({
            "OPENAI_API_KEY": openai_key,
            "LOG_ANALYTICS_WORKSPACE_ID": workspace_id
        }, f)

def keys_configured():
    keys = load_keys()
    return bool(keys.get("OPENAI_API_KEY") and keys.get("LOG_ANALYTICS_WORKSPACE_ID"))

# ── Clients (lazy) ────────────────────────────────────────────────────────────
law_client    = None
openai_client = None
model         = MODEL_MANAGEMENT.DEFAULT_MODEL

def get_clients():
    global law_client, openai_client
    keys = load_keys()
    if law_client is None:
        law_client = LogsQueryClient(credential=DefaultAzureCredential())
    if openai_client is None:
        openai_client = OpenAI(api_key=keys["OPENAI_API_KEY"])

# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    if not keys_configured():
        return redirect(url_for("setup"))
    return render_template("index.html")


@app.route("/setup", methods=["GET"])
def setup():
    return render_template("setup.html")


@app.route("/save-keys", methods=["POST"])
def save_keys_route():
    data         = request.get_json()
    openai_key   = data.get("openai_key", "").strip()
    workspace_id = data.get("workspace_id", "").strip()

    if not openai_key or not workspace_id:
        return jsonify({"error": "Both fields are required."}), 400

    save_keys(openai_key, workspace_id)

    # Reset clients so they reinitialize with new keys
    global law_client, openai_client
    law_client    = None
    openai_client = None

    return jsonify({"success": True})


@app.route("/clear-keys", methods=["POST"])
def clear_keys():
    if os.path.exists(KEYS_FILE):
        os.remove(KEYS_FILE)
    global law_client, openai_client
    law_client    = None
    openai_client = None
    return jsonify({"success": True})


@app.route("/analyze", methods=["POST"])
def analyze():
    if not keys_configured():
        return jsonify({"error": "Keys not configured. Please complete setup first."}), 401

    get_clients()

    data        = request.get_json()
    device_name = data.get("device_name", "").strip()
    hours       = int(data.get("hours", 24))

    if not device_name:
        return jsonify({"error": "Device name is required."}), 400

    try:
        GUARDRAILS.validate_tables_and_fields(
            "DeviceLogonEvents",
            "TimeGenerated, AccountName, DeviceName, ActionType, RemoteIP, RemoteDeviceName"
        )
    except SystemExit:
        return jsonify({"error": "GUARDRAILS validation failed."}), 400

    keys   = load_keys()
    result = EXECUTOR.query_log_analytics(
        log_analytics_client=law_client,
        workspace_id=keys["LOG_ANALYTICS_WORKSPACE_ID"],
        timerange_hours=hours,
        table_name="DeviceLogonEvents",
        device_name=device_name,
        fields="TimeGenerated, AccountName, DeviceName, ActionType, RemoteIP, RemoteDeviceName",
        caller="",
        user_principal_name=""
    )

    if result["count"] == 0:
        return jsonify({"findings": [], "log_count": 0, "message": "No logon events found."})

    user_message = PROMPT_MANAGEMENT.build_brute_force_prompt(device_name, result["records"])
    messages     = [PROMPT_MANAGEMENT.SYSTEM_PROMPT, user_message]
    token_count  = MODEL_MANAGEMENT.count_tokens(messages, model)
    chosen_model = MODEL_MANAGEMENT.choose_model(model, token_count, interactive=False)

    try:
        GUARDRAILS.validate_model(chosen_model)
    except SystemExit:
        return jsonify({"error": f"Model '{chosen_model}' failed GUARDRAILS validation."}), 400

    try:
        response = openai_client.chat.completions.create(
            model=chosen_model,
            messages=messages,
            response_format={"type": "json_object"}
        )
        findings = json.loads(response.choices[0].message.content)
        return jsonify({**findings, "log_count": result["count"], "model_used": chosen_model})

    except RateLimitError:
        return jsonify({"error": "Rate limit hit — try a shorter time range."}), 429

    except OpenAIError as e:
        return jsonify({"error": f"OpenAI error: {str(e)}"}), 500


@app.route("/isolate", methods=["POST"])
def isolate():
    if not keys_configured():
        return jsonify({"error": "Keys not configured."}), 401

    get_clients()

    data        = request.get_json()
    device_name = data.get("device_name", "").strip()

    if not device_name:
        return jsonify({"error": "Device name is required."}), 400

    try:
        token      = EXECUTOR.get_bearer_token()
        machine_id = EXECUTOR.get_mde_workstation_id_from_name(token, device_name)
        success    = EXECUTOR.quarantine_virtual_machine(token, machine_id)

        if success:
            return jsonify({"success": True, "message": f"{device_name} has been isolated."})
        else:
            return jsonify({"success": False, "message": "Isolation request failed."}), 500

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── Launch ────────────────────────────────────────────────────────────────────

def open_browser():
    webbrowser.open("http://127.0.0.1:5000")

if __name__ == "__main__":
    threading.Timer(1.0, open_browser).start()
    app.run(debug=False, port=5000, use_reloader=False)
