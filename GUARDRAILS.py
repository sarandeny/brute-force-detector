from colorama import Fore, Style

# TODO: Provide allowed fields later
ALLOWED_TABLES = {
    "DeviceProcessEvents": { "TimeGenerated", "AccountName", "ActionType", "DeviceName", "InitiatingProcessCommandLine", "ProcessCommandLine" },
    "DeviceNetworkEvents": { "TimeGenerated", "ActionType", "DeviceName", "RemoteIP", "RemotePort" },
    "DeviceLogonEvents": { "TimeGenerated", "AccountName", "DeviceName", "ActionType", "RemoteIP", "RemoteDeviceName" },
    "AlertInfo": {},  # No fields specified in tools
    "AlertEvidence": {},  # No fields specified in tools
    "DeviceFileEvents": {"TimeGenerated","ActionType","DeviceName","FileName","FolderPath","InitiatingProcessAccountName","SHA256"},
    "DeviceRegistryEvents": {},  # No fields specified in tools
    "AzureNetworkAnalytics_CL": { "TimeGenerated", "FlowType_s", "SrcPublicIPs_s", "DestIP_s", "DestPort_d", "VM_s", "AllowedInFlows_d", "AllowedOutFlows_d", "DeniedInFlows_d", "DeniedOutFlows_d" },
    "AzureActivity": {"TimeGenerated", "OperationNameValue", "ActivityStatusValue", "ResourceGroup", "Caller", "CallerIpAddress", "Category" },
    "SigninLogs": {"TimeGenerated", "UserPrincipalName", "OperationName", "Category", "ResultSignature", "ResultDescription", "AppDisplayName", "IPAddress", "LocationDetails" },
}

# https://platform.openai.com/docs/models/compare
ALLOWED_MODELS = {
    "gpt-4.1-nano": {"max_input_tokens": 1_047_576, "max_output_tokens": 32_768,  "cost_per_million_input": 0.10, "cost_per_million_output": 0.40,  "tier": {"free": 40_000, "1": 200_000, "2": 2_000_000, "3": 4_000_000, "4": 10_000_000, "5": 150_000_000}},
    "gpt-4.1":      {"max_input_tokens": 1_047_576, "max_output_tokens": 32_768,  "cost_per_million_input": 1.00, "cost_per_million_output": 8.00,  "tier": {"free": None,   "1": 30_000,  "2": 450_000,   "3": 800_000,   "4": 2_000_000,  "5": 30_000_000}},
    "gpt-5-mini":   {"max_input_tokens": 272_000,   "max_output_tokens": 128_000, "cost_per_million_input": 0.25, "cost_per_million_output": 2.00,  "tier": {"free": None,   "1": 200_000, "2": 2_000_000, "3": 4_000_000, "4": 10_000_000, "5": 180_000_000}},
    "gpt-5":        {"max_input_tokens": 272_000,   "max_output_tokens": 128_000, "cost_per_million_input": 1.25, "cost_per_million_output": 10.00, "tier": {"free": None,   "1": 30_000,  "2": 450_000,   "3": 800_000,   "4": 2_000_000,  "5": 40_000_000}}
}

def validate_tables_and_fields(table, fields):

    print(f"{Fore.LIGHTGREEN_EX}Validating Tables and Fields...")
    if table not in ALLOWED_TABLES:
        print(f"{Fore.RED}{Style.BRIGHT}ERROR: "f"Table '{table}' is not in allowed list — {Fore.RED}{Style.BRIGHT}{Style.RESET_ALL}exiting.")
        exit(1)
    
    fields = fields.replace(' ','').split(',')

    for field in fields:
        if field not in ALLOWED_TABLES[table]:
            print(f"{Fore.RED}{Style.BRIGHT}ERROR: Field '{field}' is not in allowed list for Table '{table}' — {Fore.RED}{Style.BRIGHT}{Style.RESET_ALL}exiting.")
            exit(1)
    
    print(f"{Fore.WHITE}Fields and tables have been validated and comply with the allowed guidelines.\n")

def validate_model(model):
    if model not in ALLOWED_MODELS:
        print(f"{Fore.RED}{Style.BRIGHT}ERROR: Model '{model}' is not allowed — {Fore.RED}{Style.BRIGHT}{Style.RESET_ALL}exiting.")
        exit(1)
    else:
        print(f"{Fore.LIGHTGREEN_EX}Selected model is valid: {Fore.CYAN}{model}\n{Style.RESET_ALL}")


