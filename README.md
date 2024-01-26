# CxOne Get Engine Logs Tool Usage Guide

## Summary

This tool is designed to retrieve engine logs from Checkmarx One for specific scans and engines (SAST & IaC Security) and save them as text files. It caters to the need for in-depth analysis of engine-specific logs, facilitating troubleshooting and auditing of scan results.

## Syntax and Arguments

Execute the script using the following command line:

```
python get_engine_logs.py --base_url BASE_URL --tenant_name TENANT_NAME --api_key API_KEY [--scan_id SCAN_ID | --scan_id_file SCAN_ID_FILE] [--debug]
```

### Required Arguments

- `--base_url`: The base URL of the Checkmarx One region.
- `--tenant_name`: Your tenant name in Checkmarx One.
- `--api_key`: Your API key for authenticating with the Checkmarx One APIs.
- `--scan_id` (optional): The ID of the scan for which you want to retrieve the workflow.
- `--scan_id_file` (optional): Path to a text file containing a list of scan IDs, one per line.

### Optional Arguments

- `--iam_base_url`: Optional IAM base URL. Defaults to the same as `base_url` if not provided.
- `--debug`: Enable debug output. (Flag, no value required)

## Usage Examples

Retrieving and saving a single scan's engine logs:

```
python get_engine_logs.py --base_url https://cxone.example.com --tenant_name mytenant --api_key 12345 --scan_id 67890
```

Retrieving and saving multiple scan engine logs from a file:

```
python get_engine_logs.py --base_url https://cxone.example.com --tenant_name mytenant --api_key 12345 --scan_id_file scan_ids.txt
```

Retrieving and saving a scan's engine logs with debug output:

```
python get_engine_logs.py --base_url https://cxone.example.com --tenant_name mytenant --api_key 12345 --scan_id 67890 --debug
```

## Output

For each scan ID and engine, the script will attempt to retrieve the log. If successful, the log will be saved in a file named <scan_id>-<engine>.txt.
