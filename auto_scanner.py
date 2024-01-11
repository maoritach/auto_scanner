import requests
import time
from pprint import pprint
import pandas as pd

def Crawler(api_key, target_url, project_id):
    if target_url not in ['app', 'eu']:
        print("Invalid target URL. Please choose 'app' or 'eu'.")
        return

    url = f"https://{target_url}.brightsec.com/api/v1/scans"
    
    api = "api-key "
    full_api_key = str(api + api_key)

    print(f"API Key: {full_api_key}")

    scan_name = input("Enter scan name: ")
    host_name = input("Enter URL to start crawling from: ")
    template_id = None
    auth_id = None

    user_provided_template_id = input("Enter template ID (press Enter to select all tests by default): ")
    if user_provided_template_id:
        template_id = user_provided_template_id

    user_provided_auth_id = input("Enter auth ID (press Enter to skip auth ID): ")
    if user_provided_auth_id:
        auth_id = user_provided_auth_id

    use_repeater = input("Use repeater? (yes/no): ").lower()
    repeater_ids = []

    if use_repeater == 'yes':
        repeater_id = input("Enter repeater ID: ")
        repeater_ids.append(repeater_id)

    headers = {
        'accept': 'application/json',
        'Content-Type': 'application/json',
        'Authorization': full_api_key
    }

    data = {
        "discoveryTypes": ["crawler"],
        "poolSize": 50,
        "crawlerUrls": [host_name],
        "attackParamLocations": ["query", "fragment", "body"],
        "smart": True,
        "optimizedCrawler": True,
        "maxInteractionsChainLength": 5,
        "skipStaticParams": True,
        "projectId": project_id,
        "exclusions": {
            "requests": [
                {
                    "patterns": [
                        "(?<excluded_file_ext>(\\/\\/[^?#]+\\.)((?<image>jpg|jpeg|png|gif|svg)|(?<font>ttf|otf|fnt|fon))(?:$|#|\\?))"
                    ],
                    "methods": ["GET"]
                }
            ]
        },
        "slowEpTimeout": 100,
        "targetTimeout": 120,
        "name": scan_name,
        "authObjectId": auth_id,
        "module": "dast",
        "templateId": template_id,
        "info": {
            "client": {
                "name": "bright-cli",
                "version": "10.0.0"
            },
            "provider": "string",
            "source": "api"
        }
    }

    if repeater_ids:
        data["repeaters"] = repeater_ids

    print("Request Data:")
    pprint(data)

    print("Sending POST request to create a scan...")
    start_scan = requests.post(url, headers=headers, json=data)

    print("Request:")
    print(start_scan.request.method, start_scan.request.url)
    print("Request Headers:")
    pprint(dict(start_scan.request.headers))
    print("Request Body:")
    pprint(data)
    print("Response:")
    print(start_scan.status_code)
    pprint(start_scan.json())
    
    if start_scan.status_code == 201:
        scan_id = start_scan.json().get('id')
        return scan_id
    else:
        print("Failed to create a scan")
        return None

def HAR(api_key, target_url, project_id):
    if target_url not in ['app', 'eu']:
        print("Invalid target URL. Please choose 'app' or 'eu'.")
        return

    api = "api-key "
    har_name = input("Enter HAR file name: ")

    if not har_name.endswith(".har"):
        har_name += ".har"

    har_file = har_name
    url = f"https://{target_url}.brightsec.com/api/v1/projects/{project_id}/files"
    
    headers = {
        "accept": "application/json",
        "Authorization": f'api-key {api_key}'
    }

    files = {"file": (har_file, open(har_file, "rb"))}

    response = requests.post(url, headers=headers, files=files)

    if response.status_code == 200 or response.status_code == 201:
        print("HAR file uploaded successfully")

    scan_name = input("Enter scan name: ")
    template_id = None
    auth_id = None
    
    user_provided_template_id = input("Enter template ID (press Enter to select all tests by default): ")
    if user_provided_template_id:
        template_id = user_provided_template_id

    user_provided_auth_id = input("Enter auth ID (press Enter to skip auth ID): ")
    if user_provided_auth_id:
        auth_id = user_provided_auth_id

    use_repeater = input("Use repeater? (yes/no): ").lower()
    repeater_ids = []

    if use_repeater == 'yes':
        repeater_id = input("Enter repeater ID: ")
        repeater_ids.append(repeater_id)

    headers = {
        'accept': 'application/json',
        'Content-Type': 'application/json',
        'Authorization': f'api-key {api_key}'
    }

    data = {
        "discoveryTypes": ["archive"],
        "poolSize": 50,
        "attackParamLocations": ["query", "fragment", "body"],
        "fileId": "kRvycMy3PkWwvs1ZD1tqF1",
        "hostsFilter": ["brokencrystals.com"],
        "smart": True,
        "optimizedCrawler": True,
        "maxInteractionsChainLength": 5,
        "skipStaticParams": True,
        "projectId": project_id,
        "exclusions": {
            "requests": [
                {
                    "patterns": [
                        "(?<excluded_file_ext>(\\/\\/[^?#]+\\.)((?<image>jpg|jpeg|png|gif|svg)|(?<font>ttf|otf|fnt|fon))(?:$|#|\\?))"
                    ],
                    "methods": ["GET"]
                }
            ]
        },
        "slowEpTimeout": 100,
        "targetTimeout": 120,
        "name": scan_name,
        "authObjectId": auth_id,
        "module": "dast",
        "templateId": template_id,
        "info": {
            "client": {
                "name": "bright-cli",
                "version": "10.0.0"
            },
            "provider": "string",
            "source": "api"
        }
    }

    if repeater_ids:
        data["repeaters"] = repeater_ids

    print("Request Data:")
    pprint(data)

    print("Sending POST request to create a scan...")
    start_scan = requests.post(url, headers=headers, json=data)

    print("Request:")
    print(start_scan.request.method, start_scan.request.url)
    print("Request Headers:")
    pprint(dict(start_scan.request.headers))
    print("Request Body:")
    pprint(data)
    print("Response:")
    print(start_scan.status_code)
    pprint(start_scan.json())
    
    if start_scan.status_code == 201:
        scan_id = start_scan.json().get('id')
        return scan_id
    else:
        print("Failed to create a scan")
        return None

def get_scan_details(scan_id, api_key, target_url):
    if scan_id is None:
        print("Invalid scan ID")
        return

    if target_url not in ['app', 'eu']:
        print("Invalid target URL. Please choose 'app' or 'eu'.")
        return

    url = f"https://{target_url}.brightsec.com/api/v1/scans/{scan_id}"
    
    headers = {
        'accept': 'application/json',
        'Content-Type': 'application/json',
        'Authorization': f'api-key {api_key}'
    }

    print(f"Sending GET request to retrieve scan details for {target_url}...")
    scan_details_response = requests.get(url, headers=headers)

    if scan_details_response.status_code == 200:
        scan_details_json = scan_details_response.json()

        scan_details_df = pd.json_normalize(scan_details_json)

        file_name = f"scan_details_{scan_id}.csv"

        scan_details_df.to_csv(file_name, index=False)

        print(f"Scan details saved to {file_name}")
    else:
        print(f"Failed to retrieve scan details. Status code: {scan_details_response.status_code}")

# Main logic - moved API key, target URL, and project ID here as they're used every time.
while True:
    print("Choose an option:")
    print("[1] HAR")
    print("[2] Crawler")
    print("[3] Get Scan Details")
    print("[4] Quit")

    choice = input(">>> ")

    if choice == '1':
        target_url = input("Choose Target URL (app/eu): ")
        if target_url not in ['app', 'eu']:
            print("Invalid target URL. Please choose 'app' or 'eu'.")
            continue
        api_key = input("Enter API Key: ")
        project_id = input("Enter Project ID: ")
        HAR(api_key, target_url, project_id)
    elif choice == '2':
        target_url = input("Choose Target URL (app/eu): ")
        if target_url not in ['app', 'eu']:
            print("Invalid target URL. Please choose 'app' or 'eu'.")
            continue
        api_key = input("Enter API Key: ")
        project_id = input("Enter Project ID: ")
        scan_id = Crawler(api_key, target_url, project_id)
        if scan_id:
            while True:
                scan_details = get_scan_details(scan_id, api_key, target_url)
                if scan_details.get('status') == 'completed':
                    print("Scan completed.")
                    break
                time.sleep(30)
    elif choice == '3':
        target_url = input("Choose Target URL (app/eu): ")
        if target_url not in ['app', 'eu']:
            print("Invalid target URL. Please choose 'app' or 'eu'.")
            continue
        api_key = input("Enter API Key: ")
        project_id = input("Enter Project ID: ")
        scan_id = input("Enter Scan ID: ")
        get_scan_details(scan_id, api_key, target_url)
    elif choice == '4':
        break
    else:
        print("Invalid input. Please choose a valid option.")
