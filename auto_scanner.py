import requests
import time
import json
from pprint import pprint
import pandas as pd

def Crawler(api_key, cluster, project_id):
    if cluster not in ['app', 'eu']:
        print("Invalid target URL. Please choose 'app' or 'eu'.")
        return

    url = f"https://{cluster}.brightsec.com/api/v1/scans"
    
    api = "api-key "
    full_api_key = str(api + api_key)

    while True:
        scan_name = input("Enter scan name: ")
        if len(scan_name) >= 3:
            break
        else:
            print("Scan name must be at least 3 characters long. Please try again.")

    host_name = input("Enter URL to start crawling from: ")
    template_id = None
    auth_id = None

    user_provided_template_id = input("Enter template ID (press Enter to select all tests by default): ")
    if user_provided_template_id:
        template_id = user_provided_template_id

    user_selected_auth = input('Would you like to use authentication object? (yes/no): ').lower()
    if user_selected_auth == "yes":
        headers = {
            'accept': 'application/json',
            'Content-Type': 'application/json',
            'Authorization': full_api_key
        }
        get_auth = requests.get(f"https://{cluster}.brightsec.com/api/v2/auth-objects", headers=headers)

        if get_auth.status_code == 200:
            data = json.loads(get_auth.text)
            items = data.get("items", [])

            if items:
                for i, item in enumerate(items, start=1):
                    auth_name = item.get("name")
                    auth_id = item.get("id")
                    print(f"{i}. {auth_name} - {auth_id}")

                auth_choice = int(input("Choose the number of the authentication object you want to use: "))
                if 1 <= auth_choice <= len(items):
                    auth_id = items[auth_choice - 1]["id"]
                else:
                    print("Invalid choice. Please select a valid number.")
            else:
                print("No authentication objects found.")
        else:
            print(f"Failed to retrieve authentication objects. Status code: {get_auth.status_code}, or make sure that the auth object has a project assigned to it")
            exit()
    else:
        auth_id = None

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

    print("Sending POST request to create a scan...")
    start_scan = requests.post('https://app.brightsec.com/api/v1/scans', headers=headers, json=data)
    if start_scan.status_code == 201:
        scan_id = start_scan.json().get('id')
        print(f"Scan started successfuly with ID: {scan_id}")
        exit(0)
    else:
        print("Failed to create a scan")
        return None

def har(api_key, cluster, project_id):
    if cluster not in ['app', 'eu']:
        print("Invalid target URL. Please choose 'app' or 'eu'.")
        return
    
    har_name = input("Enter Har file name: ")

    if not har_name.endswith(".har"):
        har_name += ".har"

    har_file = har_name
    url = f"https://{cluster}.brightsec.com/api/v1/projects/{project_id}/files"
    
    headers = {
        "accept": "application/json",
        "Authorization": f'api-key {api_key}'
    }

    files = {"file": (har_file, open(har_file, "rb"))}

    response = requests.post(url, headers=headers, files=files)
    response_data = response.json()
    if response.status_code == 200 or response.status_code == 201:
        print("Har file uploaded successfully")
        fileId = response_data.get("id")

        while True:
            scan_name = input("Enter scan name: ")
            if len(scan_name) >= 3:
                break
            else:
                print("Scan name must be at least 3 characters long. Please try again.")

        template_id = None
        auth_id = None

        user_provided_template_id = input("Enter template ID (press Enter to select all tests by default): ")
        if user_provided_template_id:
            template_id = user_provided_template_id

        user_selected_auth = input('Would you like to use authentication object? (yes/no): ').lower()
        if user_selected_auth == "yes":
            headers = {
                'accept': 'application/json',
                'Content-Type': 'application/json',
                'Authorization': f'api-key {api_key}'
            }
            get_auth = requests.get(f"https://{cluster}.brightsec.com/api/v2/auth-objects", headers=headers)

            if get_auth.status_code == 200:
                data = json.loads(get_auth.text)
                items = data.get("items", [])

                if items:
                    for i, item in enumerate(items, start=1):
                        auth_name = item.get("name")
                        auth_id = item.get("id")
                        print(f"{i}. {auth_name} - {auth_id}")

                    auth_choice = int(input("Choose the number of the authentication object you want to use: "))
                    if 1 <= auth_choice <= len(items):
                        auth_id = items[auth_choice - 1]["id"]
                    else:
                        print("Invalid choice. Please select a valid number.")
                else:
                    print("No authentication objects found.")
            else:
                print(f"Failed to retrieve authentication objects. Status code: {get_auth.status_code}, or make sure that the auth object has a project assigned to it")
                exit()
        else:
            auth_id = None

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

        print("Filtering hosts from provided HAR file...")

        host_response = requests.get(f"https://{cluster}.brightsec.com/api/v1/files/{fileId}/targets", headers=headers)
        host_data = host_response.json()
        host_urls = host_data.get("urls", [])

        if host_urls:
            print("Filtered Host URLs:")
            for i, host_url in enumerate(host_urls, start=1):
                print(f"{i}. {host_url}")

            user_choices = input("Enter the numbers of the hosts you want to include (comma-separated): ")
            selected_hosts = []

            try:
                choices = user_choices.split(',')
                for choice in choices:
                    choice_index = int(choice.strip())
                    if 1 <= choice_index <= len(host_urls):
                        selected_hosts.append({"url": host_urls[choice_index - 1]})
                    else:
                        print(f"Invalid choice: {choice_index}")
            except ValueError:
                print("Invalid input. Please enter valid numbers separated by commas.")

            if selected_hosts:
                cleaned_hosts = [host['url'].replace('http://', '').replace('https://', '').rstrip('/') for host in selected_hosts]
                data = {
                    "discoveryTypes": ["archive"],
                    "poolSize": 50,
                    "attackParamLocations": ["query", "fragment", "body"],
                    "fileId": f"{fileId}",
                    "hostsFilter":cleaned_hosts,
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
                print(data)
                print("Sending POST request to create a scan...")

                start_scan = requests.post('https://app.brightsec.com/api/v1/scans', headers=headers, json=data)
                if start_scan.status_code == 201:
                    scan_id = start_scan.json().get('id')
                    print(f"Scan started successfully with ID: {scan_id}")
                    exit(0)
                else:
                    print(f"Failed to create a scan. Status code: {start_scan.status_code}")
                    print(f"Response text: {start_scan.text}")
                    return None
            else:
                print("No hosts selected.")
        else:
            print("No host URLs found.")
    else:
        print(f"Failed to upload HAR file. Status code: {response.status_code}")

def get_scan_details(scan_id, api_key, cluster):
    if scan_id is None:
        print("Invalid scan ID")
        return

    if cluster not in ['app', 'eu']:
        print("Invalid target URL. Please choose 'app' or 'eu'.")
        return

    url = f"https://{cluster}.brightsec.com/api/v1/scans/{scan_id}"
    
    headers = {
        'accept': 'application/json',
        'Content-Type': 'application/json',
        'Authorization': f'api-key {api_key}'
    }

    print(f"Sending GET request to retrieve scan details for {cluster}...")
    scan_details_response = requests.get(url, headers=headers)

    if scan_details_response.status_code == 200:
        scan_details_json = scan_details_response.json()

        scan_details_df = pd.json_normalize(scan_details_json)

        file_name = f"scan_details_{scan_id}.csv"

        scan_details_df.to_csv(file_name, index=False)

        print(f"Scan details saved to {file_name}")
        exit(0)
    else:
        print(f"Failed to retrieve scan details. Status code: {scan_details_response.status_code}")
        
while True:
    print("Choose an option:")
    print("[1] Har")
    print("[2] Crawler")
    print("[3] Get Scan Details")
    print("[4] Quit")

    choice = input(">>> ")

    if choice == '1':
        cluster = input("Choose Cluster (app/eu): ")
        if cluster not in ['app', 'eu']:
            print("Invalid target URL. Please choose 'app' or 'eu'.")
            continue
        api_key = input("Enter API Key: ")
        project_id = input("Enter Project ID: ")
        har(api_key, cluster, project_id)
    elif choice == '2':
        cluster = input("Choose Cluster (app/eu): ")
        if cluster not in ['app', 'eu']:
            print("Invalid target URL. Please choose 'app' or 'eu'.")
            continue
        api_key = input("Enter API Key: ")
        project_id = input("Enter Project ID: ")
        scan_id = Crawler(api_key, cluster, project_id)

    elif choice == '3':
        cluster = input("Choose Cluster (app/eu): ")
        if cluster not in ['app', 'eu']:
            print("Invalid target URL. Please choose 'app' or 'eu'.")
            continue
        api_key = input("Enter API Key: ")
        project_id = input("Enter Project ID: ")
        scan_id = input("Enter Scan ID: ")
        get_scan_details(scan_id, api_key, cluster)
    elif choice == '4':
        break
    else:
        print("Invalid input. Please choose a valid option.")
