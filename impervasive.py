import argparse
import csv
import ipaddress
import os
import requests
import socket
from json.decoder import JSONDecodeError
from pathlib import Path
from urllib3.exceptions import InsecureRequestWarning
import yaml
from pyfiglet import figlet_format
from tabulate import tabulate
from resolver import custom_resolver, bind_ip

Response = requests.models.Response


def parse_sites(res: Response) -> list:
    try:
        data = res.json()
    except JSONDecodeError:
        raise SystemExit("[E] Error: Response from endpoint is not valid JSON")

    if all(key in data for key in ("res", "res_message")):
        if data["res"] != 0 or data["res_message"] != "OK":
            raise SystemExit(
                f"[E] Error {data['res']} in"
                f"response from endpoint: {data['res_message']}")
        else:
            if data["sites"]:
                return data["sites"]
            else:
                return []
    else:
        raise SystemExit("[E] Error in JSON response from endpoint")


def site_request(endpoint: str, verify: bool) -> str:
    site_headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
                    'AppleWebKit/537.36 (KHTML, like Gecko)'
                    'Chrome/91.0.4472.124 Safari/537.36'}
    try:
        res = requests.get(
            f"https://{endpoint}", headers=site_headers, verify=verify)
        res.raise_for_status()
        return "Success"
    except requests.exceptions.SSLError:
        if verify:
            raise SystemExit(f"[E] SSL Error in {endpoint}: Try running with -d set")
        else:
            return "SSL Error" # Handles non certificate SSL errors
    except requests.exceptions.HTTPError:
        return f"HTTP Error: {res.status_code}"
    except requests.exceptions.ConnectionError:
        return "Connection Error"
    except requests.exceptions.Timeout:
        return "Timed out"
    except requests.exceptions.RequestException:
        return "Request Exception"

banner = figlet_format("Impervasive") + """
Origin server testing tool for Imperva WAF
https://github.com/MorlaxAR/Impervasive
Milton Torasso (MorlaxAR) | MIT License
"""

parser = argparse.ArgumentParser(
    description="Origin server testing tool for Imperva WAF")
parser.add_argument("-d", "--disable_ssl_verify",
                    help="Disables certificate verification",
                    action="store_true")
parser.add_argument("-o", "--output_file",
                    help="CSV report output location")
args = parser.parse_args()

print(banner)

# Read config from file
script_dir = os.path.dirname(os.path.realpath(__file__))
os.chdir(script_dir)
conf_path = script_dir / Path("config.yaml")
if conf_path.is_file():
    with open(conf_path) as conf_file:
        try:
            conf = yaml.load(conf_file, Loader=yaml.FullLoader)
        except yaml.error.YAMLError:
            raise SystemExit(
                "[E] Error: Configuration file config.yaml is not valid YAML")
else:
    raise SystemExit(
        "[E] Error: Configuration file config.yaml does not exist")

if all(key in conf for key in ("api-key", "api-id")):
    api_key = conf["api-key"]
    api_id = conf["api-id"]
    if any(not value for value in (api_id, api_key)):
        for key in ("api-key", "api-id"):
            if not conf[key]:
                print(f"Error: {key} value not set")
        raise SystemExit(
            "[E] Error: Configuration file config.yaml has missing values")
else:
    for key in ("api-key", "api-id"):
        if key not in conf:
            print(f"Error: {key} key not found")
    raise SystemExit(
        "[E] Error: Configuration file config.yaml has missing keys")

# Request sites list from Imperva
imperva_headers = {
    "x-API-Key": api_key,
    "x-API-Id": str(api_id),
    "accept": "application/json",
    "User-Agent": "Impervasive 1.0"
}
endpoint = "https://my.imperva.com/api/prov/v1/sites/list"
sites = []
i = 0
while True:
    imperva_body = {
        "page_size": 50,
        "page_num": i
    }
    try:
        res = requests.post(
            endpoint,
            headers=imperva_headers,
            data=imperva_body)
        res.raise_for_status()
    # TO DO: Better exception handling of API request
    except requests.exceptions.RequestException as e:
        raise SystemExit(e)
    # Parse JSON response
    sites_page = parse_sites(res)
    if not sites_page:
        break
    sites = sites + sites_page
    i += 1

# Attempt WAF bypass for every site
etc_hosts = {}
report = []
if args.disable_ssl_verify:
    requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
for site in sites:
    hostname = site["display_name"]
    status = site["status"]
    ips = site["ips"]
    for host in ips:
        try:
            # Check if it is an IP (A reg) or a hostname (CNAME reg)
            ipaddress.ip_address(host)
            ip = host
        except ValueError:
            try:
                # Try to get IP address from CNAME host
                ip = socket.gethostbyname(host)
            except socket.gaierror:
                report.append(
                    (hostname, host, status, "Could not resolve origin IP"))
                continue
        # Check if site is up before attempting bypass
        info = site_request(hostname, not(args.disable_ssl_verify))
        if info != "Success":
            print(f"[!] {hostname} is down, skipping")
            report.append((hostname, host, status, "Site is down"))
            continue
        # Add mapping to virtual hosts file and attempt bypass
        etc_hosts = bind_ip(etc_hosts, hostname, 443, ip)
        socket.getaddrinfo = custom_resolver(etc_hosts, socket.getaddrinfo)
        info = site_request(hostname, not(args.disable_ssl_verify))
        if info == "Success":
            print(f"[+] WAF bypassed for {hostname}")
            report.append((hostname, host, status, "WAF Bypassed"))
        else:
            print(f"[-] Failed to bypass WAF for {hostname}: {info}")
            report.append((hostname, host, status, info))
print()
#Remove a column from cli table to make it fit better
cli_report = []
for row in report:
    cli_report.append(row[0:2] + row[3:])
cli_headers = ("Site", "Origin", "Bypass Result")
csv_headers = ("Site", "Origin", "Status", "Bypass Result")
if args.output_file:
    out_path = Path(args.output_file)
    try:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            with open(out_path, "w", newline='') as out_file:
                writer = csv.writer(out_file)
                writer.writerow(csv_headers)
                writer.writerows(report)
            print(f"[+] Report saved to {out_path.absolute()}\n")
        except OSError as err:
            print(f"[E] OS error when writing file: {err}\n")
    except OSError as err:
        print(f"[E] OS error when creating missing dirs: {err}\n")

print(tabulate(cli_report, headers=cli_headers, tablefmt="pretty"))
