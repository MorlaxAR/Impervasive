# Impervasive
Origin server testing tool for Imperva WAF

![Python](https://img.shields.io/badge/python-v3.6+-blue.svg) [![License](https://img.shields.io/badge/license-MIT-blue.svg)](https://opensource.org/licenses/MIT) ![Contributions welcome](https://img.shields.io/badge/contributions-welcome-orange.svg) [![GitHub Issues](https://img.shields.io/github/issues/MorlaxAR/Impervasive.svg)](https://github.com/anfederico/clairvoyant/issues)
## Disclaimer
I'm not a developer, I'm just a security guy who had to make this exact check and decided to share the script with the community. Code quality might not be great, and contributions are welcome!

The script might be slow if you have hundreds of sites  because there is no multithreading implemented. I consider this acceptable because this is a check one would usually run once a month, but I might come back and finish the multithreaded version of the script.
## About
Impervasive is a Python3 script designed to check if the origin servers behind an Imperva WAF can be accessed directly, bypassing the WAF. 

Ideally, a server behind a WAF should be configured to only allow incoming connections from the WAF.

This tool is directed to security professionals or IT administrators who use Imperva to protect their public facing sites.

## How does it work
Impervasive overrides `socket.getaddrinfo` with a custom function that uses a local variable as a mock /etc/hosts file. This allows the script to query the origin server with the correct hostname while maintaining SNI support. The original idea for the implementation came from this [Thread](https://stackoverflow.com/questions/29995133/python-requests-use-navigate-site-by-servers-ip).


The script leverages Imperva's API to obtain a list of sites for an account.  Then, it does the following for each site:

 1. Check if the site is up
 2. Add a mapping to the mock hosts file for the origin server
 3. Make an HTTP request to the origin server
 4. Check if the request was successful

## Requirements
With python3 and pip installed, open a terminal in the Impervasive folder and run:
`pip install -r requirements.txt`

Then copy `config.yaml.example` into `config.yaml` and configure both the `api-key` and `api-id` fields. The account associated with the API must have enough privileges for the `https://my.imperva.com/api/prov/v1/sites/list` endpoint.

## Instructions
Open a shell in the Impervasive folder and run the script with:

 - `python3 ./impervasive.py` on Linux
 - `python .\impervasive.py` on Windows

### Optional Parameters

 - -d / --disable-ssl-verify: Disables certificate checking for the HTTPS requests.
 - -o PATH/ --output-file PATH: Generates a .CSV report and saves it to the specified file PATH.
 - -h / --help: Shows the help menu.
