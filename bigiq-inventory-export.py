#!/usr/bin/env python3.12

import getpass
import os
import requests
import time
import urllib3

import logging
import argparse
import sys
import pandas as pd

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

LOG_FILE = 'bigiq-inventory-export.log'
logging.basicConfig(level=logging.INFO, filename=LOG_FILE)
logger = logging.getLogger(__name__)
# Restrict log file to owner-only access
if os.path.exists(LOG_FILE):
    os.chmod(LOG_FILE, 0o600)


def global_token_auth():
    global auth_token
    global auth_token_expiry
    try:
        auth_token
        auth_token_expiry
    except NameError:
        logger.debug('The variables auth_token or auth_token_expiry not found; creating variables with dummy values')
        auth_token = 'null'
        auth_token_expiry = 0
    # Check if current epoch time is less than token expiry;
    # skip token generation if not
    if (time.time() < auth_token_expiry):
        remaining_seconds = auth_token_expiry - time.time()
        logger.debug(f'Existing authentication token is still valid. Expires in {remaining_seconds} seconds.')
        return
    # request a new token
    url = f'https://{host}/mgmt/shared/authn/login'
    payload = {'username': username, 'password': password, 'provider': 'tmos'}
    headers = {'Content-type': 'application/json'}
    logger.debug(f'Token API call: {url}, {username}')
    try:
        response = requests.post(
            url,
            json=payload,
            headers=headers,
            verify=False
        )
        response.raise_for_status()  # Raise an exception for bad status codes
    except requests.exceptions.RequestException as e:
        logger.error(f'Error making API call: {e}')
        sys.exit(1)
    auth_token = response.json()['token']['token']
    auth_token_expiry = response.json()['token']['exp']
    logger.debug(f'Auth token retrieved, expires at {auth_token_expiry} epoch time')


def bigiq_http_get(uri, params):
    global_token_auth()
    url = f'https://{host}/{uri}'
    headers = {
        'Content-type': 'application/json',
        'X-F5-Auth-Token': auth_token
        }
    logger.debug(f'BIG-IQ HTTP GET URL:{url} {params}')
    try:
        response = requests.get(
            url,
            headers=headers,
            params=params,
            verify=False
        )
        response.raise_for_status()  # Raise an exception for bad status codes
    except requests.exceptions.RequestException as e:
        logger.error(f'Error making API call: {e} (Endpoint Response: {response.text})')
        return None
    logger.debug(f'BIG-IP API Response: {response.text}')
    return response


def bigiq_http_post(uri, payload):
    global_token_auth()
    url = f'https://{host}/{uri}'
    headers = {
        'Content-type': 'application/json',
        'X-F5-Auth-Token': auth_token
        }
    logger.debug(f'BIG-IQ HTTP POST {url} {payload}')
    try:
        response = requests.post(
            url,
            headers=headers,
            json=payload,
            verify=False
        )
        response.raise_for_status()  # Raise an exception for bad status codes
    except requests.exceptions.RequestException as e:
        logger.error(f'Error making API call: {e} (Endpoint Response: {response.text})')
        return None
    logger.debug(f'BIG-IP API Response: {response.text}')
    return response


def bigiq_http_patch(uri, payload):
    global_token_auth()
    url = f'https://{host}/{uri}'
    headers = {
        'Content-type': 'application/json',
        'X-F5-Auth-Token': auth_token
        }
    logger.debug(f'BIG-IQ HTTP PATCH {url} {payload}')
    try:
        response = requests.patch(
            url,
            headers=headers,
            json=payload,
            verify=False
        )
        response.raise_for_status()  # Raise an exception for bad status codes
    except requests.exceptions.RequestException as e:
        logger.error(f'Error making API call: {e} (Endpoint Response: {response.text})')
        return None
    logger.debug(f'BIG-IP API Response: {response.text}')
    return response


def parse_arguments():
    # Create the parser
    parser = argparse.ArgumentParser(description="Process login credentials and hostname.")

    # Add arguments
    parser.add_argument("--username", type=str, required=True, help="BIG-IQ user")
    parser.add_argument("--password", type=str, required=False, help="password for BIG-IQ user (reads BIGIQ_PASSWORD env var or prompts securely if omitted)")
    parser.add_argument("--hostname", type=str, required=True, help="BIG-IQ host (IP/FQDN)")
    parser.add_argument("--csv", type=str, required=False, help="CSV to write output")
    parser.add_argument("--debug", action="store_true")

    # Parse arguments
    args = parser.parse_args()
    return args

def Retrieve_Virtual_Servers():
    virtual_servers = bigiq_http_get(
        uri='mgmt/cm/adc-core/working-config/ltm/virtual',
        params=None
    )
    return virtual_servers.json()

def Retrieve_Pools():
    pools = bigiq_http_get(
        uri='mgmt/cm/adc-core/working-config/ltm/pool',
        params=None
    )
    return pools.json()

def Retrieve_Pool_Members():
    pool_members = bigiq_http_post(
        uri='mgmt/shared/pipeline/manager/All-Pool-Members-Pipeline',
        payload={
            "multiStageQueryRequest": {
                "repeatLastStageUntilTerminated": False,
                "queryParamsList": [
                    {
                        "description": "retrieval",
                        "filterProcessorReference": {
                            "link": "https://localhost/mgmt/shared/index/es-config?%24filter=kind%20eq%20'cm%3Aadc-core%3Aworking-config%3Altm%3Apool%3Amembers%3Aadcpoolmemberstate'&%24orderby=name%20asc&%24top=150&%24skip=0"
                        },
                        "pipelineAction": "DATA_RETRIEVAL",
                        "runStageInternally": False
                    },
                    {
                        "description": "expand",
                        "managedPipelineWorkerName": "expand-pipe",
                        "jsonContext": {
                            "references": [
                                {
                                    "expand": "parentInfo/deviceReference",
                                    "select": ["hostname", "properties"]
                                }
                            ]
                        }
                    },
                    {
                        "description": "stats",
                        "managedPipelineWorkerName": "resource-stats-pipe",
                        "pipelineAction": "DATA_PROCESSING",
                        "runStageInternally": False
                    }
                ]
            },
            "getOnPostAndTerminate": True,
            "isPerformanceBoostingEnabled": False
        }
    )
    return pool_members

def main():
    # Define BIG-IQ environment variables
    global username
    global password
    global host
    # Read command line arguments
    args = parse_arguments()
    if args.debug:
        logging.info('Setting logging level to debug')
        logger.setLevel(logging.DEBUG)
    username = args.username
    password = args.password or os.environ.get('BIGIQ_PASSWORD') or getpass.getpass(prompt='BIG-IQ Password: ')
    host = args.hostname
    pools = Retrieve_Pools()
    pool_members = Retrieve_Pool_Members()
    virtual_servers = pd.DataFrame(Retrieve_Virtual_Servers()['items'])
    if args.csv:
        base, ext = os.path.splitext(args.csv)
        virtual_servers.to_csv(args.csv, index=False)
        pd.DataFrame(pools['items']).to_csv(f'{base}_pools{ext}', index=False)
        pd.DataFrame(pool_members.json()['items']).to_csv(f'{base}_pool_members{ext}', index=False)


if __name__ == '__main__':
    main()
