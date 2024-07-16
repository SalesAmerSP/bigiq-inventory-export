#!/usr/bin/env python3.12

import requests
import time
import json
import logging
import argparse
import sys
import pandas as pd

logging.basicConfig(level=logging.INFO,filename='bigiq-inventory-export.log')
logger = logging.getLogger(__name__)


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
    logger.debug(f'Token API call: {url}, {headers}, {username}')
    try:
        response = requests.post(
            url,
            json=payload,
            headers=headers
        )
        response.raise_for_status()  # Raise an exception for bad status codes
    except requests.exceptions.RequestException as e:
        logger.error(f'Error making API call: {e}')
        SystemExit()
    auth_token = response.json()['token']['token']
    auth_token_expiry = response.json()['token']['exp']
    logger.debug(f'Auth token retrieved with expiration of {auth_token_expiry} epoch time')


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
            params=params
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
            json=payload
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
            json=payload
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
    parser.add_argument("--password", type=str, required=True, help="password for BIG-IQ user")
    parser.add_argument("--hostname", type=str, required=True, help="BIG-IQ host (IP/FQDN)")
    parser.add_argument("--csv", type=str, required=False, help="CSV to write output")
    parser.add_argument("--debug", action="store_true")

    # Parse arguments
    args = parser.parse_args()
    return args

def Retrieve_Virtual_Servers():
    virtual_servers = bigiq_http_get(
        uri='mgmt/cm/adc-core/working-config/ltm/virtual',
        params=''
    )
    return virtual_servers.json()

def Retrieve_Pools():
    pools = bigiq_http_get(
        uri='mgmt/cm/adc-core/working-config/ltm/pool',
        params=''
    )
    return pools.json()

def Retrieve_Pool_Members():
    pool_members = bigiq_http_post(
        uri='mgmt/shared/pipeline/manager/All-Pool-Members-Pipeline',
        payload='{"multiStageQueryRequest":{"repeatLastStageUntilTerminated":false,"queryParamsList":[{"description":"retrieval","filterProcessorReference":{"link":"https://localhost/mgmt/shared/index/es-config?%24filter=kind%20eq%20\'cm%3Aadc-core%3Aworking-config%3Altm%3Apool%3Amembers%3Aadcpoolmemberstate\'&%24orderby=name%20asc&%24top=150&%24skip=0"},"pipelineAction":"DATA_RETRIEVAL","runStageInternally":false},{"description":"expand","managedPipelineWorkerName":"expand-pipe","jsonContext":{"references":[{"expand":"parentInfo/deviceReference","select":["hostname","properties"]}]}},{"description":"stats","managedPipelineWorkerName":"resource-stats-pipe","pipelineAction":"DATA_PROCESSING","runStageInternally":false}]},"getOnPostAndTerminate":true,"isPerformanceBoostingEnabled":false}'
    )
    return pool_members

def main():
    # Define BIG-IQ environment variables
    global username
    global password
    global host
    # Read command line arguments
    args = parse_arguments()
    if args.debug == True:
        logging.info('Setting logging level to debug')
        logger.setLevel(logging.DEBUG)
    username = args.username
    password = args.password
    host = args.hostname
    pools = Retrieve_Pools()
    pool_members = Retrieve_Pool_Members()
    virtual_servers = pd.DataFrame(Retrieve_Virtual_Servers()['items'])
    if args.csv:
      virtual_servers.to_csv(args.csv, index=False)


if __name__ == '__main__':
    main()
