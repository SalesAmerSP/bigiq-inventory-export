#!/usr/bin/env python3

import getpass
import os
import requests
import time
import urllib3
import logging
import argparse
import sys
import pandas as pd

LOG_FILE = 'bigiq-inventory-export.log'
old_umask = os.umask(0o177)
logging.basicConfig(level=logging.INFO, filename=LOG_FILE)
os.umask(old_umask)
logger = logging.getLogger(__name__)


class BigIQClient:
    def __init__(self, host, username, password, verify=True, provider='local'):
        self.host = host
        self.username = username
        self.password = password
        self.verify = verify
        self.provider = provider
        self.auth_token = None
        self.auth_token_expiry = 0

    def _authenticate(self):
        # Check if current epoch time is less than token expiry;
        # skip token generation if not
        if self.auth_token is not None and time.time() < self.auth_token_expiry:
            remaining_seconds = self.auth_token_expiry - time.time()
            logger.debug(f'Existing authentication token is still valid. Expires in {remaining_seconds} seconds.')
            return
        # request a new token
        url = f'https://{self.host}/mgmt/shared/authn/login'
        payload = {'username': self.username, 'password': self.password, 'provider': self.provider}
        headers = {'Content-type': 'application/json'}
        logger.debug(f'Token API call: {url}, {self.username}')
        try:
            response = requests.post(
                url,
                json=payload,
                headers=headers,
                verify=self.verify
            )
            response.raise_for_status()  # Raise an exception for bad status codes
        except requests.exceptions.RequestException as e:
            logger.error(f'Error making API call: {e}')
            sys.exit(1)
        self.auth_token = response.json()['token']['token']
        self.auth_token_expiry = response.json()['token']['exp']
        logger.debug(f'Auth token retrieved, expires at {self.auth_token_expiry} epoch time')

    def _request(self, method, uri, params=None, payload=None):
        self._authenticate()
        url = f'https://{self.host}/{uri}'
        headers = {
            'Content-type': 'application/json',
            'X-F5-Auth-Token': self.auth_token
        }
        logger.debug(f'BIG-IQ HTTP {method} URL:{url}')
        response = None
        try:
            response = requests.request(
                method,
                url,
                headers=headers,
                params=params,
                json=payload,
                verify=self.verify
            )
            response.raise_for_status()  # Raise an exception for bad status codes
        except requests.exceptions.RequestException as e:
            endpoint_response = f' (Endpoint Response: {response.text})' if response is not None else ''
            logger.error(f'Error making API call: {e}{endpoint_response}')
            return None
        logger.debug(f'BIG-IQ HTTP {method} {url} returned status {response.status_code}')
        return response

    def retrieve_virtual_servers(self):
        virtual_servers = self._request(
            'GET',
            uri='mgmt/cm/adc-core/working-config/ltm/virtual',
        )
        if virtual_servers is None:
            logger.error('Failed to retrieve virtual servers')
            sys.exit(1)
        return virtual_servers.json()

    def retrieve_pools(self):
        pools = self._request(
            'GET',
            uri='mgmt/cm/adc-core/working-config/ltm/pool',
        )
        if pools is None:
            logger.error('Failed to retrieve pools')
            sys.exit(1)
        return pools.json()

    def retrieve_pool_members(self):
        pool_members = self._request(
            'POST',
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
        if pool_members is None:
            logger.error('Failed to retrieve pool members')
            sys.exit(1)
        return pool_members

    def revoke_token(self):
        if self.auth_token is None:
            return
        url = f'https://{self.host}/mgmt/shared/authz/tokens/{self.auth_token}'
        headers = {
            'Content-type': 'application/json',
            'X-F5-Auth-Token': self.auth_token
        }
        try:
            response = requests.delete(
                url,
                headers=headers,
                verify=self.verify
            )
            response.raise_for_status()
            logger.debug('Auth token revoked successfully')
        except requests.exceptions.RequestException as e:
            logger.error(f'Error revoking auth token: {e}')


def parse_arguments():
    # Create the parser
    parser = argparse.ArgumentParser(description="Process login credentials and hostname.")

    # Add arguments
    parser.add_argument("--username", type=str, required=True, help="BIG-IQ user")
    parser.add_argument("--hostname", type=str, required=True, help="BIG-IQ host (IP/FQDN)")
    parser.add_argument("--csv", type=str, required=False, help="CSV to write output")
    parser.add_argument("--ca-cert", type=str, required=False, help="Path to CA bundle for TLS verification")
    parser.add_argument("--insecure", action="store_true", help="Disable TLS certificate verification")
    parser.add_argument("--provider", type=str, default="local", help="Authentication provider (default: local)")
    parser.add_argument("--debug", action="store_true")

    # Parse arguments
    args = parser.parse_args()
    return args

def main():
    # Read command line arguments
    args = parse_arguments()
    if args.debug:
        logging.info('Setting logging level to debug')
        logger.setLevel(logging.DEBUG)

    username = args.username
    password = os.environ.get('BIGIQ_PASSWORD') or getpass.getpass(prompt='BIG-IQ Password: ')
    host = args.hostname

    # Determine TLS verify setting
    if args.ca_cert:
        verify = args.ca_cert
    elif args.insecure:
        verify = False
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    else:
        verify = True

    client = BigIQClient(host, username, password, verify=verify, provider=args.provider)
    try:
        pools = client.retrieve_pools()
        pool_members = client.retrieve_pool_members()
        virtual_servers_df = pd.DataFrame(client.retrieve_virtual_servers()['items'])
        pools_df = pd.DataFrame(pools['items'])
        pool_members_df = pd.DataFrame(pool_members.json()['items'])
        if args.csv:
            base, ext = os.path.splitext(args.csv)
            virtual_servers_df.to_csv(args.csv, index=False)
            pools_df.to_csv(f'{base}_pools{ext}', index=False)
            pool_members_df.to_csv(f'{base}_pool_members{ext}', index=False)
        else:
            print('--- Virtual Servers ---')
            print(virtual_servers_df.to_string())
            print()
            print('--- Pools ---')
            print(pools_df.to_string())
            print()
            print('--- Pool Members ---')
            print(pool_members_df.to_string())
    finally:
        client.revoke_token()


if __name__ == '__main__':
    main()
