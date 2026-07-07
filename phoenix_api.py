import base64
import pandas as pd
import requests
from requests.auth import HTTPBasicAuth
from datetime import datetime
import json
import sys

requests.packages.urllib3.disable_warnings()


#
# **** Define Class ****
#

# New Nucleus Class
class Phoenix_API:

    # Constructor
    def __init__(self, debug=False, api_creds_file=None):

        print ('-- New Phoenix API Instance --')
        print (f' - {api_creds_file}')

        self.findings_df = pd.DataFrame()
        self.scans_df = pd.DataFrame()

        self.ssl_verify = False     # Needed behind netskope

        # Get client_id and client_secret
        if api_creds_file:
            f = open(api_creds_file, "r")
            creds = f.readlines()
        else:
            sys.exit ("No API Creds supplied.")

        self.client_id = base64.b64decode(creds[0]).decode('utf-8')
        self.client_secret = base64.b64decode(creds[1]).decode('utf-8')
        self.client_secret_expiry = creds[2]           # for reference

        self.api_url = 'https://api.adm.securityphoenix.cloud'

        # Get initial API token
        self.headers = {
            "authorization": "Bearer some_token_goes_here", 
            "accept": "application/json", 
            "cache-control": "no-cache"
        }
        self.fetch_api_token()

        self.debug = debug


    # API Functions
    # *** Should wrap in try...!


    def check_key_expiring (self):

        expiring = False
        buffer = 1000
        now = int(datetime.timestamp(datetime.now()))
        if now > (self.api_token_expiry + buffer):
            if self.debug:
                print ('Expiring Token!')
            expiring = True
        return expiring 
    

    def fetch_api_token (self):

        token_path = '/v1/auth/access_token'
        self.api_token = ""
        self.api_token_expiry = ""

        auth_response = requests.get(url=f'{self.api_url}{token_path}', auth = HTTPBasicAuth(self.client_id, self.client_secret), verify=self.ssl_verify)

        if auth_response.status_code == 200:
            self.api_token = f'Bearer {json.loads(auth_response.content)['token']}'
            self.api_token_expiry = json.loads(auth_response.content)['expiry']
            print(" - Success fetching token")
            print(f" - Expires at {datetime.fromtimestamp(self.api_token_expiry).strftime('%Y-%m-%d %H:%M:%S')}")
            # Update header
            self.headers["authorization"] = self.api_token

        else:
            print(' - Failed fetching token')
            sys.exit('')


    def fetch_api_get (self, url):

        if self.debug:
            print (f"Fetching GET {url}")

        result = requests.get (url=url, headers=self.headers, verify=self.ssl_verify)
        
        if self.debug:
            print (f"Status Code: {result.status_code}")
        
        return result
    

    def fetch_api_post (self, url, body):
        
        if self.debug:
            print (f"Fetching POST {url}")
        
        result = requests.post (url=url, headers=self.headers, verify=self.ssl_verify, json=body)
        
        if self.debug:
            print (f"Status Code: {result.status_code}")
        
        return result


    def fetch (self, endpoint, body=None):

        if self.check_key_expiring():
            self.fetch_token()

        fetch_url = self.api_url + endpoint
        if body:
            result = self.fetch_api_post (url=fetch_url, body=body)
        else:
            result = self.fetch_api_get (url=fetch_url)
        return result


    # Modified for Phoenix
    def loop_fetch (self, endpoint, body=None, start=1, page_size=100, num_pages=1):

        data = []

        # Mimic a do while loop
        for page in range(start, num_pages+1):
            batch = self.fetch(endpoint=f"{endpoint}?pageNumber={start}&pageSize={page_size}",body=body)
            if batch.status_code == 200:
                if page == start:
                   # Print out the metadata
                    for k, v in batch.json().items():
                        if k != "content":
                            print(f"{k:25} {v}")
 
                if batch.json()['content']:
                    data.extend(batch.json()['content'])
                    start += page

        return data

    #
    # Uploads
    #

    def import_pentest_data (self, body):
    
        # Import Endpoint
        import_endpoint = '/v1/import/assets'

        result = self.fetch(endpoint=import_endpoint, body=body)

        if result.status_code == 400:
            print (f'error: {result.text}')
        if result.status_code == 200:
            print ('[Response] OK')

    #
    # Searches
    #

    def check_asset_exists (self, asset_type, asset):
    
        # Endpoint
        endpoint = '/v1/assets'

        asset_type = asset_type.upper()

        if asset_type == 'CLOUD':

            if asset.startswith('/subscriptions'):
                _tokens = asset.split('/')
                accountID = _tokens[2]
            else:
                accountID = 'unknown'

            json_body = {
                    "requests": [{
                        "types": ['CLOUD'],
                        "filters": [{
                            "providerAccountId": [accountID],
                        }]
                    }]
                }
            

        if asset_type == 'INFRA':

            json_body = {
                "requests": [{
                    "types": [asset_type],
                    "filters": [{
                        "hostnames": [asset],
                    }]
                }]
            }

        if asset_type == 'WEBSITE_API':

            json_body = {
                "requests": [{
                    "types": [asset_type],
                    "filters": [{
                        "fqdn": [asset],
                    }]
                }]
            }    

        result = self.fetch (endpoint=endpoint, body=json_body)

        if result.status_code == 200:

            if result.json()['content']:

                if result.json()['totalPages'] > 1:

                    data = self.loop_fetch(endpoint=endpoint, body=json_body, start=1, page_size=result.json()['pageSize'], num_pages=result.json()['totalPages'])
                else:
                    data = result.json()['content']

                if asset_type == 'CLOUD':
                    # Check further
                    for a in data:
                        if a['name'] == asset:
                            return True
                    return False
                else:
                    # Other types
                    return True
            else:
                # Blank response
                return False
        else:
            # Something broke in the API request
            print ('- Warning: API Request Failed')
            return False
        
        

    def get_asset_type (self, asset):
    
        # Endpoint
        endpoint = '/v1/assets'

        # Some cloud ones are easy to spot
        if asset.startswith('/subscriptions'):
            return 'CLOUD'

        #for asset_type in  ['CLOUD', 'INFRA', 'CONTAINER', 'WEBSITE_API', 'REPOSITORY', 'SOURCE_CODE', 'BUILD']:
        for asset_type in  ['INFRA', 'WEBSITE_API']:

            if asset_type == 'INFRA':

                json_body = {
                    "requests": [{
                        "types": [asset_type],
                        "filters": [{
                            "hostnames": [asset],
                        }]
                    }]
                }

            if asset_type == 'WEBSITE_API':

                json_body = {
                    "requests": [{
                        "types": [asset_type],
                        "filters": [{
                            "fqdn": [asset],
                        }]
                    }]
                }

  
            result = self.fetch (endpoint=endpoint, body=json_body)

            if result.status_code == 200:
                if result.json()['content']:
                    return asset_type

        # We didn't find an asset type    
        return None



    

    