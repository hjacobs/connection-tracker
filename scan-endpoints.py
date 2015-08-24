#!/usr/bin/env python3
import requests
import sys
import zign.api

requests.packages.urllib3.disable_warnings()

url = sys.argv[1]

token = zign.api.get_existing_token('test')
access_token = token['access_token']

r = requests.get(url + '/endpoints', headers={'Authorization': 'Bearer {}'.format(access_token)})
data = r.json()

for account, public_endpoints in sorted(data.items()):
    print(account)
    for endpoint, port in public_endpoints:
        if port == 443:
            scheme = 'https'
        else:
            scheme = 'http'
        url = '{}://{}:{}/'.format(scheme, endpoint.split('/')[-1], port)
        try:
            r = requests.get(url, timeout=5, verify=False)
            print(endpoint, port, r.status_code)
        except Exception as e:
            print(endpoint, port, str(e))
