# Get the abuse API key from the site
abuseKey = ''

# Get the hybrid API key from the site
hybridKey = ''

# Get the malshare API key from the site
malshareKey = ''

# Get the urlscan key from the site
urlScanKey = ''

# Get the valhalla key from the site
valhallaKey = ''

# Get the Virustotal API key from the site
vtKey = ''

# Get the Cape Sandbox Token using the sample codes
"""
import requests
data = {'username': '<USER>','password': '<PASSWD>'}
response = requests.post('https://capesandbox.com/apiv2/api-token-auth/', data=data)
print(response.json()) 
"""
# OR
"""
curl -d "username=<USER>&password=<PASSWD>" https://capesandbox.com/apiv2/api-token-auth/
"""
capeToken = ''
