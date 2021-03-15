# Empty Dictionary that gets populated with data
empty = {}

# Abuse URL and Data Gathered
abuseUrl = 'https://api.abuseipdb.com/api/v2/check'

# Cape sandbox URL and Data Gathered
capeUrl = 'https://www.capesandbox.com/api/tasks/extendedsearch/'

# Hybrid Analysis URLS and Data Gathered
hybridUrlSearch = 'https://www.hybrid-analysis.com/api/v2/search/hash'
hybridUrlScan = 'https://www.hybrid-analysis.com/api/v2/quick-scan/url'
hybridUrlReport = 'https://www.hybrid-analysis.com/api/v2/report/%s/summary'

# Malshare URL and Data Gathered
malshareUrl = 'https://malshare.com/api.php?api_key=%s&action=details&hash=%s'

# Urlhaus URL and Data Gathered
urlhausUrl = 'https://urlhaus-api.abuse.ch/v1/'

# VirusTotal URLS and Data Gathered
vtHashUrl = 'https://www.virustotal.com/vtapi/v2/file/report'
vtIpUrl = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
vtUrlUrl = 'https://www.virustotal.com/vtapi/v2/url/report'
vtUrlScan = 'https://www.virustotal.com/vtapi/v2/url/scan'

engine_list = ['AbuseLink', 'AbuseScore', 'VTLink', 'VTScore', 'UrlScanLink', 'UrlScanScore']
