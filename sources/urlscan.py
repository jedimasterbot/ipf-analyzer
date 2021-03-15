import copy
import requests
from common.config import empty


def UrlScanReporter(values, analysis=True):
    urlscan_val = []
    for usrInput in values:
        urlScanFramework = copy.deepcopy(empty)
        params = (('q', 'domain:%s' % usrInput),)
        response = requests.get('https://urlscan.io/api/v1/search/', params=params)
        r = response.json()
        if r.get('status'):
            pass
        elif len(r.get('results')) == 0:
            pass
        else:
            data = (r.get('results')[0])
            if analysis:
                urlScanFramework.update({'Action On': usrInput})
                urlScanFramework.update({'Link': data.get('result')})
                urlScanFramework.update({'Screenshot URL': data.get('screenshot')})
                urlScanFramework.update({'Indexed At': data.get('indexedAt')})
                urlScanFramework.update({'Task Submitted': data.get('task').get('method')})
                urlScanFramework.update({'Visibility': data.get('task').get('visibility')})

                urlscan_val.append({'URLScan': urlScanFramework})

            else:
                urlScanFramework.update({'UrlScanLink': data.get('result')})
                res = requests.get(data.get('result'))
                if res.status_code != 200:
                    urlScanFramework.update({'UrlScanScore': 'None'})
                    urlscan_val.append({str(usrInput): urlScanFramework})
                else:
                    scanData = res.json()
                    urlScanFramework.update({'UrlScanScore': str(scanData.get('verdicts').get('overall').get('score'))})
                    urlscan_val.append({str(usrInput): urlScanFramework})

    return urlscan_val


