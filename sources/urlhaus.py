import copy
import requests
from common.config import urlhausUrl, empty

version = '0.0.2'


def UrlHausUrlReporter(values):
    urlhaus_val = []
    for usrInput in values:
        urlhausFramework = copy.deepcopy(empty)
        r = requests.post('{}url/'.format(urlhausUrl),
                          headers={'User-Agent': 'urlhaus-python-client-{}'.format(version)}, data={'url': usrInput})
        if r.json().get('query_status') == 'ok':
            dataReport = r.json()
            urlhausFramework.update({'Action On': usrInput})
            urlhausFramework.update({'File Size': (dataReport.get('payloads')[0]).get('response_size')})
            urlhausFramework.update({'File Type': dataReport.get('file_type')})
            urlhausFramework.update({'First Seen': dataReport.get('date_added')})
            urlhausFramework.update({'Signature': (dataReport.get('payloads')[0]).get('signature')})
            urlhausFramework.update({'Url Count': 'No Information'})
            urlhausFramework.update({'Url Status': dataReport.get('url_status')})
            urlhausFramework.update({'Link': dataReport.get('urlhaus_reference')})

            urlhaus_val.append({'URLHaus': urlhausFramework})

    return urlhaus_val


def UrlHausHashReporter(values, hash_type):
    urlhaus_val = []
    for usrInput in values:
        urlhausFramework = copy.deepcopy(empty)
        r = requests.post('{}payload/'.format(urlhausUrl),
                          headers={'User-Agent': 'urlhaus-python-client-{}'.format(version)},
                          data={hash_type: usrInput})
        if r.ok:
            dataReport = r.json()
            results = dataReport.get('query_status')
            if results == 'no_results':
                pass
            else:
                urlhausFramework.update({'Action On': usrInput})
                urlhausFramework.update({'File Size': dataReport.get('file_size')})
                urlhausFramework.update({'File Type': dataReport.get('file_type')})
                urlhausFramework.update({'First Seen': dataReport.get('firstseen')})
                urlhausFramework.update({'Signature': dataReport.get('signature')})
                urlhausFramework.update({'Url Count': dataReport.get('url_count')})
                urlhausFramework.update({'Url Status': (dataReport.get('urls')[0]).get('url_status')})
                urlhausFramework.update({'Link': (dataReport.get('urls')[0]).get('urlhaus_reference')})

                urlhaus_val.append({'URLHaus': urlhausFramework})

    return urlhaus_val
