import copy
import requests
from common.apiKeys import malshareKey
from common.config import empty, malshareUrl


def malshareReporter(values):
    if not malshareKey:
        return [{'Malshare': {'Malshare API Key': 'Malshare API Key Not Found'}}]
    else:
        malShare_val = []
        for usrInput in values:
            malshareFramework = copy.deepcopy(empty)
            url = malshareUrl % (malshareKey, usrInput)
            response = requests.post(url)
            dataReport = response.json()
            stat = 404
            err = dataReport.get('ERROR')
            if err:
                if err.get('CODE') == stat:
                    pass
            else:
                md5 = dataReport.get('MD5')
                permalink = 'https://malshare.com/sample.php?action=detail&hash=%s' % md5
                malshareFramework.update({'Action On': usrInput})
                malshareFramework.update({'Link': permalink})
                malshareFramework.update({'Positives': 'True'})
                malshareFramework.update({'MD5': dataReport.get('MD5')})
                malshareFramework.update({'SHA1': dataReport.get('SHA1')})
                malshareFramework.update({'SHA256': dataReport.get('SHA256')})
                malshareFramework.update({'File Type': dataReport.get('F_TYPE')})

                malShare_val.append({'Malshare': malshareFramework})

        return malShare_val
