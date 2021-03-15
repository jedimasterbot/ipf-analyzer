import copy
import requests
from common.config import empty, abuseUrl
from common.apiKeys import abuseKey


def AbuseReporter(values, analysis=True):
    if not abuseKey:
        return [{'Abuse IP': {'Abuse API Key': 'Abuse IP API Key Not Found'}}]
    else:
        abuse_val = []
        for usrInput in values:
            abuseFramework = copy.deepcopy(empty)
            # Defining the api-endpoint
            querystring = {'ipAddress': usrInput}
            headers = {'Accept': 'application/json', 'Key': abuseKey}
            response = requests.request(method='GET', url=abuseUrl, headers=headers, params=querystring)
            if response.status_code == 200:
                data = response.json()
                report = data.get('data')
                if analysis:
                    abuseFramework.update({'Action On': usrInput})
                    abuseFramework.update({'Link': 'https://www.abuseipdb.com/check/' + str(usrInput)})
                    abuseFramework.update({'Abuse Confidence Score': report.get('abuseConfidenceScore')})
                    abuseFramework.update({'Country Code': report.get('countryCode')})
                    abuseFramework.update({'Domain': report.get('domain')})
                    abuseFramework.update({'IsWhitelisted': report.get('isWhitelisted')})
                    abuseFramework.update({'Total Reports': report.get('totalReports')})
                    abuseFramework.update({'Last Reported At': report.get('lastReportedAt')})

                    abuse_val.append({'Abuse IP': abuseFramework})

                else:
                    abuseFramework.update({'AbuseLink': 'https://www.abuseipdb.com/check/' + str(usrInput)})
                    abuseFramework.update({'AbuseScore': report.get('abuseConfidenceScore')})

                    abuse_val.append({str(usrInput): abuseFramework})

        return abuse_val
