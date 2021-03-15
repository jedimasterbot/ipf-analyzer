import copy
import requests
import time
from common.apiKeys import vtKey
from common.config import empty, vtHashUrl, vtIpUrl, vtUrlUrl, vtUrlScan


# Gets hash report from virustotal
def VTHashReporter(values):
    if not vtKey:
        return [{'Virus Total': {'VT API Key': 'VirusTotal API Key Not Found'}}]
    else:
        vt_val = []
        for usrInput in values:
            vtFramework = copy.deepcopy(empty)
            params = {'apikey': vtKey, 'resource': usrInput}
            response = requests.get(vtHashUrl, params=params)
            resp_code = 0
            dataReport = response.json()
            if dataReport.get('response_code') is resp_code:
                # Gets the report for the scanned URL
                pass
            else:
                vtFramework.update({'Action On': usrInput})
                vtFramework.update({'Link': dataReport.get('permalink')})
                vtFramework.update({'Positives': dataReport.get('positives')})
                vtFramework.update({'Resource': dataReport.get('resource')})
                vtFramework.update({'Scan Date': dataReport.get('scan_date')})
                vtFramework.update({'Total': dataReport.get('total')})
                vtFramework.update({'Score': str(dataReport.get('positives')) + '/' + str(dataReport.get('total'))})

                vt_val.append({'Virus Total': vtFramework})

        return vt_val


# Gets the IP report from virustotal
def VTIpReporter(values, analysis=True):
    if not vtKey:
        return [{'Virus Total': {'VT API Key': 'VirusTotal API Key Not Found'}}]
    else:
        vt_val = []
        for usrInput in values:
            vtFramework = copy.deepcopy(empty)
            params = {'apikey': vtKey, 'ip': usrInput}
            response = requests.get(vtIpUrl, params=params)
            ipData = response.json()
            if analysis:
                vtFramework.update({'Action On': usrInput})
                vtFramework.update(
                    {'Link': 'https://www.virustotal.com/gui/ip-address/' + str(usrInput) + '/detection'})
                vtFramework.update({'Positives': (int(ipData['detected_urls'][0].get('positives')) - 1)})
                vtFramework.update({'Resource': ipData['detected_urls'][0].get('url')})
                vtFramework.update({'Scan Date': ipData['detected_urls'][0].get('scan_date')})
                vtFramework.update({'Total': ipData['detected_urls'][0].get('total')})
                vtFramework.update({'Score': str(int(str(ipData['detected_urls'][0].get('positives'))) - 1) + '/' + str(
                    ipData['detected_urls'][0].get('total'))})

                vt_val.append({'Virus Total': vtFramework})

            else:
                vtFramework.update(
                    {'Link': 'https://www.virustotal.com/gui/ip-address/' + str(usrInput) + '/detection'})
                vtFramework.update({'Score': str(int(str(ipData['detected_urls'][0].get('positives'))) - 1) + '/' + str(
                    ipData['detected_urls'][0].get('total'))})

                vt_val.append({str(usrInput): vtFramework})

        return vt_val


# Gets the URL/Domain report from virustotal
def VTUrlReporter(values):
    if not vtKey:
        return [{'Virus Total': {'VT API Key': 'VirusTotal API Key Not Found'}}]
    else:
        vt_val = []
        for usrInput in values:
            vtFramework = copy.deepcopy(empty)

            # Gets the URL report from virustotal
            def urlReport(usrInput):
                params = {'apikey': vtKey, 'resource': usrInput, 'allinfo': True}
                response = requests.get(vtUrlUrl, params=params)
                return response.json()

            # Requests virustotal to scan the URL
            def urlScan(usrInput):
                params = {'apikey': vtKey, 'url': usrInput}
                response = requests.post(vtUrlScan, data=params)

            # First checks if already a submission is on virustotal
            dataReport = urlReport(usrInput)
            resp_code = 0
            if dataReport.get('response_code') is resp_code:
                # Requests virustotal to scan the URL
                urlScan(usrInput)
                # Waits for virustotal to complete the scan
                time.sleep(15)
                # Gets the report for the scanned URL
                dataReportRescan = urlReport(usrInput)
                vtFramework.update({'Action On': usrInput})
                vtFramework.update({'Link': dataReportRescan.get('permalink')})
                vtFramework.update({'Positives': dataReportRescan.get('positives')})
                vtFramework.update({'Resource': dataReportRescan.get('resource')})
                vtFramework.update({'Scan Date': dataReportRescan.get('scan_date')})
                vtFramework.update({'Total': dataReportRescan.get('total')})
                vtFramework.update(
                    {'Score': str(dataReportRescan.get('positives')) + '/' + str(dataReportRescan.get('total'))})

                vt_val.append({'Virus Total': vtFramework})

            else:
                vtFramework.update({'Action On': usrInput})
                vtFramework.update({'Link': dataReport.get('permalink')})
                vtFramework.update({'Positives': dataReport.get('positives')})
                vtFramework.update({'Resource': dataReport.get('resource')})
                vtFramework.update({'Scan Date': dataReport.get('scan_date')})
                vtFramework.update({'Total': dataReport.get('total')})
                vtFramework.update({'Score': str(dataReport.get('positives')) + '/' + str(dataReport.get('total'))})

                vt_val.append({'Virus Total': vtFramework})

        return vt_val
