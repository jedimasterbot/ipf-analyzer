import copy
import time

import requests
from common.apiKeys import hybridKey
from common.config import empty, hybridUrlSearch, hybridUrlScan


# Falcon Sandbox
def HybridReporter(values):
    if not hybridKey:
        return [{'Hybrid Analysis': {'Hybrid API Key': 'Hybrid Analysis API Key Not Found'}}]
    else:
        hybrid_val = []
        for usrInput in values:
            hybridFramework = copy.deepcopy(empty)
            headers = {'User-Agent': 'VxStream', 'api-key': hybridKey}
            data = {'hash': usrInput}
            response = requests.post(hybridUrlSearch, headers=headers, data=data)
            if response.json():
                dataReport = response.json()[0]
                if len(dataReport) > 0:
                    hybridFramework.update({'Action On': usrInput})
                    hybridFramework.update({'Analysis Start Time': dataReport.get('analysis_start_time')})
                    hybridFramework.update({'Threat Level': dataReport.get('threat_level')})
                    hybridFramework.update({'Threat Score': dataReport.get('threat_score')})
                    hybridFramework.update({'Total Network Connections': dataReport.get('total_network_connections')})
                    hybridFramework.update({'Total Processes': dataReport.get('total_processes')})
                    hybridFramework.update({'Total Signatures': dataReport.get('total_signatures')})
                    hybridFramework.update({'Type': dataReport.get('type')})
                    hybridFramework.update({'Type Short': dataReport.get('type_short')})
                    hybridFramework.update({'Url Analysis': dataReport.get('url_analysis')})
                    hybridFramework.update({'Verdict': dataReport.get('verdict')})
                    hybridFramework.update({'VX Family': dataReport.get('vx_family')})

                    hybrid_val.append({'Hybrid Analysis': hybridFramework})

        return hybrid_val


def HybridPcapReporter(values):
    if not hybridKey:
        return [{'Hybrid Analysis': {'Hybrid API Key': 'Hybrid Analysis API Key Not Found'}}]
    else:
        hybrid_val = []
        for usrInput in values:
            hybridFramework = copy.deepcopy(empty)
            headers = {'User-Agent': 'Falcon Sandbox', 'api-key': hybridKey}
            data = {'scan_type': 'lookup_virustotal', 'url': usrInput}
            try:
                response = requests.post(hybridUrlScan, headers=headers, data=data, timeout=5)
                if response.status_code == 200 and response.json():
                    url_json = response.json()
                    status = url_json.get('finished')

                    while not status:
                        time.sleep(1)
                        response = requests.post(hybridUrlScan, headers=headers, data=data)
                        url_json = response.json()
                        status = url_json.get('finished')
                    scanner_info = url_json.get('scanners')
                    ipData = scanner_info[0]
                    hybridFramework.update(
                        {'VTLink': 'https://www.virustotal.com/gui/ip-address/{}/detection'.format(usrInput)})
                    hybridFramework.update({'VTScore': str(ipData.get('positives')) + '/' + str(ipData.get('total'))})

                    hybrid_val.append({str(usrInput): hybridFramework})
                else:
                    pass
            except requests.exceptions.ReadTimeout:
                pass

        return hybrid_val
