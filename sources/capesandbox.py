import copy
import iocextract
import requests
from common.config import capeUrl, empty


def allReport(usrInput, argType):
    local_cape_val = []
    data = {'option': argType, 'argument': usrInput}
    response = requests.post(capeUrl, data=data)

    if response.status_code == 200:
        res = response.json()
        if not res.get('error') and res['data']:
            responseData = res.get('data')
            for i in range(0, len(responseData)):
                capeFramework = copy.deepcopy(empty)
                tId = responseData[i].get('info').get('id')
                package = responseData[i].get('info').get('package')
                detection = responseData[i].get('detections')
                malfamily_tag = responseData[i].get('malfamily_tag')
                malscore = responseData[i].get('malscore')
                suri_alert_cnt = responseData[i].get('suri_alert_cnt')
                suri_http_cnt = responseData[i].get('suri_http_cnt')
                suri_tls_cnt = responseData[i].get('suri_tls_cnt')
                virustotal_summary = responseData[i].get('virustotal_summary')
                task_url = 'https://www.capesandbox.com/api/files/view/id/%s/' % tId
                t_req = requests.get(task_url)
                dataReport = t_req.json()
                capeFramework.update({'Action On': usrInput})
                capeFramework.update({'Package': package})
                capeFramework.update({'Detection': detection})
                capeFramework.update({'Malware Family Tag': malfamily_tag})
                capeFramework.update({'Malware Score': malscore})
                capeFramework.update({'Suricata Alert Connection': suri_alert_cnt})
                capeFramework.update({'Suricata HTTP Connection': suri_http_cnt})
                capeFramework.update({'Suricata TLS Connection': suri_tls_cnt})
                capeFramework.update({'VirusTotal Summary': virustotal_summary})
                capeFramework.update({'Link': f'https://capesandbox.com/analysis/{str(tId)}/'})
                if not dataReport.get('error'):
                    capeFramework.update({'Parent': ((dataReport.get('data')).get('parent'))})
                    capeFramework.update({'Source Url': ((dataReport.get('data')).get('source_url'))})
                    capeFramework.update({'MD5': ((dataReport.get('data')).get('md5'))})
                    capeFramework.update({'File Type': ((dataReport.get('data')).get('file_type'))})
                    capeFramework.update({'File Size': ((dataReport.get('data')).get('file_size'))})

                local_cape_val.append(capeFramework)

        return local_cape_val

    else:
        return local_cape_val


def CapeReporter(values):
    cape_val = []
    for usrInput in values:
        chk_ip = list(iocextract.extract_ipv4s(usrInput))
        chk_url = list(iocextract.extract_urls(usrInput))
        chk_md5 = list(iocextract.extract_md5_hashes(usrInput))
        chk_sha1 = list(iocextract.extract_sha1_hashes(usrInput))
        chk_256 = list(iocextract.extract_sha256_hashes(usrInput))
        if chk_url:
            usrInput = chk_url[0]
            argType = 'url'
            stream = allReport(usrInput, argType)
            for data in stream:
                cape_val.append({'Cape Sandbox': data})
        elif chk_ip:
            usrInput = chk_ip[0]
            argType = 'ip'
            stream = allReport(usrInput, argType)
            for data in stream:
                cape_val.append({'Cape Sandbox': data})
        elif chk_md5:
            usrInput = chk_md5[0]
            argType = 'md5'
            stream = allReport(usrInput, argType)
            for data in stream:
                cape_val.append({'Cape Sandbox': data})
        elif chk_sha1:
            usrInput = chk_sha1[0]
            argType = 'sha1'
            stream = allReport(usrInput, argType)
            for data in stream:
                cape_val.append({'Cape Sandbox': data})
        elif chk_256:
            usrInput = chk_256[0]
            argType = 'sha256'
            stream = allReport(usrInput, argType)
            for data in stream:
                cape_val.append({'Cape Sandbox': data})
        else:
            pass

    return cape_val
