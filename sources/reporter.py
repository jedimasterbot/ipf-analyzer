from common.apiKeys import *
from common.config import engine_list
from sources.fileanalysis import file_type_hashes, pe_check, PE
from sources.strings import file_strings
from ioc_finder import find_iocs
from ipaddress import ip_address

from scapy.all import *
from scapy.layers.inet import IP

from sources.abuseip import AbuseReporter
from sources.capesandbox import CapeReporter
from sources.hybrid import HybridReporter, HybridPcapReporter
from sources.malshare import malshareReporter
from sources.pcapgraph import CountTable, BytesOverTime, SniffUrls
from sources.urlhaus import UrlHausUrlReporter, UrlHausHashReporter
from sources.urlscan import UrlScanReporter
from sources.vallaha import ValhallaReporter
from sources.virustotal import VTIpReporter, VTUrlReporter, VTHashReporter


def mainReporter(ioc):
    engine_responses = []
    ioc_allowed = ['urls', 'domains', 'ipv4s', 'sha256s', 'sha1s', 'md5s']
    validate = find_iocs(ioc)
    analyze = {k: v for k, v in validate.items() if v and k in ioc_allowed}
    if analyze:
        for key, value in analyze.items():
            if key == ioc_allowed[0]:
                vtUrl = VTUrlReporter(value)
                urlHaus = UrlHausUrlReporter(value)
                capeUrl = CapeReporter(value)
                scanUrl = UrlScanReporter(value)
                engine_responses = vtUrl + urlHaus + capeUrl + scanUrl

            if key == ioc_allowed[1]:
                vtDom = VTUrlReporter(value)
                urlHausDom = UrlHausUrlReporter(value)
                capeDom = CapeReporter(value)
                scanDom = UrlScanReporter(value, True)
                engine_responses = engine_responses + vtDom + urlHausDom + capeDom + scanDom

            if key == ioc_allowed[2]:
                abuse = AbuseReporter(value)
                vtIp = VTIpReporter(value)
                capeIp = CapeReporter(value)
                scanIp = UrlScanReporter(value)

                engine_responses = engine_responses + abuse + vtIp + capeIp + scanIp

            if key == ioc_allowed[3]:
                malshare256 = malshareReporter(value)
                vt256 = VTHashReporter(value)
                urlHaus256 = UrlHausHashReporter(value, 'sha256_hash')
                valhalla256 = ValhallaReporter(value)
                hybrid256 = HybridReporter(value)
                cape256 = CapeReporter(value)
                engine_responses = engine_responses + malshare256 + vt256 + urlHaus256 + valhalla256 + hybrid256 + cape256

            if key == ioc_allowed[4]:
                malshare1 = malshareReporter(value)
                vt1 = VTHashReporter(value)
                hybrid1 = HybridReporter(value)
                cape1 = CapeReporter(value)
                engine_responses = engine_responses + malshare1 + vt1 + hybrid1 + cape1

            if key == ioc_allowed[5]:
                malshare5 = malshareReporter(value)
                vt5 = VTHashReporter(value)
                urlHaus5 = UrlHausHashReporter(value, 'md5_hash')
                hybrid5 = HybridReporter(value)
                cape5 = CapeReporter(value)
                engine_responses = engine_responses + malshare5 + vt5 + urlHaus5 + hybrid5 + cape5

    return engine_responses


def ReporterPcap(file, abuseCheck, virusCheck, urlscanCheck, countTableCheck, botCheck, urlCheck):
    all_ip, public_ip, engine_responses, final = [], [], [], []
    try:
        packets = rdpcap(file)
    except Exception as err:
        return {'error': err}

    for pkt in packets:
        if IP in pkt:
            try:
                all_ip.append(pkt[IP].src)
                all_ip.append(pkt[IP].dst)
            except:
                pass

    unique_ip = list(set(all_ip))

    for x in unique_ip:
        address = ip_address(x)
        if address.is_global:
            public_ip.append(x)

    abuse = AbuseReporter(public_ip, False) if abuseCheck else []
    vtIp = HybridPcapReporter(public_ip) if virusCheck else []
    scanIp = UrlScanReporter(public_ip, False) if urlscanCheck else []
    data = abuse + vtIp + scanIp

    if data:
        for ip in public_ip:
            check = [x for x in data if x.get(ip)]
            if len(check) == 1:
                dd = dict(check[0].get(ip))
            elif len(check) == 2:
                dd = dict(check[0].get(ip), **check[1].get(ip))
            elif len(check) > 2:
                dd = dict(check[0].get(ip), **check[1].get(ip), **check[2].get(ip))
            else:
                dd = {}

            final.append({str(ip): dd})

    if countTableCheck:
        tableIp, tablePubIp = CountTable(all_ip, public_ip)
    else:
        tableIp, tablePubIp = {}, {}

    graphJson = BytesOverTime(packets) if botCheck else {}

    urlJson = SniffUrls(packets) if urlCheck else {}

    return {'EngineData': final, 'totalIp': tableIp, 'totalPub': tablePubIp, 'graph': graphJson, 'urls': urlJson,
            'engines': engine_list}


def ReporterFile(file, stringCheck, peCheck, engineCheck):
    file_info = file_type_hashes(file)

    if stringCheck:
        ascii_strings, uni_strings = file_strings(file)
    else:
        ascii_strings, uni_strings = [], []

    if peCheck:
        pe_status = pe_check(file)
        if pe_status.get('errorState'):
            pe_detail = pe_status
        else:
            pe_detail = PE(file).pe_info()
    else:
        pe_detail = {}

    en = mainReporter(file_info.get('sha256')) if engineCheck else []

    return {'fileInfo': file_info, 'peInfo': pe_detail, 'asciiStrings': ascii_strings,
            'uniStrings': uni_strings, 'engine': en}

