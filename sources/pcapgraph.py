import json
from collections import Counter
from scapy.layers.inet import IP
from datetime import datetime
import pandas as pd
import plotly
import plotly.graph_objs as go
from scapy.layers import http


def CountTable(all_ip, public_ip):
    tableIp, tablePubIp = {}, {}

    cnt = Counter()
    for ip in all_ip:
        cnt[ip] += 1

    for key, value in cnt.most_common():
        if key in public_ip:
            tablePubIp[key] = value
            tableIp[key] = value
        else:
            tableIp[key] = value

    return tableIp, tablePubIp


def BytesOverTime(packets):
    pktBytes = []
    pktTimes = []
    for pkt in packets:
        if IP in pkt:
            try:
                pktBytes.append(pkt[IP].len)
                pktTime = datetime.fromtimestamp(pkt.time)
                pktTimes.append(pktTime.strftime('%Y-%m-%d %H:%M:%S.%f'))
            except:
                pass

    dataByte = pd.Series(pktBytes).astype(int)
    times = pd.to_datetime(pd.Series(pktTimes).astype(str), errors='coerce')
    df = pd.DataFrame({'Bytes': dataByte, 'Time': times})
    df = df.set_index('Time')
    df2 = df.resample('2S').sum()
    trace = [go.Scatter(x=df2.index, y=df2['Bytes'])]
    graphJSON = json.dumps(trace, cls=plotly.utils.PlotlyJSONEncoder)

    return graphJSON


def SniffUrls(packets):
    urls = []
    for packet in packets:
        if packet.haslayer(http.HTTPRequest):
            http_layer = packet.getlayer(http.HTTPRequest)
            ip_layer = packet.getlayer(IP)
            src, method = ip_layer.fields.get('src'), http_layer.fields.get('Method')
            host, path = (http_layer.fields.get('Host')), (http_layer.fields.get('Path'))
            method = method.decode('utf-8')
            url = (host.decode('utf-8') + path.decode('utf-8'))
            urls.append([src, method, f'http://{url}'])

    return {'urls': urls}
