import copy
import iocextract
from valhallaAPI.valhalla import ValhallaAPI
from common.apiKeys import valhallaKey
from common.config import empty


def ValhallaReporter(values):
    vallaha_val = []
    for usrInput in values:
        valFramework = copy.deepcopy(empty)
        chk_256 = list(iocextract.extract_sha256_hashes(usrInput))
        if chk_256:
            usrInput = chk_256[0]
            v = ValhallaAPI(api_key=valhallaKey)
            response = v.get_hash_info(hash=usrInput)
            if response.get('status') == 'empty':
                pass
            else:
                dataReport = response.get('results')[0]
                if len(dataReport) > 0:
                    valFramework.update({'Action On': usrInput})
                    valFramework.update({'Positives': dataReport.get('positives')})
                    valFramework.update({'Rule Name': dataReport.get('rulename')})
                    valFramework.update({'Tags': dataReport.get('tags')})
                    valFramework.update({'Timestamp': dataReport.get('timestamp')})
                    valFramework.update({'Total': dataReport.get('total')})
                    valFramework.update(
                        {'Score': str(dataReport.get('positives')) + '/' + str(dataReport.get('total'))})

                    vallaha_val.append({'Vallaha': valFramework})

    return vallaha_val

