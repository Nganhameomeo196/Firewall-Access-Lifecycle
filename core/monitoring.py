"""Import observed network flows; do not mistake observed flow for firewall ALLOW.

CSV schema: timestamp,src_ip,dst_ip,protocol,dst_port,observed_action
Zeek JSON-lines: ts,id.orig_h,id.resp_h,id.resp_p,proto. Zeek has no
firewall action: observed_action remains UNKNOWN.
"""
from __future__ import annotations
from datetime import datetime,timezone
from hashlib import sha256
import csv,io,json
from core.database import transaction,event,query,utc_now
from core.security import ipv4,role_check
from core.policy import Packet,trace_decision,Rule
from core.workflow import iso_utc,AccessService,WorkflowError


def normalized_time(value):
    if value is None or str(value).strip()=='':return utc_now()
    if isinstance(value,(float,int)) or (isinstance(value,str) and value.replace('.','',1).isdigit()):
        return datetime.fromtimestamp(float(value),timezone.utc).isoformat(timespec='seconds')
    return iso_utc(str(value))


def normalized(row,fmt):
    if fmt=='zeek':
        src=row.get('id.orig_h');dst=row.get('id.resp_h')
        proto=str(row.get('proto','')).upper();port=row.get('id.resp_p',0)
        action='UNKNOWN';timestamp=row.get('ts')
    else:
        src=row.get('src_ip');dst=row.get('dst_ip')
        proto=str(row.get('protocol','')).upper();port=row.get('dst_port')
        action=str(row.get('observed_action','UNKNOWN') or 'UNKNOWN').upper()
        timestamp=row.get('timestamp')
    if proto not in ('TCP','UDP','ICMP'):raise ValueError('protocol phải TCP/UDP/ICMP')
    if action not in ('ALLOW','DENY','UNKNOWN'):raise ValueError('observed_action phải ALLOW/DENY/UNKNOWN')
    p=0 if proto=='ICMP' else int(port)
    if not 0<=p<=65535:raise ValueError('dst_port ngoài 0–65535')
    return (normalized_time(timestamp),ipv4(str(src)),ipv4(str(dst)),proto,p,action,fmt)


def parse_blob(blob:str,fmt:str,max_rows=5000):
    if len(blob.encode('utf-8')) > 3_000_000:
        raise ValueError('File log vượt giới hạn 3 MB của phiên bản lab')
    if fmt=='csv':
        rows=list(csv.DictReader(io.StringIO(blob)))
    elif fmt=='zeek':
        rows=[json.loads(line) for line in blob.splitlines() if line.strip() and not line.lstrip().startswith('#')]
    else:raise ValueError('Chỉ hỗ trợ CSV hoặc Zeek JSON-lines')
    if len(rows)>max_rows:raise ValueError(f'Chỉ cho phép tối đa {max_rows} bản ghi mỗi lần')
    cleaned=[]
    for idx,r in enumerate(rows,1):
        try:cleaned.append(normalized(r,fmt))
        except Exception as exc:raise ValueError(f'Lỗi dòng {idx}: {exc}') from exc
    return cleaned


def import_traffic(service:AccessService,actor_id,blob,fmt):
    role_check(service.actor(actor_id),'ADMIN','APPROVER')
    parsed=parse_blob(blob,fmt)
    added=0
    with transaction(service.db) as c:
        for row in parsed:
            key=sha256(json.dumps(row).encode()).hexdigest()
            x=c.execute('''INSERT OR IGNORE INTO traffic(dedup_key,occurred_at,src_ip,dst_ip,protocol,dst_port,observed_action,source_type,imported_at)
                           VALUES (?,?,?,?,?,?,?,?,?)''',(key,*row,utc_now()))
            added+=x.rowcount
        event(c,actor_id,'TRAFFIC_IMPORTED','traffic',None,{'parsed':len(parsed),'added':added,'format':fmt})
    return {'parsed':len(parsed),'added':added,'duplicates':len(parsed)-added}


def analyze_traffic(service:AccessService,firewall_rules:list[Rule],max_rows=5000):
    items=query(service.db,'SELECT * FROM traffic ORDER BY id DESC LIMIT ?', (max_rows,))
    approved=__import__('core.policy',fromlist=['rules_from_grants']).rules_from_grants(service.active_access())
    alerts=[];ok=0
    for row in items:
        packet=Packet(row['src_ip'],row['dst_ip'],row['protocol'],None if row['protocol']=='ICMP' else row['dst_port'])
        predicted=trace_decision(firewall_rules,packet)
        authorized=trace_decision(approved,packet)['action']=='ALLOW'
        observed=row['observed_action']
        if observed=='ALLOW' and not authorized:
            code='LOGGED_ALLOW_OUTSIDE_ENTITLEMENT';risk=90
        elif not authorized:
            code='OBSERVED_OUTSIDE_ENTITLEMENT';risk=55
        elif observed in ('ALLOW','DENY') and observed!=predicted['action']:
            code='DECISION_DISAGREEMENT';risk=40
        else:
            code='NO_ALERT';risk=0;ok+=1
        if code!='NO_ALERT':
            alerts.append({'traffic_id':row['id'],'category':code,'risk_score':risk,
               'source':row['src_ip'],'destination':row['dst_ip'],'protocol':row['protocol'],'port':row['dst_port'],
               'firewall_predicted':predicted['action'],'firewall_observed':observed,
               'approved_by_access_workflow':authorized,
               'explanation':'Ghi nhận tại điểm quan sát; UNKNOWN không chứng minh gói đã được firewall cho phép.'})
    alerts.sort(key=lambda x:(-x['risk_score'],-x['traffic_id']))
    return {'total':len(items),'without_alert':ok,'alerts':alerts,
       'note':'So sánh log với quyền hiện tại (không tái hiện quyền trong quá khứ). Zeek conn logs không phải log quyết định firewall. Điểm rủi ro là heuristic minh họa.'}
