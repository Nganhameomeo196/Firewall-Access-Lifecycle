"""Deterministic firewall policy generation and stateless IPv4 simulation.

An approved request is a *network* entitlement after authorization.
Each generated ALLOW rule is scoped to one registered IPv4 source, one
asset IPv4, protocol and destination port. No implicit ANY/ALLOW.
"""
from __future__ import annotations
from dataclasses import dataclass,asdict
from ipaddress import ip_network,ip_address,IPv4Address
from typing import Any
from core.security import ipv4

PROTOCOLS={'TCP','UDP','ICMP','ANY'}
ACTIONS={'ALLOW','DENY'}


def valid_scope(v):
    if str(v).upper()=='ANY':return '0.0.0.0/0'
    net=ip_network(str(v),strict=False)
    if net.version!=4:raise ValueError('IPv4 only')
    return str(net)


@dataclass(frozen=True)
class Rule:
    id: str
    source: str
    destination: str
    protocol: str
    port: int | str
    action: str
    priority: int
    provenance: tuple[int,...]=()
    reason: str=''

    def __post_init__(self):
        if not str(self.id).strip():raise ValueError('id là bắt buộc')
        object.__setattr__(self,'source',valid_scope(self.source))
        object.__setattr__(self,'destination',valid_scope(self.destination))
        protocol=str(self.protocol).upper()
        if protocol not in PROTOCOLS:raise ValueError('Protocol không hợp lệ')
        object.__setattr__(self,'protocol',protocol)
        action=str(self.action).upper()
        if action not in ACTIONS:raise ValueError('Action không hợp lệ')
        object.__setattr__(self,'action',action)
        try:priority=int(self.priority)
        except (ValueError,TypeError):raise ValueError('Priority phải là số nguyên')
        if not (-1_000_000 <= priority <= 1_000_000):raise ValueError('Priority nằm ngoài giới hạn')
        object.__setattr__(self,'priority',priority)
        if isinstance(self.port,str) and self.port.upper()=='ANY':
            object.__setattr__(self,'port','ANY')
        else:
            try:port=int(self.port)
            except (ValueError,TypeError):raise ValueError('Port phải là số hoặc ANY')
            if not 0<=port<=65535:raise ValueError('Port nằm ngoài 0–65535')
            object.__setattr__(self,'port',port)
        if protocol=='ICMP' and self.port!='ANY':raise ValueError('ICMP không có destination port; dùng ANY')
        object.__setattr__(self,'provenance',tuple(int(x) for x in self.provenance))

    @classmethod
    def from_dict(cls,d):
        return cls(id=d['id'],source=d['source'],destination=d['destination'],
          protocol=d['protocol'],port=d['port'],action=d['action'],priority=d['priority'],
          provenance=tuple(d.get('provenance',[])),reason=d.get('reason',''))

    def to_dict(self):
        v=asdict(self)
        v['provenance']=list(self.provenance)
        return v


@dataclass(frozen=True)
class Packet:
    source: str
    destination: str
    protocol: str
    port: int | None

    def __post_init__(self):
        object.__setattr__(self,'source',ipv4(self.source))
        object.__setattr__(self,'destination',ipv4(self.destination))
        protocol=str(self.protocol).upper()
        if protocol not in ('TCP','UDP','ICMP'):raise ValueError('Protocol request chỉ TCP/UDP/ICMP')
        object.__setattr__(self,'protocol',protocol)
        if protocol=='ICMP':
            if self.port is not None:raise ValueError('ICMP port phải bỏ trống')
        else:
            if self.port is None or not 0<=int(self.port)<=65535:raise ValueError('Port không hợp lệ')
            object.__setattr__(self,'port',int(self.port))

    def to_dict(self):return asdict(self)


def rules_from_grants(grants:list[dict]):
    """One ALLOW per distinct (source,destination,proto,port); provenance preserved."""
    groups={}
    for g in grants:
        key=(ipv4(g['source_ip']),ipv4(g['dst_ip']),g['protocol'].upper(),int(g['port']))
        groups.setdefault(key,[]).append(int(g['request_id']))
    result=[]
    for i,(key,ids) in enumerate(sorted(groups.items()),start=1):
        src,dst,proto,port=key
        result.append(Rule(f'G{i:04d}',src,dst,proto,port,'ALLOW',priority=i*10,
                           provenance=tuple(sorted(ids)),reason='Được cấp bởi yêu cầu #'+','.join(map(str,sorted(ids)))))
    return result


def _covers(net: str, ip: str):
    return ip_address(ip) in ip_network(net,strict=False)


def trace_decision(rules:list[Rule],packet:Packet,default='DENY'):
    if default not in ACTIONS:raise ValueError('default action không hợp lệ')
    trace=[]
    for r in sorted(rules,key=lambda x:(x.priority,x.id)):
        checks={'source':_covers(r.source,packet.source),
                'destination':_covers(r.destination,packet.destination),
                'protocol':r.protocol=='ANY' or r.protocol==packet.protocol,
                'port':r.port=='ANY' or (packet.port is not None and r.port==packet.port)}
        # ICMP must only match ANY-port rules; no exception for TCP-only rules.
        ok=all(checks.values())
        trace.append({'rule_id':r.id,'checks':checks,'matched':ok})
        if ok:
            return {'action':r.action,'rule_id':r.id,'reason':r.reason,'provenance':list(r.provenance),'trace':trace}
    return {'action':default,'rule_id':None,'reason':'Không khớp luật nào; áp dụng default deny','provenance':[],'trace':trace}


def export_policy(rules:list[Rule]):
    return {'schema':'firewall-access-lifecycle/v1','model':'stateless-ipv4-first-match',
            'default_action':'DENY','rules':[r.to_dict() for r in rules]}


def parse_policy(payload:dict):
    if not isinstance(payload,dict) or not isinstance(payload.get('rules'),list):raise ValueError('Phải có trường rules dạng danh sách')
    if payload.get('default_action','DENY')!='DENY':raise ValueError('Hiện chỉ kiểm toán chính sách default DENY')
    rules=[Rule.from_dict(r) for r in payload['rules']]
    ids=[r.id for r in rules]
    if len(ids)!=len(set(ids)):raise ValueError('Rule id bị trùng')
    return rules
