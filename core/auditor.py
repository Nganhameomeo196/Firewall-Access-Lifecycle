"""Exact, bounded audits of stateless IPv4 rule behavior vs approved grants.

Proof: all match predicates remain constant inside each cell bounded by
all source and destination subnet endpoints and each destination port.
Both rule policy and approved grant predicates participate in partitioning.
"""
from __future__ import annotations
from dataclasses import dataclass
from ipaddress import ip_network, ip_address, IPv4Address
from itertools import product
from core.policy import Rule,Packet,trace_decision,rules_from_grants

class AuditIncomplete(RuntimeError):pass

@dataclass(frozen=True)
class Compiled:
    source:tuple[int,int]
    destination:tuple[int,int]
    proto:str
    port:int|str
    action:str
    id:str

    @classmethod
    def of(cls,rule):
        src=ip_network(rule.source,strict=False)
        dst=ip_network(rule.destination,strict=False)
        return cls((int(src.network_address),int(src.broadcast_address)),
                   (int(dst.network_address),int(dst.broadcast_address)),
                   rule.protocol,rule.port,rule.action,rule.id)

    def matches(self,s,d,proto,p):
        return (self.source[0]<=s<=self.source[1] and
                self.destination[0]<=d<=self.destination[1] and
                (self.proto=='ANY' or self.proto==proto) and
                (self.port=='ANY' or (p is not None and self.port==p)))


def partitions(*sets,max_cells=150_000):
    all_rules=[r for seq in sets for r in seq]
    sr={0,2**32};ds={0,2**32};pt={0,65536}
    for r in all_rules:
        a=Compiled.of(r)
        for dest,field in ((sr,a.source),(ds,a.destination)):
            dest.update((field[0],field[1]+1))
        if isinstance(a.port,int):pt.update((a.port,a.port+1))
    starts=lambda boundary: sorted(boundary)[:-1]
    s,d,p=starts(sr),starts(ds),starts(pt)
    total=len(s)*len(d)*(2*len(p)+1)
    if total>max_cells:raise AuditIncomplete(f'INCONCLUSIVE: {total:,} cells > max_cells={max_cells:,}. Không thể kết luận chính xác.')
    for src,dst in product(s,d):
        for proto in ('TCP','UDP'):
            for port in p:yield (src,dst,proto,port)
        yield (src,dst,'ICMP',None)


def decision(rules,compiled,cell,skip=None):
    for rule,c in zip(rules,compiled):
        if skip is not None and rule.id==skip:continue
        if c.matches(*cell):return rule.action,rule.id
    return 'DENY',None


def witness(cell):
    src,dst,protocol,port=cell
    return {'source':str(IPv4Address(src)),'destination':str(IPv4Address(dst)),
            'protocol':protocol,'port':port}


def audit_policy(actual_rules:list[Rule],approved_rules:list[Rule],max_cells=150_000,max_examples=100):
    """Exact allow-set equality for supported model; aggregates witnesses.

    Approved ALLOW defines intended grants. Everything else must be denied.
    Any configured ALLOW outside approved set => OVERPERMISSIVE.
    Any approved ALLOW blocked by policy => UNDERPERMISSIVE.
    """
    ar=sorted(actual_rules,key=lambda r:(r.priority,r.id))
    approved=sorted(approved_rules,key=lambda r:(r.priority,r.id))
    cp=[Compiled.of(x) for x in ar];cr=[Compiled.of(x) for x in approved]
    examples=[];issue_count=0;checked=0;types=set();seen=set()
    try:
        for cell in partitions(ar,approved,max_cells=max_cells):
            checked+=1
            actual,rid=decision(ar,cp,cell)
            expected,_=decision(approved,cr,cell)
            if actual==expected:continue
            category='OVERPERMISSIVE' if actual=='ALLOW' else 'UNDERPERMISSIVE'
            issue_count+=1;types.add(category)
            key=(category,rid,cell[2],cell[3])
            if key not in seen and len(examples)<max_examples:
                seen.add(key)
                examples.append({'category':category,'expected':expected,'actual':actual,
                                 'matched_rule':rid,'witness':witness(cell)})
        return {'complete':True,'checked_cells':checked,'violating_cells':issue_count,
                'types':sorted(types),'examples':examples,
                'summary':'PASS' if issue_count==0 else 'VIOLATIONS',
                'note':'Chính xác trong mô hình IPv4 stateless khi complete=True; ô không phải là gói tin.'}
    except AuditIncomplete as exc:
        return {'complete':False,'checked_cells':0,'violating_cells':None,
                'types':[],'examples':[],'summary':'INCONCLUSIVE','note':str(exc)}


def analyze_rules(rules:list[Rule],max_cells=150_000):
    """First-match shadow, partial overlap, and action-only redundancy."""
    ordered=sorted(rules,key=lambda r:(r.priority,r.id));compiled=[Compiled.of(r) for r in ordered]
    hits=[0]*len(ordered);first=[0]*len(ordered);blockers=[set() for _ in ordered]
    witnesses=[None]*len(ordered);redundant=[True]*len(ordered);checked=0
    try:
        for cell in partitions(ordered,max_cells=max_cells):
            checked+=1
            matching=[i for i,c in enumerate(compiled) if c.matches(*cell)]
            if not matching:continue
            winner=matching[0];first[winner]+=1
            if redundant[winner]:
                fall=ordered[matching[1]].action if len(matching)>1 else 'DENY'
                if fall!=ordered[winner].action:redundant[winner]=False
            for i in matching:
                hits[i]+=1
                if i!=winner:
                    blockers[i].add(ordered[winner].id)
                    if witnesses[i] is None:witnesses[i]=witness(cell)
    except AuditIncomplete as exc:
        return {'complete':False,'findings':[],'note':str(exc)}
    findings=[]
    for i,r in enumerate(ordered):
        if hits[i] and first[i]==0:
            other=[x for x in ordered if x.id in blockers[i]]
            opposite=any(x.action!=r.action for x in other)
            findings.append({'type':'SHADOWED','rule_id':r.id,'blockers':sorted(blockers[i]),
                             'severity':'HIGH' if opposite else 'LOW','witness':witnesses[i],
                             'explanation':'Luật không bao giờ là first-match; '+('có hành động đối lập.' if opposite else 'cùng hành động.')})
        elif hits[i]>first[i]:
            findings.append({'type':'PARTIAL_OVERLAP','rule_id':r.id,'blockers':sorted(blockers[i]),
                             'severity':'INFO','witness':witnesses[i],
                             'explanation':'Một phần vùng khớp bị luật trước quyết định; chưa tự kết luận là lỗi.'})
        if redundant[i]:
            findings.append({'type':'REDUNDANT_ACTION','rule_id':r.id,'blockers':[],
                             'severity':'INFO','witness':None,
                             'explanation':'Xóa luật không đổi ALLOW/DENY; chưa xét ý nghĩa logging/audit.'})
    return {'complete':True,'checked_cells':checked,'findings':findings,'note':'Phân tích tập luật hiện tại theo first-match.'}


def comparison(before:list[Rule],after:list[Rule],max_cells=150_000):
    a=sorted(before,key=lambda r:(r.priority,r.id));b=sorted(after,key=lambda r:(r.priority,r.id))
    ca=[Compiled.of(r) for r in a];cb=[Compiled.of(r) for r in b]
    try:
        n=0;changed=0;examples=[]
        for cell in partitions(a,b,max_cells=max_cells):
            n+=1
            left,_=decision(a,ca,cell);right,_=decision(b,cb,cell)
            if left!=right:
                changed+=1
                if len(examples)<30:examples.append({'witness':witness(cell),'before':left,'after':right})
        return {'complete':True,'checked_cells':n,'changed_cells':changed,'examples':examples}
    except AuditIncomplete as exc:
        return {'complete':False,'changed_cells':None,'examples':[],'note':str(exc)}
