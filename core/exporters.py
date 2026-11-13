"""Policy adapter interface with two concrete, side-effect-free exporters.

The draft nftables exporter is for a lab gateway only. It does not execute
commands or verify existing nftables state, NAT, interfaces or conntrack.
"""
from typing import Protocol
import json
from core.policy import Rule,export_policy


class PolicyExporter(Protocol):
    def render(self,rules:list[Rule])->str:...


class JSONExporter:
    def render(self,rules:list[Rule])->str:
        return json.dumps(export_policy(rules),indent=2,ensure_ascii=False)


class NftablesLabDraftExporter:
    def render(self,rules:list[Rule])->str:
        lines=['# LAB DRAFT — review before any use; no automatic application.',
               '# Model: IPv4 stateless forward traffic only; deny by default.',
               '# Must validate with nft syntax check in an isolated lab.',
               'table inet accessflow_lab {',
               '  chain forward {',
               '    type filter hook forward priority 0; policy drop;']
        for r in sorted(rules,key=lambda x:(x.priority,x.id)):
            # Only generated well-scoped ALLOW rules should be exported.
            if r.action!='ALLOW' or r.protocol not in ('TCP','UDP') or not isinstance(r.port,int) or not r.provenance:
                raise ValueError('Nft lab export chỉ hỗ trợ ALLOW TCP/UDP từ phiếu đã phê duyệt; không xuất luật tùy ý.')
            comment='req_'+('_'.join(map(str,r.provenance)))
            lines.append(f'    ip saddr {r.source} ip daddr {r.destination} '
                         f'{r.protocol.lower()} dport {r.port} counter accept comment "{comment}"')
        lines+=['  }','}']
        return '\n'.join(lines)+'\n'


EXPORTERS={'json':JSONExporter(),'nft_lab_draft':NftablesLabDraftExporter()}
