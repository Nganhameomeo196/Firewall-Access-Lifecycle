"""Command-line interface; provides independent non-Streamlit operation."""
import argparse
import json
from pathlib import Path
from core.workflow import AccessService
from core.demo import seed_demo
from core.policy import rules_from_grants,export_policy,parse_policy
from core.auditor import audit_policy,analyze_rules,comparison
from core.monitoring import import_traffic,analyze_traffic
from core.reports import make_report,markdown_report
from core.exporters import NftablesLabDraftExporter

BASE=Path(__file__).resolve().parent
DEFAULT_DB=BASE/'runtime'/'access.sqlite3'


def dump(obj):print(json.dumps(obj,ensure_ascii=False,indent=2))


def main():
    p=argparse.ArgumentParser(description='Access Lifecycle + Firewall Auditor (local lab)')
    p.add_argument('--db',default=str(DEFAULT_DB),help='SQLite database path')
    sub=p.add_subparsers(dest='command',required=True)
    for x in ['init','status','policy','audit','analyze','monitor','demo','report'] :sub.add_parser(x)
    x=sub.add_parser('simulate');x.add_argument('--src',required=True);x.add_argument('--dst',required=True);x.add_argument('--proto',default='TCP');x.add_argument('--port',type=int,required=True)
    x=sub.add_parser('compare');x.add_argument('json_file')
    x=sub.add_parser('import-traffic');x.add_argument('path');x.add_argument('--format',choices=['csv','zeek'],default='csv');x.add_argument('--actor',default='admin');x.add_argument('--password',required=True)
    x=sub.add_parser('expire');x.add_argument('--actor',default='admin');x.add_argument('--password',required=True)
    x=sub.add_parser('export');x.add_argument('file')
    x=sub.add_parser('export-nft-lab-draft');x.add_argument('file')
    args=p.parse_args();svc=AccessService(args.db)
    if args.command in ('init','demo'):
        seeded=seed_demo(svc)
        print('Demo seeded.' if seeded else 'Database already initialized; existing data preserved.')
    rules=rules_from_grants(svc.active_access())
    if args.command=='status':dump({'users':len(svc.list('users')),'assets':len(svc.list('assets')),'services':len(svc.list('services')),'requests':len(svc.list('requests')),'active_access':len(svc.active_access()),'generated_rules':len(rules)})
    elif args.command in ('policy','demo'):dump(export_policy(rules))
    elif args.command=='audit':dump(audit_policy(rules,rules))
    elif args.command=='analyze':dump(analyze_rules(rules))
    elif args.command=='monitor':dump(analyze_traffic(svc,rules))
    elif args.command=='report':dump(make_report(svc))
    elif args.command=='simulate':
        from core.policy import Packet,trace_decision
        dump(trace_decision(rules,Packet(args.src,args.dst,args.proto,args.port)))
    elif args.command=='compare':
        other=parse_policy(json.loads(Path(args.json_file).read_text(encoding='utf-8')))
        dump({'compliance':audit_policy(other,rules),'what_if':comparison(rules,other)})
    elif args.command=='export':
        Path(args.file).write_text(json.dumps(export_policy(rules),ensure_ascii=False,indent=2),encoding='utf-8')
        print('Wrote:',args.file)
    elif args.command=='export-nft-lab-draft':
        Path(args.file).write_text(NftablesLabDraftExporter().render(rules),encoding='utf-8')
        print('Wrote lab-only draft (NOT applied):',args.file)
    elif args.command=='import-traffic':
        actor=svc.login(args.actor,args.password)
        dump(import_traffic(svc,actor,Path(args.path).read_text(encoding='utf-8'),args.format))
    elif args.command=='expire':
        actor=svc.login(args.actor,args.password);dump({'expired_count':svc.expire_due(actor)})


if __name__=='__main__':main()
