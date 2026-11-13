"""Structured, reproducible local audit report; never exports password hashes."""
from datetime import datetime,timezone
from collections import Counter
from core.policy import rules_from_grants,export_policy
from core.auditor import audit_policy,analyze_rules
from core.monitoring import analyze_traffic


def make_report(svc):
    grants=svc.active_access();rules=rules_from_grants(grants)
    reqs=svc.list('requests')
    inventory=svc.inventory()
    roles=svc.list('entitlements')
    traffic=analyze_traffic(svc,rules)
    return {'report_name':'AccessFlow network access governance audit',
      'generated_at':datetime.now(timezone.utc).isoformat(timespec='seconds'),
      'scope':'IPv4 stateless, source IP, destination IP, protocol, destination port, first-match/default-deny',
      'assets':inventory,'role_entitlements':roles,
      'request_status_counts':dict(Counter(r['status'] for r in reqs)),
      'active_approvals':grants,
      'policy':export_policy(rules),
      'compliance':audit_policy(rules,rules),
      'rule_anomalies':analyze_rules(rules),
      'traffic_review':traffic,
      'total_audit_events':len(svc.list('audit_events')),
      'caveats':['Không thực thi firewall thật.',
      'Log được đối chiếu với quyền đang có hiệu lực, không tái dựng quyền trong quá khứ.',
      'Mô hình gắn một IPv4 tĩnh cho mỗi tài khoản; không giải quyết DHCP/NAT/mạo danh IP.',
      'Chỉ kết luận kiểm toán chính xác nếu complete=True.',
      'Thời hạn quyền chặn sinh luật kể cả khi chưa cập nhật trạng thái EXPIRED.']}


def markdown_report(report):
    lines=['# Báo cáo kiểm toán quản lý truy cập mạng','',f"- Thời điểm: {report['generated_at']}",
           f"- Phạm vi: {report['scope']}",
           f"- Số quyền có hiệu lực: {len(report['active_approvals'])}",
           f"- Số luật sinh từ quyền: {len(report['policy']['rules'])}",
           f"- Kiểm toán: {report['compliance']['summary']} (complete={report['compliance']['complete']})",
           f"- Luồng có cảnh báo: {len(report['traffic_review']['alerts'])}",'',
           '## Trạng thái yêu cầu']
    lines.extend(f"- {key}: {v}" for key,v in report['request_status_counts'].items())
    lines+=['','## Quyền đang có hiệu lực']
    for grant in report['active_approvals']:
        lines.append(f"- Phiếu #{grant['request_id']}: {grant['username']} ({grant['source_ip']}) → "
                     f"{grant['asset_name']} ({grant['dst_ip']}) {grant['protocol']}/{grant['port']}; "
                     f"hết hạn {grant['expires_at']}")
    lines+=['','## Cảnh báo chính sách']
    if not report['compliance']['examples']:lines.append('- Không có sai lệch giữa luật sinh và quyền còn hiệu lực (trong mô hình).')
    else:
        for e in report['compliance']['examples']:
            lines.append(f"- {e['category']}: {e['witness']}")
    lines+=['','## Giám sát cần rà soát']
    for a in report['traffic_review']['alerts'][:50]:
        lines.append(f"- #{a['traffic_id']}: {a['category']} (score {a['risk_score']}) "
                     f"{a['source']} → {a['destination']} {a['protocol']}/{a['port']}")
    lines+=['','## Giới hạn và giả định']
    lines.extend(f'- {x}' for x in report['caveats'])
    return '\n'.join(lines)+'\n'
