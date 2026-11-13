import json
import shutil
import sqlite3
import tempfile
import unittest
from datetime import datetime,timedelta,timezone
from pathlib import Path
from contextlib import closing
from core.database import query,connect
from core.workflow import AccessService
from core.demo import seed_demo,DEMO_PASSWORD
from core.policy import Packet,Rule,rules_from_grants,trace_decision,export_policy,parse_policy
from core.auditor import audit_policy,analyze_rules,comparison
from core.monitoring import import_traffic,analyze_traffic,parse_blob

ROOT=Path(__file__).resolve().parents[1]

class Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory()
        svc=AccessService(Path(cls.temp.name)/'original.sqlite3')
        seed_demo(svc)
        with closing(connect(svc.db)) as source, closing(sqlite3.connect(str(Path(cls.temp.name)/'template.sqlite3'))) as target:
            source.backup(target)

    @classmethod
    def tearDownClass(cls):cls.temp.cleanup()

    def setUp(self):
        # Every test starts from an identical, clean, committed demo snapshot.
        self.db=Path(self.temp.name)/(self.id().replace('.','_')+'.sqlite3')
        shutil.copyfile(Path(self.temp.name)/'template.sqlite3',self.db)
        self.svc=AccessService(self.db)
        self.admin=self.svc.login('admin',DEMO_PASSWORD)
        self.approver=self.svc.login('approver',DEMO_PASSWORD)
        self.linh=self.svc.login('linh',DEMO_PASSWORD)
        self.mai=self.svc.login('mai',DEMO_PASSWORD)
        self.nam=self.svc.login('nam',DEMO_PASSWORD)
        self.quang=self.svc.login('quang',DEMO_PASSWORD)

    def service(self,asset):
        return next(x['id'] for x in self.svc.inventory() if x['asset']==asset)

    def fresh_request(self,who,service,days=4):
        exp=(datetime.now(timezone.utc)+timedelta(days=days)).isoformat(timespec='seconds')
        return self.svc.request_access(who,service,'Đề nghị quyền nghiệp vụ có lý do rõ ràng',exp)


class IdentityAndInventory(Base):
    def test_demo_seed(self):
        self.assertEqual(len(self.svc.list('users')),6)
        self.assertEqual(len(self.svc.active_access()),3)

    def test_login_rejects_wrong_password(self):
        with self.assertRaises(PermissionError):self.svc.login('admin','wrong password')

    def test_login_rejects_missing_user(self):
        with self.assertRaises(PermissionError):self.svc.login('nonexistent','whatever')

    def test_employee_cannot_add_user(self):
        with self.assertRaises(PermissionError):self.svc.add_user(self.linh,'other','Demo@2026!','Test','HR','EMPLOYEE','10.10.10.111')

    def test_admin_adds_user(self):
        target=self.svc.add_user(self.admin,'newuser','NewPassword@10','New employee','HR','EMPLOYEE','10.10.10.111')
        self.assertEqual(self.svc.actor(target)['business_role'],'HR')

    def test_unique_device_ip(self):
        with self.assertRaises(sqlite3.IntegrityError):
            self.svc.add_user(self.admin,'other','NewPassword@10','Two devices same IP','SALES','EMPLOYEE','10.10.10.10')

    def test_invalid_ipv4_is_rejected(self):
        with self.assertRaises(ValueError):
            self.svc.add_asset(self.admin,'bad','10.99.99.999','IT','LOW','Ops')

    def test_admin_can_create_asset_and_service(self):
        aid=self.svc.add_asset(self.admin,'Lab API','10.20.4.10','IT','HIGH','IT')
        sid=self.svc.add_service(self.admin,aid,'HTTPS','TCP',443)
        self.svc.grant_entitlement(self.admin,'SALES',sid)
        self.assertTrue(any(x['business_role']=='SALES' and x['service_id']==sid for x in self.svc.list('entitlements')))

    def test_password_change(self):
        self.svc.change_password(self.linh,DEMO_PASSWORD,'AnotherGoodPassword@1')
        self.assertEqual(self.svc.login('linh','AnotherGoodPassword@1'),self.linh)
        with self.assertRaises(PermissionError):self.svc.login('linh',DEMO_PASSWORD)

    def test_wrong_old_password(self):
        with self.assertRaises(PermissionError):self.svc.change_password(self.linh,'not right','SomeGoodPassword@1')


class RequestWorkflow(Base):
    def test_employee_submits_request(self):
        rid=self.fresh_request(self.quang,self.service('Accounting Application'))
        rows=query(self.db,'SELECT status FROM requests WHERE id=?',(rid,))
        self.assertEqual(rows[0]['status'],'PENDING')

    def test_self_approval_is_forbidden(self):
        rid=self.fresh_request(self.approver,self.service('Internal Portal'))
        with self.assertRaises(PermissionError):self.svc.decide(self.approver,rid,True,'tự cấp')

    def test_regular_employee_cannot_approve(self):
        rid=self.fresh_request(self.quang,self.service('Accounting Application'))
        with self.assertRaises(PermissionError):self.svc.decide(self.linh,rid,True,'không có quyền')

    def test_approve_with_entitlement(self):
        rid=self.fresh_request(self.quang,self.service('Accounting Application'))
        self.svc.decide(self.approver,rid,True,'đúng vai trò, hợp lệ')
        self.assertIn(rid,[g['request_id'] for g in self.svc.active_access()])

    def test_approval_rejects_business_role_mismatch(self):
        rid=self.fresh_request(self.linh,self.service('Finance Database'))
        with self.assertRaises(PermissionError):self.svc.decide(self.approver,rid,True,'thử vượt quyền')
        self.assertEqual(query(self.db,'SELECT status FROM requests WHERE id=?',(rid,))[0]['status'],'PENDING')

    def test_reject_request(self):
        rid=self.fresh_request(self.linh,self.service('Finance Database'))
        self.svc.decide(self.approver,rid,False,'không có nhu cầu phù hợp')
        self.assertEqual(query(self.db,'SELECT status FROM requests WHERE id=?',(rid,))[0]['status'],'REJECTED')

    def test_cannot_approve_twice(self):
        rid=self.fresh_request(self.quang,self.service('Accounting Application'))
        self.svc.decide(self.approver,rid,True,'lần một')
        with self.assertRaises(ValueError):self.svc.decide(self.approver,rid,True,'lần hai')

    def test_empty_reason_is_rejected(self):
        rid=self.fresh_request(self.quang,self.service('Accounting Application'))
        with self.assertRaises(ValueError):self.svc.decide(self.approver,rid,True,' ')

    def test_past_expiry_rejected(self):
        with self.assertRaises(ValueError):self.svc.request_access(self.linh,self.service('Internal Portal'),'business','2020-01-01T00:00:00+00:00')

    def test_malformed_expiry_rejected(self):
        with self.assertRaises(ValueError):self.svc.request_access(self.linh,self.service('Internal Portal'),'business','2026-11-11T14:00:00')


class PolicyAndAudit(Base):
    def test_rules_have_provenance(self):
        rules=rules_from_grants(self.svc.active_access())
        self.assertEqual(len(rules),3)
        self.assertTrue(all(r.provenance and r.reason for r in rules))

    def test_authorized_flow_allowed(self):
        rules=rules_from_grants(self.svc.active_access())
        result=trace_decision(rules,Packet('10.10.10.10','10.20.1.10','TCP',443))
        self.assertEqual(result['action'],'ALLOW')
        self.assertTrue(result['provenance'])

    def test_unauthorized_flow_denied(self):
        rules=rules_from_grants(self.svc.active_access())
        self.assertEqual(trace_decision(rules,Packet('10.10.30.10','10.20.2.10','TCP',5432))['action'],'DENY')

    def test_exact_generated_policy_passes(self):
        rules=rules_from_grants(self.svc.active_access())
        result=audit_policy(rules,rules)
        self.assertTrue(result['complete']);self.assertEqual(result['summary'],'PASS')

    def test_broad_allow_is_flagged_with_witness(self):
        candidate=parse_policy(json.loads((ROOT/'samples/what_if_broad.json').read_text()))
        expected=rules_from_grants(self.svc.active_access())
        result=audit_policy(candidate,expected)
        self.assertEqual(result['summary'],'VIOLATIONS')
        self.assertTrue(any(e['category']=='OVERPERMISSIVE' and e['witness'] for e in result['examples']))
        self.assertTrue(any(e['category']=='UNDERPERMISSIVE' for e in result['examples']))

    def test_comparison_detects_change(self):
        expected=rules_from_grants(self.svc.active_access())
        candidate=parse_policy(json.loads((ROOT/'samples/what_if_broad.json').read_text()))
        self.assertGreater(comparison(expected,candidate)['changed_cells'],0)

    def test_comparison_same_policy_no_change(self):
        rules=rules_from_grants(self.svc.active_access())
        self.assertEqual(comparison(rules,rules)['changed_cells'],0)

    def test_incomplete_not_falsely_passed(self):
        rules=rules_from_grants(self.svc.active_access())
        result=audit_policy(rules,rules,max_cells=1)
        self.assertFalse(result['complete']);self.assertEqual(result['summary'],'INCONCLUSIVE')

    def test_duplicate_rule_ids_rejected(self):
        rules=rules_from_grants(self.svc.active_access())
        obj=export_policy(rules)
        obj['rules'].append(obj['rules'][0])
        with self.assertRaises(ValueError):parse_policy(obj)

    def test_analyzer_shadow_identifies_blocker(self):
        rules=[Rule('A','ANY','10.20.1.10','TCP',443,'ALLOW',1),
               Rule('B','10.10.10.10','10.20.1.10','TCP',443,'DENY',2)]
        findings=analyze_rules(rules)
        self.assertTrue(findings['complete'])
        x=next(f for f in findings['findings'] if f['rule_id']=='B' and f['type']=='SHADOWED')
        self.assertEqual(x['blockers'],['A']);self.assertEqual(x['severity'],'HIGH')

    def test_redundant_explicit_deny(self):
        rules=[Rule('DEFAULT','ANY','ANY','ANY','ANY','DENY',10)]
        result=analyze_rules(rules)
        self.assertTrue(any(x['type']=='REDUNDANT_ACTION' for x in result['findings']))

    def test_icmp_port_validation(self):
        with self.assertRaises(ValueError):Rule('I','ANY','ANY','ICMP',22,'DENY',5)
        self.assertEqual(trace_decision([Rule('I','ANY','ANY','ICMP','ANY','ALLOW',5)],Packet('10.1.1.1','10.1.1.2','ICMP',None))['action'],'ALLOW')


class LifecycleAndMonitoring(Base):
    def test_revocation_removes_network_rule(self):
        rid=next(g['request_id'] for g in self.svc.active_access() if g['username']=='linh')
        self.svc.revoke_request(self.approver,rid,'Kết thúc yêu cầu')
        flow=trace_decision(rules_from_grants(self.svc.active_access()),Packet('10.10.10.10','10.20.1.10','TCP',443))
        self.assertEqual(flow['action'],'DENY')

    def test_role_change_revoke(self):
        n=self.svc.change_user(self.admin,self.linh,business_role='SALES')
        self.assertGreaterEqual(n,1)
        self.assertFalse(any(x['requester_id']==self.linh for x in self.svc.active_access()))

    def test_ip_change_revoke(self):
        n=self.svc.change_user(self.admin,self.linh,source_ip='10.10.10.100')
        self.assertGreaterEqual(n,1)

    def test_offboarding_revokes_and_blocks_login(self):
        self.svc.change_user(self.admin,self.linh,active=False)
        with self.assertRaises(PermissionError):self.svc.login('linh',DEMO_PASSWORD)
        self.assertFalse(any(x['requester_id']==self.linh for x in self.svc.active_access()))

    def test_expiry_is_effective_before_sync(self):
        rid=next(g['request_id'] for g in self.svc.active_access() if g['username']=='linh')
        with closing(connect(self.db)) as c:
            with c:
                c.execute('UPDATE requests SET expires_at=? WHERE id=?',('2020-01-01T00:00:00+00:00',rid))
        self.assertNotIn(rid,[x['request_id'] for x in self.svc.active_access()])
        self.assertEqual(self.svc.expire_due(self.approver),1)
        self.assertEqual(query(self.db,'SELECT status FROM requests WHERE id=?',(rid,))[0]['status'],'EXPIRED')

    def test_entitlement_removal_revokes(self):
        sid=self.service('Accounting Application')
        self.svc.remove_entitlement(self.admin,'ACCOUNTING',sid)
        self.assertFalse(any(x['service_id']==sid for x in self.svc.active_access()))

    def test_disable_asset_revokes(self):
        asset=next(x for x in self.svc.list('assets') if x['name']=='Accounting Application')
        count=self.svc.disable_asset(self.admin,asset['id'])
        self.assertGreaterEqual(count,1)
        self.assertFalse(any(x['asset_id']==asset['id'] for x in self.svc.active_access()))

    def test_log_import_and_dedup(self):
        blob=(ROOT/'samples/traffic.csv').read_text(encoding='utf-8')
        result=import_traffic(self.svc,self.approver,blob,'csv')
        self.assertEqual(result['added'],5)
        self.assertEqual(import_traffic(self.svc,self.approver,blob,'csv')['added'],0)

    def test_employee_cannot_import_log(self):
        with self.assertRaises(PermissionError):import_traffic(self.svc,self.linh,(ROOT/'samples/traffic.csv').read_text(),'csv')

    def test_zeek_import_action_is_unknown(self):
        blob=(ROOT/'samples/zeek_conn.jsonl').read_text()
        result=import_traffic(self.svc,self.approver,blob,'zeek')
        self.assertEqual(result['added'],2)
        self.assertTrue(all(x['observed_action']=='UNKNOWN' for x in self.svc.list('traffic')))

    def test_monitor_detects_unapproved(self):
        import_traffic(self.svc,self.admin,(ROOT/'samples/traffic.csv').read_text(),'csv')
        result=analyze_traffic(self.svc,rules_from_grants(self.svc.active_access()))
        self.assertTrue(result['alerts'])
        self.assertTrue(any(x['category']=='OBSERVED_OUTSIDE_ENTITLEMENT' for x in result['alerts']))

    def test_monitor_marks_explicit_allow_outside_entitlement(self):
        import_traffic(self.svc,self.admin,(ROOT/'samples/traffic.csv').read_text(),'csv')
        result=analyze_traffic(self.svc,rules_from_grants(self.svc.active_access()))
        self.assertTrue(any(x['category']=='LOGGED_ALLOW_OUTSIDE_ENTITLEMENT' for x in result['alerts']))

    def test_bad_import_is_atomic(self):
        blob='timestamp,src_ip,dst_ip,protocol,dst_port,observed_action\n2026-11-10T08:00:00+00:00,10.1.1.1,10.2.2.2,TCP,80,ALLOW\n2026-11-10T08:00:00+00:00,wrong,10.2.2.2,TCP,80,ALLOW\n'
        with self.assertRaises(ValueError):import_traffic(self.svc,self.admin,blob,'csv')
        self.assertEqual(len(self.svc.list('traffic')),0)

    def test_audit_trail_records_decisions(self):
        rid=self.fresh_request(self.quang,self.service('Accounting Application'))
        self.svc.decide(self.approver,rid,True,'Kiểm tra quyền')
        names=[x['event'] for x in self.svc.list('audit_events')]
        self.assertIn('REQUEST_SUBMITTED',names)
        self.assertIn('REQUEST_APPROVED',names)

if __name__=='__main__':unittest.main(verbosity=2)

class ReportingAndExport(Base):
    def test_report_hides_password_hashes(self):
        from core.reports import make_report,markdown_report
        rep=make_report(self.svc)
        self.assertIn('compliance',rep)
        self.assertNotIn('password_hash',str(rep))
        self.assertIn('Quyền',markdown_report(rep))

    def test_nft_draft_is_read_only_text(self):
        from core.exporters import NftablesLabDraftExporter
        before=len(self.svc.active_access())
        text=NftablesLabDraftExporter().render(rules_from_grants(self.svc.active_access()))
        self.assertIn('ip saddr',text)
        self.assertIn('LAB DRAFT',text)
        self.assertEqual(len(self.svc.active_access()),before)

    def test_nft_rejects_unapproved_arbitrary_rule(self):
        from core.exporters import NftablesLabDraftExporter
        with self.assertRaises(ValueError):
            NftablesLabDraftExporter().render([Rule('BAD','ANY','ANY','TCP',22,'ALLOW',1)])
