"""End-to-end HTTP smoke tests for V2 REST API against isolated SQLite DBs."""
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase
from unittest.mock import patch
import json
from fastapi.testclient import TestClient
import backend.app as api_mod
from core.demo import seed_demo


class ApiIntegrationTests(TestCase):
    def setUp(self):
        self.tmp=TemporaryDirectory()
        self.patch=patch.object(api_mod,'DB',Path(self.tmp.name)/'test.sqlite3')
        self.patch.start()
        seed_demo(api_mod.service())
        self.client=TestClient(api_mod.app)

    def tearDown(self):
        self.client.close()
        self.patch.stop()
        self.tmp.cleanup()

    def login(self,username='admin'):
        r=self.client.post('/api/auth/login',json={'username':username,'password':'Demo@2026!'})
        self.assertEqual(r.status_code,200,r.text)

    def test_auth_and_state(self):
        self.assertEqual(self.client.get('/api/auth/me').status_code,401)
        self.assertEqual(self.client.post('/api/auth/login',json={'username':'admin','password':'wrong'}).status_code,401)
        self.login()
        x=self.client.get('/api/state');self.assertEqual(x.status_code,200)
        self.assertEqual(x.json()['summary']['users'],6)
        self.assertEqual(x.json()['summary']['assets'],5)
        self.assertEqual(x.json()['summary']['generated_rules'],3)
        self.assertIn('insights',x.json())
        self.client.post('/api/auth/logout')
        self.assertEqual(self.client.get('/api/auth/me').status_code,401)

    def test_crm_visible_without_service_and_duplicate_friendly(self):
        self.login()
        payload={'name':'CRM Lab','ip':'10.20.4.10','department':'SALES','sensitivity':'MEDIUM','owner':'Phòng kinh doanh'}
        self.assertEqual(self.client.post('/api/assets',json=payload).status_code,200)
        state=self.client.get('/api/state').json()
        assets=[x for x in state['assets'] if x['name']=='CRM Lab']
        self.assertEqual(len(assets),1)
        self.assertFalse(any(x['asset']=='CRM Lab' for x in state['services']))
        self.assertEqual(state['summary']['assets'],6)
        duplicate=self.client.post('/api/assets',json={**payload,'name':'Other CRM'})
        self.assertEqual(duplicate.status_code,409)
        self.assertIn('IP',duplicate.json()['detail'])
        srv=self.client.post('/api/services',json={'asset_id':assets[0]['id'],'name':'HTTPS','protocol':'TCP','port':443})
        self.assertEqual(srv.status_code,200,srv.text)
        state=self.client.get('/api/state').json()
        self.assertTrue(any(x['asset']=='CRM Lab' and x['port']==443 for x in state['services']))

    def test_employee_cannot_admin_and_cannot_self_approve(self):
        self.login('nam')
        self.assertEqual(self.client.post('/api/assets',json={'name':'X','ip':'10.20.9.9','department':'SALES','owner':'X','sensitivity':'LOW'}).status_code,403)
        self.assertEqual(self.client.get('/api/policy/audit').status_code,403)
        self.assertEqual(self.client.get('/api/state').json()['actor']['username'],'nam')

    def test_preview_approve_revoke_and_policy_simulation(self):
        self.login('approver')
        before=self.client.get('/api/state').json()
        q=next(x for x in before['requests'] if x['username']=='quang' and x['status']=='PENDING')
        a=self.client.get(f"/api/requests/{q['id']}/preview?mode=approve")
        self.assertEqual(a.status_code,200,a.text)
        self.assertTrue(a.json()['eligible'])
        self.assertTrue(a.json()['impact']['complete'])
        self.assertGreater(a.json()['impact']['changed_cells'],0)
        self.assertEqual(self.client.post(f"/api/requests/{q['id']}/decision",json={'approve':True,'reason':'Hợp lệ'}).status_code,200)
        after=self.client.get('/api/state').json()
        self.assertEqual(len(after['rules']),len(before['rules'])+1)
        simulation=self.client.post('/api/policy/simulate',json={'source':'10.10.10.11','destination':'10.20.1.10','protocol':'TCP','port':443})
        self.assertEqual(simulation.json()['decision']['action'],'ALLOW')
        impact=self.client.get(f"/api/requests/{q['id']}/preview?mode=revoke")
        self.assertTrue(impact.json()['eligible'])
        self.assertGreater(impact.json()['impact']['changed_cells'],0)
        self.assertEqual(self.client.post(f"/api/requests/{q['id']}/revoke",json={'reason':'Hết nhu cầu'}).status_code,200)
        self.assertEqual(self.client.get('/api/state').json()['summary']['generated_rules'],3)
        simulation=self.client.post('/api/policy/simulate',json={'source':'10.10.10.11','destination':'10.20.1.10','protocol':'TCP','port':443})
        self.assertEqual(simulation.json()['decision']['action'],'DENY')

    def test_whatif_monitor_and_exports(self):
        self.login()
        payload=json.loads((Path(__file__).resolve().parent.parent/'samples'/'what_if_broad.json').read_text())
        r=self.client.post('/api/policy/whatif',json={'policy':payload})
        self.assertEqual(r.status_code,200,r.text)
        self.assertEqual(r.json()['audit']['summary'],'VIOLATIONS')
        self.assertIn('OVERPERMISSIVE',r.json()['audit']['types'])
        text=(Path(__file__).resolve().parent.parent/'samples'/'traffic.csv').read_text()
        r=self.client.post('/api/monitor/import',json={'format':'csv','content':text})
        self.assertEqual(r.status_code,200,r.text)
        self.assertGreaterEqual(r.json()['added'],1)
        self.assertGreaterEqual(self.client.get('/api/state').json()['monitor']['total'],1)
        r=self.client.get('/api/policy/export/nft');self.assertEqual(r.status_code,200)
        self.assertIn('table',r.text)
        r=self.client.get('/api/report/md');self.assertEqual(r.status_code,200)

    def test_new_crm_end_to_end(self):
        self.login()
        asset=self.client.post('/api/assets',json={'name':'New CRM','ip':'10.20.4.10','department':'SALES','sensitivity':'MEDIUM','owner':'IT'}).json()['id']
        service_id=self.client.post('/api/services',json={'asset_id':asset,'name':'HTTPS','protocol':'TCP','port':443}).json()['id']
        self.assertEqual(self.client.post('/api/entitlements',json={'business_role':'SALES','service_id':service_id}).status_code,200)
        self.client.post('/api/auth/logout')
        self.login('nam')
        req=self.client.post('/api/requests',json={'service_id':service_id,'purpose':'Quản lý khách hàng CRM','days':3})
        self.assertEqual(req.status_code,200,req.text)
        rid=req.json()['id']
        self.client.post('/api/auth/logout')
        self.login('approver')
        self.assertTrue(self.client.get(f'/api/requests/{rid}/preview').json()['eligible'])
        r=self.client.post(f'/api/requests/{rid}/decision',json={'approve':True,'reason':'Sales được phép'})
        self.assertEqual(r.status_code,200,r.text)
        sim=self.client.post('/api/policy/simulate',json={'source':'10.10.30.10','destination':'10.20.4.10','protocol':'TCP','port':443})
        self.assertEqual(sim.json()['decision']['action'],'ALLOW')
