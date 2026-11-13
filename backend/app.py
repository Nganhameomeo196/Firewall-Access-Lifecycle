"""AccessFlow V2 HTTP API + responsive local web UI.

Careful scope: no packet interception, no automatic firewall apply. All
mutating operations go through AccessService's role checks.
"""
from __future__ import annotations
from datetime import datetime,timezone,timedelta
from pathlib import Path
import json
import sqlite3
import os
from typing import Literal

from fastapi import FastAPI, Request, Depends, HTTPException
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from backend.auth import create_session,decode_session,guard_login,failed_login,successful_login
from backend.insights import enriched_requests,insights,approval_check
from core.workflow import AccessService
from core.demo import seed_demo
from core.database import query
from core.policy import rules_from_grants, Packet, trace_decision, export_policy,parse_policy
from core.auditor import audit_policy, analyze_rules,comparison
from core.monitoring import import_traffic,analyze_traffic
from core.exporters import NftablesLabDraftExporter
from core.reports import make_report,markdown_report

ROOT = Path(__file__).resolve().parent.parent
DB = Path(os.environ.get('ACCESSFLOW_DB', str(ROOT / 'runtime' / 'access.sqlite3')))
WEB = ROOT / 'web'
app=FastAPI(title='AccessFlow V2 API',version='2.0.0',docs_url='/api/docs',openapi_url='/api/openapi.json',redoc_url=None)
app.add_middleware(TrustedHostMiddleware,allowed_hosts=['localhost','127.0.0.1','testserver'])

@app.on_event('startup')
def startup():
    seed_demo(service())


def service() -> AccessService:
    return AccessService(DB)


def actor(request: Request,svc:AccessService=Depends(service)):
    uid=decode_session(request,ROOT)
    try:
        result=svc.actor(uid)
        if not result['active']:raise PermissionError('Tài khoản đã bị khóa')
        return result
    except PermissionError as exc:raise HTTPException(status_code=401,detail=str(exc))


def needs(*roles):
    def check(user=Depends(actor)):
        if user['system_role'] not in roles:raise HTTPException(status_code=403,detail='Tài khoản không có quyền thực hiện thao tác này')
        return user
    return check


def service_error(exc):
    if isinstance(exc,sqlite3.IntegrityError):
        raw=str(exc)
        field=raw.split(': ',1)[-1]
        names={'assets.ip':'Địa chỉ IP máy chủ đã được sử dụng','assets.name':'Tên tài nguyên đã tồn tại',
               'users.source_ip':'Địa chỉ IP thiết bị đã được sử dụng','users.username':'Tên đăng nhập đã tồn tại',
               'services.asset_id, services.protocol, services.port':'Dịch vụ giao thức/cổng đã có trên máy chủ này',
               'entitlements.business_role, entitlements.service_id':'Quyền chuẩn đã tồn tại'}
        return HTTPException(status_code=409,detail=names.get(field,'Dữ liệu bị trùng hoặc vi phạm ràng buộc cơ sở dữ liệu'))
    if isinstance(exc,PermissionError):return HTTPException(status_code=403,detail=str(exc))
    if isinstance(exc,(ValueError,TypeError)):return HTTPException(status_code=400,detail=str(exc))
    raise exc


@app.exception_handler(sqlite3.IntegrityError)
async def db_exception(request:Request,exc:sqlite3.IntegrityError):
    e=service_error(exc)
    return JSONResponse(status_code=e.status_code,content={'detail':e.detail})

@app.exception_handler(PermissionError)
async def permission_exception(request:Request,exc:PermissionError):
    e=service_error(exc)
    return JSONResponse(status_code=e.status_code,content={'detail':e.detail})

@app.exception_handler(ValueError)
async def value_exception(request:Request,exc:ValueError):
    e=service_error(exc)
    return JSONResponse(status_code=e.status_code,content={'detail':e.detail})


class Login(BaseModel):
    username:str=Field(min_length=1,max_length=64)
    password:str=Field(min_length=1,max_length=256)

class UserIn(BaseModel):
    username:str
    password:str=Field(min_length=10)
    display_name:str
    business_role:str
    system_role:Literal['EMPLOYEE','APPROVER','ADMIN']='EMPLOYEE'
    source_ip:str

class AssetIn(BaseModel):
    name:str
    ip:str
    department:str
    sensitivity:Literal['LOW','MEDIUM','HIGH']='MEDIUM'
    owner:str

class ServiceIn(BaseModel):
    asset_id:int
    name:str
    protocol:Literal['TCP','UDP']='TCP'
    port:int=Field(ge=1,le=65535)

class EntitlementIn(BaseModel):
    business_role:str
    service_id:int

class RequestIn(BaseModel):
    service_id:int
    purpose:str
    days:int=Field(ge=1,le=365)

class DecisionIn(BaseModel):
    approve:bool
    reason:str

class RevokeIn(BaseModel):
    reason:str

class UserChange(BaseModel):
    business_role:str|None=None
    source_ip:str|None=None
    active:bool|None=None

class PasswordChange(BaseModel):
    current_password:str
    new_password:str=Field(min_length=10)

class Simulate(BaseModel):
    source:str
    destination:str
    protocol:Literal['TCP','UDP','ICMP']='TCP'
    port:int|None=Field(default=443,ge=0,le=65535)

class Candidate(BaseModel):
    policy:dict

class TrafficImport(BaseModel):
    format:Literal['csv','zeek']
    content:str


@app.get('/api/health')
def health():return {'status':'ok','version':'2.0.0','mode':'local-lab','live_firewall':False}


@app.post('/api/auth/login')
def login(payload:Login,request:Request,svc:AccessService=Depends(service)):
    ip=request.client.host if request.client else 'unknown'
    guard_login(ip)
    try:
        uid=svc.login(payload.username,payload.password)
    except PermissionError:
        failed_login(ip)
        raise HTTPException(status_code=401,detail='Sai tên đăng nhập hoặc mật khẩu')
    successful_login(ip)
    response=JSONResponse({'ok':True})
    response.set_cookie('af_session',create_session(uid,ROOT),httponly=True,samesite='strict',secure=False,path='/',max_age=8*3600)
    return response


@app.post('/api/auth/logout')
def logout():
    result=JSONResponse({'ok':True})
    result.delete_cookie('af_session',path='/')
    return result


@app.get('/api/auth/me')
def me(user=Depends(actor)):
    return {k:user[k] for k in ('id','username','display_name','business_role','system_role','source_ip','active')}


@app.get('/api/state')
def state(user=Depends(actor),svc:AccessService=Depends(service)):
    manager=user['system_role'] in ('ADMIN','APPROVER')
    admin=user['system_role']=='ADMIN'
    allreq=enriched_requests(svc.db)
    requests=allreq if manager else [r for r in allreq if r['requester_id']==user['id']]
    grants=svc.active_access()
    usergrants=grants if manager else [x for x in grants if x['requester_id']==user['id']]
    assets=svc.list('assets')
    services=svc.inventory()
    rules=rules_from_grants(grants)
    monitor=analyze_traffic(svc,rules) if manager else {'total':0,'without_alert':0,'alerts':[],'note':'Giám sát chỉ dành cho quản lý'}
    events=svc.list('audit_events') if manager else [e for e in svc.list('audit_events') if e['actor_id']==user['id']]
    allusers=svc.list('users')
    users=allusers if manager else [u for u in allusers if u['id']==user['id']]
    pending=len([r for r in allreq if r['status']=='PENDING']) if manager else len([r for r in requests if r['status']=='PENDING'])
    return {'actor':{k:user[k] for k in ('id','username','display_name','business_role','system_role','source_ip')},
            'summary':{'users':len(allusers),'assets':len(assets),'services':len(services),
                       'pending':pending,'active_grants':len(grants) if manager else len(usergrants),
                       'generated_rules':len(rules),'alerts':len(monitor['alerts'])},
            'users':users,'assets':assets,'services':services,
            'entitlements':svc.list('entitlements'), 'requests':requests,'grants':usergrants,
            'rules': [r.to_dict() for r in rules] if manager else [r.to_dict() for r in rules if any(k in r.provenance for k in [g['request_id'] for g in usergrants])],
            'events':events[:100] if manager else events[:50],
            'traffic':svc.list('traffic')[:100] if manager else [],
            'monitor':monitor,
            'insights':insights(svc,requests,usergrants,monitor['alerts'],assets)}


@app.post('/api/users')
def add_user(p:UserIn,user=Depends(needs('ADMIN')),svc:AccessService=Depends(service)):
    return {'id':svc.add_user(user['id'],p.username,p.password,p.display_name,p.business_role,p.system_role,p.source_ip)}


@app.post('/api/assets')
def add_asset(p:AssetIn,user=Depends(needs('ADMIN')),svc:AccessService=Depends(service)):
    return {'id':svc.add_asset(user['id'],p.name,p.ip,p.department,p.sensitivity,p.owner)}


@app.post('/api/services')
def add_service(p:ServiceIn,user=Depends(needs('ADMIN')),svc:AccessService=Depends(service)):
    return {'id':svc.add_service(user['id'],p.asset_id,p.name,p.protocol,p.port)}


@app.post('/api/entitlements')
def add_entitlement(p:EntitlementIn,user=Depends(needs('ADMIN')),svc:AccessService=Depends(service)):
    svc.grant_entitlement(user['id'],p.business_role,p.service_id)
    return {'ok':True}


@app.delete('/api/entitlements')
def remove_entitlement(p:EntitlementIn,user=Depends(needs('ADMIN')),svc:AccessService=Depends(service)):
    svc.remove_entitlement(user['id'],p.business_role,p.service_id)
    return {'ok':True}


@app.post('/api/requests')
def submit_request(p:RequestIn,user=Depends(actor),svc:AccessService=Depends(service)):
    expiry=(datetime.now(timezone.utc)+timedelta(days=p.days)).isoformat(timespec='seconds')
    return {'id':svc.request_access(user['id'],p.service_id,p.purpose,expiry)}


def preview_result(svc:AccessService,request_id:int,actor_id:int,mode:str):
    req=next((x for x in enriched_requests(svc.db) if x['id']==request_id),None)
    if req is None:raise HTTPException(status_code=404,detail='Không tìm thấy phiếu')
    grants=svc.active_access()
    before=rules_from_grants(grants)
    eligible=approval_check(svc,req)
    if mode=='approve':
        if req['requester_id']==actor_id:eligible={'eligible':False,'reason':'Không được tự duyệt yêu cầu của mình'}
        if not eligible['eligible']:
            return {'eligible':False,'reason':eligible['reason'],'mode':mode}
        u=next(x for x in svc.list('users') if x['id']==req['requester_id'])
        fake={'request_id':req['id'],'source_ip':u['source_ip'],'dst_ip':req['destination_ip'],
              'protocol':req['protocol'],'port':req['port']}
        after=rules_from_grants(grants+[fake])
    else:
        eligible={'eligible':any(x['request_id']==request_id for x in grants),'reason':'Quyền đang có hiệu lực' if any(x['request_id']==request_id for x in grants) else 'Phiếu chưa có quyền đang hiệu lực để thu hồi'}
        if not eligible['eligible']:return {'eligible':False,'reason':eligible['reason'],'mode':mode}
        after=rules_from_grants([x for x in grants if x['request_id']!=request_id])
    impact=comparison(before,after)
    return {'eligible':True,'reason':eligible['reason'],'mode':mode,'request_id':request_id,
            'before_rules':len(before),'after_rules':len(after),'impact':impact,
            'after_policy':export_policy(after),
            'note':'So sánh chính xác trong mô hình IPv4 stateless nếu complete=true. Số cells không phải số packet. Không tự triển khai firewall.'}


@app.get('/api/requests/{request_id}/preview')
def preview_request(request_id:int,mode:Literal['approve','revoke']='approve',user=Depends(needs('ADMIN','APPROVER')),svc:AccessService=Depends(service)):
    return preview_result(svc,request_id,user['id'],mode)


@app.post('/api/requests/{request_id}/decision')
def decide_request(request_id:int,p:DecisionIn,user=Depends(needs('ADMIN','APPROVER')),svc:AccessService=Depends(service)):
    svc.decide(user['id'],request_id,p.approve,p.reason)
    return {'ok':True}


@app.post('/api/requests/{request_id}/revoke')
def revoke_request(request_id:int,p:RevokeIn,user=Depends(needs('ADMIN','APPROVER')),svc:AccessService=Depends(service)):
    svc.revoke_request(user['id'],request_id,p.reason)
    return {'ok':True}


@app.patch('/api/users/{target_id}')
def update_user(target_id:int,p:UserChange,user=Depends(needs('ADMIN')),svc:AccessService=Depends(service)):
    return {'revoked':svc.change_user(user['id'],target_id,business_role=p.business_role,source_ip=p.source_ip,active=p.active)}


@app.post('/api/assets/{asset_id}/disable')
def disable_asset(asset_id:int,user=Depends(needs('ADMIN')),svc:AccessService=Depends(service)):
    return {'revoked':svc.disable_asset(user['id'],asset_id)}


@app.post('/api/lifecycle/expire')
def expire(user=Depends(needs('ADMIN','APPROVER')),svc:AccessService=Depends(service)):
    return {'expired':svc.expire_due(user['id'])}


@app.post('/api/auth/password')
def password(p:PasswordChange,user=Depends(actor),svc:AccessService=Depends(service)):
    svc.change_password(user['id'],p.current_password,p.new_password)
    return {'ok':True}


@app.post('/api/policy/simulate')
def simulate(p:Simulate,user=Depends(actor),svc:AccessService=Depends(service)):
    packet=Packet(p.source,p.destination,p.protocol,None if p.protocol=='ICMP' else p.port)
    return {'packet':packet.to_dict(),'decision':trace_decision(rules_from_grants(svc.active_access()),packet)}


@app.get('/api/policy/audit')
def audit(user=Depends(needs('ADMIN','APPROVER')),svc:AccessService=Depends(service)):
    rules=rules_from_grants(svc.active_access())
    baseline=audit_policy(rules,rules)
    return {'baseline':baseline,'rule_analysis':analyze_rules(rules),
            'note':'Baseline đối chiếu cùng nguồn quyền đã duyệt: chỉ kiểm tra tính nhất quán của bộ sinh luật, KHÔNG là chứng nhận chính sách thực tế an toàn. Dùng what-if để kiểm chứng chính sách ứng viên độc lập.'}


@app.post('/api/policy/whatif')
def whatif(p:Candidate,user=Depends(needs('ADMIN','APPROVER')),svc:AccessService=Depends(service)):
    candidate=parse_policy(p.policy)
    baseline=rules_from_grants(svc.active_access())
    return {'audit':audit_policy(candidate,baseline),'impact':comparison(baseline,candidate),
            'analysis':analyze_rules(candidate),'candidate_rules':len(candidate),'baseline_rules':len(baseline)}


@app.get('/api/policy/export/{format}')
def export_policy_file(format:Literal['json','nft'],user=Depends(needs('ADMIN','APPROVER')),svc:AccessService=Depends(service)):
    rules=rules_from_grants(svc.active_access())
    if format=='json':
        return Response(json.dumps(export_policy(rules),ensure_ascii=False,indent=2),media_type='application/json',
                        headers={'Content-Disposition':'attachment; filename="accessflow_policy.json"'})
    return Response(NftablesLabDraftExporter().render(rules),media_type='text/plain; charset=utf-8',
                    headers={'Content-Disposition':'attachment; filename="accessflow_lab_draft.nft"'})


@app.post('/api/monitor/import')
def monitor_import(p:TrafficImport,user=Depends(needs('ADMIN','APPROVER')),svc:AccessService=Depends(service)):
    return import_traffic(svc,user['id'],p.content,p.format)


@app.get('/api/report/{format}')
def report(format:Literal['json','md'],user=Depends(needs('ADMIN','APPROVER')),svc:AccessService=Depends(service)):
    data=make_report(svc)
    if format=='json':return Response(json.dumps(data,ensure_ascii=False,indent=2),media_type='application/json',
        headers={'Content-Disposition':'attachment; filename="accessflow_audit.json"'})
    return Response(markdown_report(data),media_type='text/markdown; charset=utf-8',
        headers={'Content-Disposition':'attachment; filename="accessflow_audit.md"'})


app.mount('/static',StaticFiles(directory=WEB),name='static')


@app.get('/')
def home():return FileResponse(WEB/'index.html')


@app.get('/{any_path:path}',include_in_schema=False)
def spa(any_path:str):
    if any_path.startswith('api/'):raise HTTPException(status_code=404,detail='API endpoint không tồn tại')
    return FileResponse(WEB/'index.html')
