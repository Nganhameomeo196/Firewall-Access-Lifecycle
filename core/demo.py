"""Disposably seeded lab accounts and plausible IT service inventory.

Demo identities are NEVER suitable for deployment; each password is documented
so the user can exercise the roles locally. No external services are contacted.
"""
from __future__ import annotations
from datetime import datetime,timedelta,timezone
from core.database import transaction,event,utc_now,query
from core.security import hash_password
from core.workflow import AccessService

DEMO_PASSWORD='Demo@2026!'


def seed_demo(svc:AccessService):
    if query(svc.db,'SELECT id FROM users LIMIT 1'):
        return False
    now=datetime.now(timezone.utc)
    with transaction(svc.db) as c:
        accounts=[
          ('admin','Quản trị hệ thống','IT','ADMIN','10.10.99.10'),
          ('approver','Quản lý CNTT','IT','APPROVER','10.10.99.11'),
          ('linh','Nhân viên kế toán','ACCOUNTING','EMPLOYEE','10.10.10.10'),
          ('mai','Nhân viên nhân sự','HR','EMPLOYEE','10.10.20.10'),
          ('nam','Nhân viên kinh doanh','SALES','EMPLOYEE','10.10.30.10'),
          ('quang','Kế toán trưởng','ACCOUNTING','EMPLOYEE','10.10.10.11')]
        users={}
        for username,display,biz,role,source in accounts:
            obj=c.execute('INSERT INTO users (username,password_hash,display_name,business_role,system_role,source_ip,created_at) VALUES (?,?,?,?,?,?,?)',
               (username,hash_password(DEMO_PASSWORD),display,biz,role,source,utc_now()))
            users[username]=obj.lastrowid
        assets={}
        for name,ip,dept,level,owner in [
            ('Accounting Application','10.20.1.10','Finance','HIGH','Kế toán'),
            ('HR Application','10.20.1.20','HR','HIGH','Nhân sự'),
            ('Internal Portal','10.20.1.30','IT','MEDIUM','CNTT'),
            ('Finance Database','10.20.2.10','Finance','HIGH','Kế toán'),
            ('Internal DNS','10.20.3.53','IT','MEDIUM','CNTT')]:
            obj=c.execute('INSERT INTO assets (name,ip,department,sensitivity,owner) VALUES (?,?,?,?,?)',
                          (name,ip,dept,level,owner));assets[name]=obj.lastrowid
        services={}
        for asset,name,proto,port in [
            ('Accounting Application','HTTPS','TCP',443),('HR Application','HTTPS','TCP',443),
            ('Internal Portal','HTTPS','TCP',443),('Finance Database','PostgreSQL','TCP',5432),
            ('Internal DNS','DNS','UDP',53)]:
            obj=c.execute('INSERT INTO services (asset_id,name,protocol,port) VALUES (?,?,?,?)',
                          (assets[asset],name,proto,port));services[asset]=obj.lastrowid
        for biz,asset in [('ACCOUNTING','Accounting Application'),('ACCOUNTING','Internal Portal'),
                          ('HR','HR Application'),('HR','Internal Portal'),('SALES','Internal Portal'),
                          ('IT','Internal Portal'),('IT','Internal DNS')]:
            c.execute('INSERT INTO entitlements (business_role,service_id) VALUES (?,?)',(biz,services[asset]))
        # Seed a realistic history: three approved, two pending, each traceable.
        rows=[
            ('linh','Accounting Application', 'Dùng hệ thống kế toán theo công việc', 'APPROVED',14),
            ('mai','HR Application','Duyệt hồ sơ nhân sự','APPROVED',7),
            ('nam','Internal Portal','Tra cứu thông báo nội bộ','APPROVED',21),
            ('quang','Accounting Application','Truy cập tạm ứng dụng kế toán','PENDING',2),
            ('linh','Finance Database','Muốn truy cập trực tiếp DB để lập báo cáo','PENDING',4)]
        for user,asset,purpose,status,days in rows:
            expiry=(now+timedelta(days=days)).isoformat(timespec='seconds')
            c.execute('''INSERT INTO requests (requester_id,service_id,purpose,status,requested_at,expires_at,decided_by,decided_at,decision_reason)
                     VALUES (?,?,?,?,?,?,?,?,?)''',
                     (users[user],services[asset],purpose,status,utc_now(),expiry,
                      users['approver'] if status=='APPROVED' else None,
                      utc_now() if status=='APPROVED' else None,
                      'Đã xác minh quyền theo vai trò và nhu cầu nghiệp vụ' if status=='APPROVED' else ''))
        event(c,users['admin'],'DEMO_SEEDED','database',None,
              {'note':'Tài khoản và IP/dịch vụ chỉ dành cho môi trường lab; không phải mạng thật'})
    return True
