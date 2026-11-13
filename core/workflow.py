"""Access-control request lifecycle: resources, roles, approval and revocation.

All mutations enforce system-role authorization at the service layer, not only in UI.
An approved business-role entitlement does NOT automatically grant network access;
a separately approved, time-limited request is required.
"""
from __future__ import annotations
from datetime import datetime, timezone, timedelta
from pathlib import Path
from ipaddress import ip_address
from core.database import connect,transaction,event,utc_now,query,initialize
from core.security import hash_password,verify_password,ipv4,role_check


class WorkflowError(ValueError):pass


def iso_utc(v: str) -> str:
    """Parse timestamp with timezone; normalize to comparable UTC ISO seconds."""
    d=datetime.fromisoformat(v.replace('Z','+00:00'))
    if d.tzinfo is None: raise WorkflowError('Thời điểm phải chứa múi giờ (ví dụ +00:00)')
    return d.astimezone(timezone.utc).isoformat(timespec='seconds')


class AccessService:
    def __init__(self, database: str | Path):
        self.db=Path(database)
        initialize(self.db)

    def list(self, table):
        allowed={'users','assets','services','entitlements','requests','traffic','audit_events'}
        if table not in allowed:raise ValueError('Bảng không hợp lệ')
        if table=='users':
            return query(self.db,'SELECT id,username,display_name,business_role,system_role,source_ip,active,created_at FROM users ORDER BY id DESC')
        return query(self.db,f'SELECT * FROM {table} ORDER BY id DESC')

    def actor(self, uid):
        rows=query(self.db,'SELECT * FROM users WHERE id=?',(uid,))
        if not rows:raise PermissionError('Tài khoản không tồn tại')
        return rows[0]

    def login(self, username, password):
        rows=query(self.db,'SELECT * FROM users WHERE username=? AND active=1',(username,))
        if not rows or not verify_password(password,rows[0]['password_hash']):
            raise PermissionError('Sai tài khoản hoặc mật khẩu')
        return rows[0]['id']

    def add_user(self, actor_id, username, password, name, business_role, system_role, source_ip):
        role_check(self.actor(actor_id),'ADMIN')
        if system_role not in ('EMPLOYEE','APPROVER','ADMIN'):raise WorkflowError('system_role không hợp lệ')
        if not username.strip() or not business_role.strip() or not name.strip():raise WorkflowError('Thiếu thông tin người dùng')
        source_ip=ipv4(source_ip)
        with transaction(self.db) as c:
            res=c.execute('INSERT INTO users (username,password_hash,display_name,business_role,system_role,source_ip,created_at) VALUES (?,?,?,?,?,?,?)',
                (username.strip(),hash_password(password),name.strip(),business_role.strip().upper(),system_role,source_ip,utc_now()))
            event(c,actor_id,'USER_CREATED','user',res.lastrowid,{'username':username,'business_role':business_role})
        return res.lastrowid

    def change_password(self, actor_id, old_password, new_password):
        actor=self.actor(actor_id)
        if not verify_password(old_password,actor['password_hash']):raise PermissionError('Mật khẩu cũ không đúng')
        with transaction(self.db) as c:
            c.execute('UPDATE users SET password_hash=? WHERE id=?',(hash_password(new_password),actor_id))
            event(c,actor_id,'PASSWORD_CHANGED','user',actor_id)

    def add_asset(self, actor_id, name, ip, department, sensitivity, owner):
        role_check(self.actor(actor_id),'ADMIN')
        if sensitivity not in ('LOW','MEDIUM','HIGH'):raise WorkflowError('sensitivity không hợp lệ')
        if not all(map(str.strip,[name,department,owner])):raise WorkflowError('Thiếu thông tin tài nguyên')
        with transaction(self.db) as c:
            x=c.execute('INSERT INTO assets(name,ip,department,sensitivity,owner) VALUES(?,?,?,?,?)',
                (name.strip(),ipv4(ip),department.strip(),sensitivity,owner.strip()))
            event(c,actor_id,'ASSET_CREATED','asset',x.lastrowid,{'name':name,'ip':ip})
            return x.lastrowid

    def add_service(self, actor_id, asset_id, name, protocol, port):
        role_check(self.actor(actor_id),'ADMIN')
        protocol=protocol.upper()
        if protocol not in ('TCP','UDP') or not (1<=int(port)<=65535):raise WorkflowError('Protocol/port không hợp lệ')
        if not name.strip():raise WorkflowError('Tên dịch vụ không được trống')
        with transaction(self.db) as c:
            if not c.execute('SELECT id FROM assets WHERE id=? AND active=1',(asset_id,)).fetchone():raise WorkflowError('Asset không tồn tại/đã tắt')
            x=c.execute('INSERT INTO services (asset_id,name,protocol,port) VALUES (?,?,?,?)',(asset_id,name.strip(),protocol,int(port)))
            event(c,actor_id,'SERVICE_CREATED','service',x.lastrowid,{'asset_id':asset_id,'name':name})
            return x.lastrowid

    def grant_entitlement(self, actor_id, business_role, service_id):
        role_check(self.actor(actor_id),'ADMIN')
        business_role=business_role.strip().upper()
        with transaction(self.db) as c:
            if not c.execute('SELECT id FROM services WHERE id=?',(service_id,)).fetchone():raise WorkflowError('Service không tồn tại')
            c.execute('INSERT OR IGNORE INTO entitlements(business_role,service_id) VALUES(?,?)',(business_role,service_id))
            event(c,actor_id,'ENTITLEMENT_GRANTED','entitlement',None,{'business_role':business_role,'service_id':service_id})

    def remove_entitlement(self, actor_id, business_role, service_id):
        role_check(self.actor(actor_id),'ADMIN')
        with transaction(self.db) as c:
            c.execute('DELETE FROM entitlements WHERE business_role=? AND service_id=?',(business_role.upper(),service_id))
            changed=c.execute('''UPDATE requests SET status='REVOKED',decided_by=?,decided_at=?,decision_reason='Role entitlement removed'
                WHERE status='APPROVED' AND service_id=? AND requester_id IN
                (SELECT id FROM users WHERE business_role=?)''',(actor_id,utc_now(),service_id,business_role.upper())).rowcount
            event(c,actor_id,'ENTITLEMENT_REMOVED','entitlement',None,{'role':business_role,'service_id':service_id,'revoked':changed})

    def request_access(self, actor_id, service_id, purpose, expires_at):
        actor=self.actor(actor_id)
        role_check(actor,'EMPLOYEE','APPROVER','ADMIN')
        if not purpose.strip():raise WorkflowError('Mục đích cấp quyền không được trống')
        exp=iso_utc(expires_at)
        if exp <= utc_now():raise WorkflowError('Thời điểm hết hạn phải nằm trong tương lai')
        with transaction(self.db) as c:
            s=c.execute('''SELECT s.id FROM services s JOIN assets a ON a.id=s.asset_id
                                   WHERE s.id=? AND s.active=1 AND a.active=1''',(service_id,)).fetchone()
            if not s:raise WorkflowError('Dịch vụ không tồn tại hoặc đã tắt')
            x=c.execute("INSERT INTO requests(requester_id,service_id,purpose,status,requested_at,expires_at) VALUES(?,?,?,'PENDING',?,?)",
                        (actor_id,service_id,purpose.strip(),utc_now(),exp))
            event(c,actor_id,'REQUEST_SUBMITTED','request',x.lastrowid,{'service_id':service_id,'expires_at':exp})
            return x.lastrowid

    def decide(self, actor_id, request_id, approve: bool, reason: str):
        actor=self.actor(actor_id);role_check(actor,'ADMIN','APPROVER')
        if not reason.strip():raise WorkflowError('Cần ghi lý do phê duyệt/từ chối')
        with transaction(self.db) as c:
            req=c.execute('SELECT * FROM requests WHERE id=?',(request_id,)).fetchone()
            if req is None or req['status']!='PENDING':raise WorkflowError('Yêu cầu không tồn tại hoặc không còn chờ duyệt')
            if req['requester_id']==actor_id:raise PermissionError('Không được tự duyệt yêu cầu của mình')
            if iso_utc(req['expires_at'])<=utc_now():raise WorkflowError('Yêu cầu đã quá thời hạn')
            user=c.execute('SELECT * FROM users WHERE id=?',(req['requester_id'],)).fetchone()
            if not user or not user['active']:raise WorkflowError('Người yêu cầu đã bị vô hiệu hóa')
            service=c.execute('''SELECT s.id FROM services s JOIN assets a ON s.asset_id=a.id
                                  WHERE s.id=? AND s.active=1 AND a.active=1''',(req['service_id'],)).fetchone()
            if not service:raise WorkflowError('Dịch vụ không còn hoạt động')
            if approve and not c.execute('SELECT 1 FROM entitlements WHERE business_role=? AND service_id=?',
                    (user['business_role'],req['service_id'])).fetchone():
                raise PermissionError('Vai trò nghiệp vụ không được cấp quyền tới dịch vụ; quản trị viên phải định nghĩa entitlement trước')
            status='APPROVED' if approve else 'REJECTED'
            c.execute('UPDATE requests SET status=?,decided_by=?,decided_at=?,decision_reason=? WHERE id=?',
                (status,actor_id,utc_now(),reason.strip(),request_id))
            event(c,actor_id,'REQUEST_'+status,'request',request_id,{'reason':reason.strip(),'requester_id':req['requester_id']})

    def revoke_request(self, actor_id, request_id, reason):
        actor=self.actor(actor_id);role_check(actor,'ADMIN','APPROVER')
        if not reason.strip():raise WorkflowError('Phải nêu lý do thu hồi')
        with transaction(self.db) as c:
            x=c.execute("UPDATE requests SET status='REVOKED',decided_by=?,decided_at=?,decision_reason=? WHERE id=? AND status='APPROVED'",
                        (actor_id,utc_now(),reason.strip(),request_id))
            if not x.rowcount:raise WorkflowError('Không tìm thấy quyền APPROVED để thu hồi')
            event(c,actor_id,'REQUEST_REVOKED','request',request_id,{'reason':reason})

    def change_user(self, actor_id, target_id, *, business_role=None, source_ip=None, active=None):
        role_check(self.actor(actor_id),'ADMIN')
        if actor_id==target_id and active is False:raise WorkflowError('Không thể tự vô hiệu hóa tài khoản admin đang dùng')
        with transaction(self.db) as c:
            user=c.execute('SELECT * FROM users WHERE id=?',(target_id,)).fetchone()
            if not user:raise WorkflowError('User không tồn tại')
            changes={}
            if business_role is not None and business_role.strip().upper()!=user['business_role']:changes['business_role']=business_role.strip().upper()
            if source_ip is not None and ipv4(source_ip)!=user['source_ip']:changes['source_ip']=ipv4(source_ip)
            if active is not None and int(active)!=user['active']:changes['active']=int(active)
            if not changes:return 0
            for name,value in changes.items():c.execute(f'UPDATE users SET {name}=? WHERE id=?',(value,target_id))
            revoked=0
            if 'business_role' in changes or 'source_ip' in changes or changes.get('active')==0:
                revoked=c.execute("UPDATE requests SET status='REVOKED',decided_by=?,decided_at=?,decision_reason='Identity/role change' WHERE requester_id=? AND status='APPROVED'",
                        (actor_id,utc_now(),target_id)).rowcount
            event(c,actor_id,'USER_CHANGED','user',target_id,{'changes':changes,'revoked_requests':revoked})
            return revoked

    def disable_asset(self, actor_id, asset_id):
        role_check(self.actor(actor_id),'ADMIN')
        with transaction(self.db) as c:
            c.execute('UPDATE assets SET active=0 WHERE id=?',(asset_id,))
            count=c.execute("UPDATE requests SET status='REVOKED',decided_by=?,decided_at=?,decision_reason='Asset disabled' WHERE status='APPROVED' AND service_id IN (SELECT id FROM services WHERE asset_id=?)",
                (actor_id,utc_now(),asset_id)).rowcount
            event(c,actor_id,'ASSET_DISABLED','asset',asset_id,{'revoked':count})
            return count

    def expire_due(self, actor_id, at=None):
        role_check(self.actor(actor_id),'ADMIN','APPROVER')
        now=iso_utc(at) if at else utc_now()
        with transaction(self.db) as c:
            rows=c.execute("SELECT id FROM requests WHERE status='APPROVED' AND expires_at<=?",(now,)).fetchall()
            for row in rows:
                c.execute("UPDATE requests SET status='EXPIRED',decided_at=?,decided_by=?,decision_reason='Automatic time expiry' WHERE id=?",(now,actor_id,row['id']))
                event(c,actor_id,'REQUEST_EXPIRED','request',row['id'])
            return len(rows)

    def active_access(self, at=None):
        now=iso_utc(at) if at else utc_now()
        return query(self.db,'''SELECT r.id as request_id,r.requester_id,u.username,u.source_ip,u.business_role,
             r.expires_at,r.purpose,s.id as service_id,s.name as service_name,s.protocol,s.port,
             a.id as asset_id,a.name as asset_name,a.ip as dst_ip,a.sensitivity
             FROM requests r JOIN users u ON r.requester_id=u.id
             JOIN services s ON r.service_id=s.id JOIN assets a ON s.asset_id=a.id
             JOIN entitlements e ON e.business_role=u.business_role AND e.service_id=s.id
             WHERE r.status='APPROVED' AND r.expires_at>? AND u.active=1 AND s.active=1 AND a.active=1
             ORDER BY r.id''',(now,))

    def pending(self):
        return query(self.db,"""SELECT r.id,r.purpose,r.status,r.expires_at,u.username,u.business_role,
            s.name AS service_name,a.name AS asset_name FROM requests r
            JOIN users u ON r.requester_id=u.id JOIN services s ON r.service_id=s.id
            JOIN assets a ON s.asset_id=a.id WHERE r.status='PENDING' ORDER BY r.id DESC""")

    def inventory(self):
        return query(self.db,'''SELECT s.id,s.name AS service,s.protocol,s.port,s.active as service_active,
             a.name AS asset,a.ip AS dst_ip,a.sensitivity,a.department,a.active AS asset_active
             FROM services s JOIN assets a ON a.id=s.asset_id ORDER BY a.name,s.port''')

    def reset_demo(self):
        """Explicit destructive reset; never called from the application."""
        raise NotImplementedError('Để đặt lại dữ liệu demo: tắt ứng dụng, xóa file SQLite và chạy seed lại.')
