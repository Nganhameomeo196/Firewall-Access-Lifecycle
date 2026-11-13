"""Explainable, non-ML audit insights derived from actual app state."""
from __future__ import annotations
from datetime import datetime,timezone,timedelta
from core.database import query


def enriched_requests(db):
    return query(db, '''SELECT r.*,u.username,u.display_name AS requester_name,u.business_role,
      s.name AS service_name,s.protocol,s.port, a.name AS asset_name,a.ip AS destination_ip,
      a.sensitivity, a.active AS asset_active
      FROM requests r JOIN users u ON r.requester_id=u.id
      JOIN services s ON r.service_id=s.id JOIN assets a ON s.asset_id=a.id
      ORDER BY r.id DESC''')


def insights(svc,requests,grants,alerts,assets):
    now=datetime.now(timezone.utc)
    end=(now+timedelta(hours=72)).isoformat(timespec='seconds')
    expiring=[x for x in grants if x['expires_at']<=end]
    pending=[x for x in requests if x['status']=='PENDING']
    high=[x for x in grants if x['sensitivity']=='HIGH']
    results=[]
    if pending:
        results.append({'id':'pending','severity':'info','title':f'{len(pending)} yêu cầu đang chờ phê duyệt',
            'description':'Các phiếu chưa tạo luật firewall. Kiểm tra vai trò, mục đích và thời hạn trước khi quyết định.', 'target':'requests'})
    if expiring:
        results.append({'id':'expiring','severity':'warning','title':f'{len(expiring)} quyền sắp hết hạn trong 72 giờ',
            'description':'Khi hết hạn, luật tương ứng không còn được sinh. Kiểm tra các dịch vụ có thể bị ảnh hưởng.', 'target':'lifecycle'})
    if alerts:
        results.append({'id':'traffic','severity':'danger','title':f'{len(alerts)} log kết nối cần rà soát',
            'description':'Kết quả đối chiếu log với quyền hiện hành; điểm quan sát không thay thế log quyết định firewall.', 'target':'monitoring'})
    if high:
        results.append({'id':'high','severity':'info','title':f'{len(high)} quyền đang cấp tới tài nguyên nhạy cảm cao',
            'description':'Đây không mặc định là sai; hãy đánh giá mục đích và tính cần thiết của các quyền này.', 'target':'lifecycle'})
    if not results:
        results.append({'id':'clear','severity':'success','title':'Chưa phát hiện mục cần ưu tiên rà soát',
            'description':'Không đồng nghĩa môi trường mạng thực tế đã an toàn. Hệ thống chỉ phân tích dữ liệu đang có.', 'target':'overview'})
    return results


def approval_check(svc,req):
    if req['status']!='PENDING':return {'eligible':False,'reason':'Phiếu không ở trạng thái chờ duyệt'}
    if req['requester_id']==req.get('reviewer_id') and req.get('reviewer_id') is not None:
        return {'eligible':False,'reason':'Không được tự phê duyệt'}
    now=datetime.now(timezone.utc).isoformat(timespec='seconds')
    if req['expires_at']<=now:return {'eligible':False,'reason':'Phiếu đã hết thời hạn'}
    user=next((u for u in svc.list('users') if u['id']==req['requester_id']),None)
    if not user or not user['active']:return {'eligible':False,'reason':'Tài khoản yêu cầu không hoạt động'}
    inv=next((s for s in svc.inventory() if s['id']==req['service_id']),None)
    if not inv or not inv['service_active'] or not inv['asset_active']:
        return {'eligible':False,'reason':'Dịch vụ hoặc tài nguyên đã bị vô hiệu hóa'}
    if not any(e['business_role']==user['business_role'] and e['service_id']==req['service_id'] for e in svc.list('entitlements')):
        return {'eligible':False,'reason':'Vai trò chưa có quyền chuẩn để xin dịch vụ này'}
    return {'eligible':True,'reason':'Đạt kiểm tra vai trò, tài nguyên và thời hạn; vẫn cần người có thẩm quyền phê duyệt'}
