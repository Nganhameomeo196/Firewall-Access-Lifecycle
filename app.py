"""Local Streamlit application for six access-lifecycle workflows.

This is a lab app; session login is not a production security boundary.
Service-layer mutations still enforce actor system roles.
"""
from __future__ import annotations
from pathlib import Path
from datetime import datetime,timezone,timedelta
import json
import sqlite3
import streamlit as st
from core.workflow import AccessService,iso_utc
from core.demo import seed_demo
from core.policy import rules_from_grants,Packet,trace_decision,export_policy,parse_policy
from core.auditor import audit_policy,analyze_rules,comparison
from core.monitoring import import_traffic,analyze_traffic
from core.reports import make_report,markdown_report
from core.exporters import NftablesLabDraftExporter

ROOT=Path(__file__).resolve().parent
DB=ROOT/'runtime'/'access.sqlite3'
svc=AccessService(DB)
seed_demo(svc)
st.set_page_config(page_title='AccessFlow Firewall',page_icon='🛡️',layout='wide')
st.title('🛡️ AccessFlow — Quản lý vòng đời quyền truy cập mạng')
st.caption('6 chức năng liên kết • SQLite • RBAC nghiệp vụ • Firewall first-match • Audit có witness • Lab cục bộ')


def run_action(fn,*args,**kwargs):
    try:
        result=fn(*args,**kwargs)
        st.success('Thao tác thành công.')
        if result is not None:st.info(f'Kết quả: {result}')
        st.rerun()
    except (ValueError,PermissionError,sqlite3.Error,TypeError) as exc:
        st.error(f'Không thể thực hiện: {exc}')


def rows_table(rows,empty='Chưa có dữ liệu'):
    if rows:st.dataframe(rows,use_container_width=True,hide_index=True)
    else:st.info(empty)


def select_from(items,title,key,display):
    if not items:
        st.info('Chưa có lựa chọn khả dụng')
        return None
    by_id={x['id']:x for x in items}
    value=st.selectbox(title,list(by_id),key=key,format_func=lambda i:display(by_id[i]))
    return value


if 'actor_id' not in st.session_state:
    st.session_state.actor_id=None
if st.session_state.actor_id is None:
    st.info('Đăng nhập bằng tài khoản demo cục bộ. Mật khẩu được mô tả trong README; hãy đổi khi thử nghiệm.')
    with st.form('login'):
        username=st.text_input('Tên đăng nhập',value='admin')
        password=st.text_input('Mật khẩu',type='password')
        submit=st.form_submit_button('Đăng nhập',type='primary')
    if submit:
        try:
            st.session_state.actor_id=svc.login(username,password)
            st.rerun()
        except PermissionError as exc:st.error(str(exc))
    st.stop()

try:
    actor=svc.actor(st.session_state.actor_id)
    if not actor['active']:raise PermissionError('Account inactive')
except PermissionError:
    st.session_state.actor_id=None;st.rerun()
uid=actor['id']
admin=actor['system_role']=='ADMIN'
manager=actor['system_role'] in ('ADMIN','APPROVER')

with st.sidebar:
    st.success(f"{actor['display_name']} · {actor['system_role']}")
    st.caption(f"Vai trò nghiệp vụ: {actor['business_role']} · IP: {actor['source_ip']}")
    if st.button('Đăng xuất'):
        st.session_state.actor_id=None;st.rerun()
    page=st.radio('Các phân hệ',[
      '1. Tài nguyên & người dùng','2. Vai trò & quyền chuẩn','3. Yêu cầu & phê duyệt',
      '4. Sinh luật & kiểm toán','5. Giám sát truy cập','6. Vòng đời & nhật ký'])
    st.caption('Không cấu hình/chặn gói tin thật. Muốn thử firewall thực cần lab được phép và cơ chế rollback.')

users=[{k:v for k,v in row.items() if k!='password_hash'} for row in svc.list('users')]
assets=svc.list('assets')
services=svc.inventory()
requests=svc.list('requests')
grants=svc.active_access()
rules=rules_from_grants(grants)

a,b,c,d=st.columns(4)
a.metric('Người dùng',len(users));b.metric('Tài nguyên',len(assets));c.metric('Yêu cầu chờ duyệt',len([r for r in requests if r['status']=='PENDING']));d.metric('Quyền còn hiệu lực',len(grants))

if page.startswith('1.'):
    st.header('1. Quản lý tài nguyên mạng và danh tính')
    st.write('Nguồn sự thật về tài nguyên, người dùng, IP thiết bị, dịch vụ và người chịu trách nhiệm.')
    st.subheader('Máy chủ và dịch vụ')
    rows_table(services)
    st.subheader('Danh sách người dùng')
    rows_table(users)
    if admin:
        with st.expander('➕ Thêm người dùng',expanded=False):
            with st.form('add_user'):
                x,y=st.columns(2)
                username=x.text_input('Username');display=y.text_input('Họ tên')
                password=x.text_input('Mật khẩu (≥10 ký tự)',type='password')
                source_ip=y.text_input('IPv4 thiết bị',value='10.10.40.10')
                biz=x.text_input('Vai trò nghiệp vụ',value='SALES')
                sysrole=y.selectbox('Vai trò hệ thống',['EMPLOYEE','APPROVER','ADMIN'])
                if st.form_submit_button('Tạo người dùng'):
                    run_action(svc.add_user,uid,username,password,display,biz,sysrole,source_ip)
        with st.expander('➕ Thêm máy chủ / tài nguyên'):
            with st.form('add_asset'):
                name=st.text_input('Tên tài nguyên')
                x,y=st.columns(2);ip=x.text_input('IPv4',value='10.20.4.10');dept=y.text_input('Phòng ban quản lý',value='IT')
                level=st.selectbox('Độ nhạy cảm',['LOW','MEDIUM','HIGH'])
                owner=st.text_input('Chủ sở hữu',value='Phòng CNTT')
                if st.form_submit_button('Tạo tài nguyên'):run_action(svc.add_asset,uid,name,ip,dept,level,owner)
        with st.expander('➕ Thêm dịch vụ trên máy chủ'):
            with st.form('add_service'):
                asset_id=select_from(assets,'Chọn máy chủ','asset_new',lambda x:f"{x['name']} — {x['ip']}")
                name=st.text_input('Tên dịch vụ',value='HTTPS')
                x,y=st.columns(2);proto=x.selectbox('Giao thức',['TCP','UDP']);port=y.number_input('Port',1,65535,443)
                if st.form_submit_button('Tạo dịch vụ') and asset_id is not None:
                    run_action(svc.add_service,uid,asset_id,name,proto,port)

elif page.startswith('2.'):
    st.header('2. RBAC: Quyền chuẩn theo vai trò nghiệp vụ')
    st.write('Entitlement chỉ xác định **dịch vụ được phép xin truy cập**. Không tự sinh luật ALLOW cho đến khi có yêu cầu được phê duyệt.')
    ent=svc.list('entitlements');by_service={s['id']:s for s in services}
    rows_table([{'role':r['business_role'],'service_id':r['service_id'],
      'resource':by_service.get(r['service_id'],{}).get('asset','?'),
      'service':by_service.get(r['service_id'],{}).get('service','?')} for r in ent])
    if admin:
        with st.form('entitlement_add'):
            roles=sorted({u['business_role'] for u in users})
            biz=st.selectbox('Vai trò nghiệp vụ',roles)
            sid=select_from(services,'Dịch vụ được phép xin quyền','role_service',lambda x:f"{x['asset']} / {x['service']} {x['protocol']}/{x['port']}")
            if st.form_submit_button('Cấp quyền chuẩn cho vai trò') and sid:
                run_action(svc.grant_entitlement,uid,biz,sid)
        with st.expander('Thu hồi quyền chuẩn từ một vai trò'):
            if ent:
                eid=select_from(ent,'Entitlement','ent_del',lambda x:f"{x['business_role']} → service #{x['service_id']}")
                if st.button('Thu hồi entitlement và quyền liên quan',type='secondary'):
                    item=next(x for x in ent if x['id']==eid)
                    run_action(svc.remove_entitlement,uid,item['business_role'],item['service_id'])
    st.warning('Không đồng nhất vai trò nghiệp vụ với danh tính mạng. Ví dụ này gắn một IP IPv4 cố định cho mỗi tài khoản; môi trường DHCP/NAT cần tích hợp nhận diện thiết bị đáng tin cậy.')

elif page.startswith('3.'):
    st.header('3. Yêu cầu truy cập và phê duyệt')
    st.write('Người dùng gửi nhu cầu nghiệp vụ. Người có quyền duyệt kiểm tra RBAC, thời hạn và nguyên tắc tách nhiệm vụ; không ai được tự duyệt yêu cầu của chính mình.')
    available=[x for x in services if x['asset_active'] and x['service_active']]
    with st.form('request_access'):
        sid=select_from(available,'Dịch vụ muốn truy cập','request_service',lambda x:f"{x['asset']} / {x['service']} {x['protocol']}/{x['port']}")
        purpose=st.text_area('Mục đích nghiệp vụ',placeholder='Ví dụ: truy cập ứng dụng kế toán để xử lý hóa đơn')
        days=st.number_input('Hiệu lực trong bao nhiêu ngày?',min_value=1,max_value=365,value=7)
        if st.form_submit_button('Gửi yêu cầu',type='primary') and sid:
            expires=(datetime.now(timezone.utc)+timedelta(days=int(days))).isoformat(timespec='seconds')
            run_action(svc.request_access,uid,sid,purpose,expires)
    st.subheader('Yêu cầu của tôi')
    rows_table([r for r in requests if r['requester_id']==uid])
    if manager:
        st.subheader('Hàng đợi phê duyệt')
        pending=svc.pending()
        rows_table(pending)
        if pending:
            chosen=select_from(pending,'Chọn phiếu','approve_request',lambda x:f"#{x['id']} · {x['username']} · {x['asset_name']} / {x['service_name']}")
            if chosen:
                r=next(x for x in pending if x['id']==chosen)
                role=next((u['business_role'] for u in users if u['username']==r['username']),None)
                allowed=any(x['business_role']==role and x['service_id']==next((s['id'] for s in services if s['asset']==r['asset_name'] and s['service']==r['service_name']),-1) for x in svc.list('entitlements'))
                st.caption(f"RBAC preliminary check: {'Có entitlement phù hợp' if allowed else 'Chưa có entitlement phù hợp; service sẽ từ chối duyệt'}")
                with st.form('decision_form'):
                    why=st.text_input('Lý do quyết định',value='Đã xác minh yêu cầu và quyền theo vai trò')
                    action=st.radio('Quyết định',['APPROVE','REJECT'],horizontal=True)
                    if st.form_submit_button('Xác nhận quyết định'):
                        run_action(svc.decide,uid,chosen,action=='APPROVE',why)

elif page.startswith('4.'):
    st.header('4. Sinh luật tường lửa và kiểm toán chính sách')
    st.write('Firewall **không tự tạo quyền**: nó được sinh từ quyền đang có hiệu lực. Mỗi ALLOW phải truy vết được về phiếu phê duyệt và hết hạn theo phiếu.')
    st.subheader('Luật sinh tự động')
    rows_table([r.to_dict() for r in rules],empty='Chưa có quyền APPROVED còn hiệu lực; chính sách DENY mặc định.')
    st.download_button('⬇️ Xuất chính sách JSON',json.dumps(export_policy(rules),ensure_ascii=False,indent=2),
                       'generated_policy.json','application/json')
    st.download_button('⬇️ Xuất nftables DRAFT cho lab (không tự áp dụng)',
        NftablesLabDraftExporter().render(rules),'nftables_lab_draft.nft','text/plain')
    st.subheader('Mô phỏng một kết nối')
    with st.form('evaluate'):
        x,y,z,w=st.columns(4)
        src=x.text_input('Source IPv4','10.10.10.10');dst=y.text_input('Destination IPv4','10.20.1.10')
        proto=z.selectbox('Protocol',['TCP','UDP','ICMP']);port=w.number_input('Destination Port',0,65535,443)
        if st.form_submit_button('Mô phỏng kết nối'):
            try:
                ans=trace_decision(rules,Packet(src,dst,proto,None if proto=='ICMP' else port))
                st.success(ans['action']) if ans['action']=='ALLOW' else st.warning(ans['action'])
                st.json(ans)
            except ValueError as exc:st.error(str(exc))
    st.subheader('Kiểm toán bộ luật đang sinh')
    current=audit_policy(rules,rules)
    st.metric('Tuân thủ quyền đã duyệt',current['summary'])
    st.caption(current['note'])
    with st.expander('Phân tích luật: shadowing / redundancy'):
        st.json(analyze_rules(rules))
    st.subheader('What-if: tải một chính sách JSON để kiểm toán trước khi áp dụng')
    st.caption('Mở samples/what_if_broad.json để thử một luật ALLOW quá rộng. Tải lên để phát hiện OVERPERMISSIVE với witness.')
    upload=st.file_uploader('Chính sách candidate (.json)',type=['json'])
    if upload is not None:
        try:
            candidate=parse_policy(json.loads(upload.getvalue().decode('utf-8')))
            audited=audit_policy(candidate,rules)
            diff=comparison(rules,candidate)
            left,right=st.columns(2)
            left.metric('Kết quả audit',audited['summary']);right.metric('Số vùng đổi ALLOW/DENY',str(diff.get('changed_cells')))
            st.json(audited);st.json(diff)
            if audited['complete'] and audited['summary']=='PASS':st.success('Ứng viên thỏa đúng tập quyền đã duyệt trong mô hình được hỗ trợ; chưa kiểm chứng hiệu ứng firewall thực.')
            else:st.warning('Không được triển khai tự động; cần kiểm tra sai phạm/INCONCLUSIVE.')
        except (ValueError,KeyError,TypeError) as exc:st.error('Chính sách không hợp lệ: '+str(exc))

elif page.startswith('5.'):
    st.header('5. Giám sát kết nối và đánh giá rủi ro')
    st.write('Nhập nhật ký kết nối CSV hoặc Zeek JSON-lines, rồi đối chiếu với quyền đã duyệt và luật firewall dự kiến.')
    st.warning('Quan sát một luồng bằng Zeek **không chứng minh firewall đã ALLOW**. Chỉ coi ALLOW/DENY là kết quả thực thi khi nguồn log cung cấp rõ.')
    if manager:
        upload=st.file_uploader('CSV hoặc JSONL',type=['csv','jsonl','txt'],key='traffic_file')
        fmt=st.selectbox('Định dạng',['csv','zeek'])
        if st.button('Nhập log') and upload:
            try:run_action(import_traffic,svc,uid,upload.getvalue().decode('utf-8'),fmt)
            except UnicodeDecodeError:st.error('File phải được mã hóa UTF-8')
    else:st.info('Chỉ APPROVER/ADMIN được nhập dữ liệu giám sát.')
    result=analyze_traffic(svc,rules)
    x,y=st.columns(2);x.metric('Dòng log phân tích',result['total']);y.metric('Cảnh báo cần rà soát',len(result['alerts']))
    rows_table(result['alerts'],empty='Chưa có cảnh báo trong log đã nhập.')
    with st.expander('Nhật ký đã nhập'):
        rows_table(svc.list('traffic')[:150])
    st.caption(result['note'])

elif page.startswith('6.'):
    st.header('6. Vòng đời quyền truy cập, thu hồi và audit trail')
    st.subheader('Quyền còn hiệu lực')
    rows_table(grants)
    if manager:
        with st.expander('⏰ Đồng bộ quyền đã hết hạn',expanded=True):
            st.write('Các quyền hết hạn không còn sinh luật ngay cả trước khi đồng bộ trạng thái. Nút này cập nhật trạng thái EXPIRED và ghi audit log.')
            if st.button('Đồng bộ quyền hết hạn'):run_action(svc.expire_due,uid)
        with st.expander('Thu hồi một quyền đang hiệu lực'):
            if grants:
                rid=select_from(grants,'Quyền cần thu hồi','revoke_grant',lambda x:f"Phiếu #{x['request_id']} · {x['username']} → {x['asset_name']}/{x['service_name']}")
                why=st.text_input('Lý do thu hồi',value='Không còn nhu cầu truy cập')
                if st.button('Thu hồi quyền đã phê duyệt'):
                    g=next(x for x in grants if x['request_id']==rid)
                    run_action(svc.revoke_request,uid,g['request_id'],why)
    if admin:
        with st.expander('Nhân viên chuyển bộ phận / nghỉ việc / thay IP'):
            if users:
                target=select_from(users,'Chọn tài khoản','change_user',lambda x:f"{x['username']} ({x['business_role']})")
                person=next(x for x in users if x['id']==target)
                newrole=st.text_input('Vai trò nghiệp vụ mới',value=person['business_role'])
                newip=st.text_input('IPv4 mới',value=person['source_ip'])
                enabled=st.checkbox('Tài khoản còn hoạt động',value=bool(person['active']))
                if st.button('Cập nhật người dùng và thu hồi quyền cũ nếu có'):
                    run_action(svc.change_user,uid,target,business_role=newrole,source_ip=newip,active=enabled)
        with st.expander('Vô hiệu hóa tài nguyên và thu hồi các quyền liên quan'):
            working=[a for a in assets if a['active']]
            target=select_from(working,'Máy chủ cần tắt','asset_disable',lambda x:x['name'])
            if st.button('Vô hiệu hóa tài nguyên') and target:
                run_action(svc.disable_asset,uid,target)
    with st.expander('Đổi mật khẩu tài khoản hiện tại'):
        with st.form('password_change'):
            old=st.text_input('Mật khẩu cũ',type='password');new=st.text_input('Mật khẩu mới (≥10 ký tự)',type='password')
            if st.form_submit_button('Đổi mật khẩu'):run_action(svc.change_password,uid,old,new)
    st.subheader('Lịch sử nghiệp vụ')
    logs=svc.list('audit_events')
    if not manager:logs=[x for x in logs if x['actor_id']==uid]
    rows_table(logs[:300])
    st.caption('Lưu audit trail trong SQLite giúp truy vết; không phải hệ thống log bất biến chống quản trị viên sửa trực tiếp database.')
    if manager:
        st.subheader('Xuất báo cáo kiểm toán')
        report=make_report(svc)
        st.download_button('⬇️ Báo cáo Markdown',markdown_report(report),'access_audit_report.md','text/markdown')
        st.download_button('⬇️ Báo cáo JSON',json.dumps(report,ensure_ascii=False,indent=2),'access_audit_report.json','application/json')
