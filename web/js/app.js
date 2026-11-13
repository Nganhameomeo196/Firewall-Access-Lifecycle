import {api,downloadFile} from './api.js';
import {esc,icon,fmtDate,fmtDay,statusBadge,isManager,isAdmin,field,empty} from './utils.js';
import {loginView,shellView,modalHTML,modalFooter} from './views.js';

const AF={page:'overview',data:null,assetSearch:'',requestFilter:'ALL',busy:false};
window.AF=AF;
const app=document.querySelector('#app');
const modalEl=document.querySelector('#modal-root');
let toastTimer=0;
const isLogged=()=>!!AF.data?.actor;
const actor=()=>AF.data?.actor;
const getFormData=form=>Object.fromEntries(new FormData(form).entries());

function toast(msg,type='success'){
 const region=document.getElementById('toast-region');if(!region)return;
 const ic=type==='error'?'alert':'check';region.innerHTML=`<div class="toast ${type}">${icon(ic,17)}<span>${esc(msg)}</span></div>`;
 clearTimeout(toastTimer);toastTimer=setTimeout(()=>region.innerHTML='',5100);
}
function openModal(title,desc,body,footer='',wide=false){modalEl.innerHTML=modalHTML(title,desc,body,footer,wide);modalEl.querySelector('.modal-close')?.focus()}
function closeModal(){modalEl.innerHTML=''}
function formModal(title,desc,body,submit='Lưu',danger=false,wide=false){openModal(title,desc,`<form id="form-modal" data-form="modal" class="form-grid">${body}</form>`,modalFooter(submit,'form-modal',danger),wide)}
function render(){app.innerHTML=isLogged()?shellView(AF.data,AF.page):loginView()}
async function refresh(silent=false){const d=await api('/state');AF.data=d;render();if(!silent)toast('Dữ liệu đã được làm mới')}
async function boot(){try{await api('/auth/me');await refresh(true)}catch(e){AF.data=null;render()}}
async function mutate(path,method,data,success){const result=await api(path,method,data);closeModal();await refresh(true);if(success)toast(success);return result}
function needAuth(e){if(e?.status===401){AF.data=null;closeModal();render();toast('Phiên đăng nhập đã hết hạn. Vui lòng đăng nhập lại','error');return true}return false}
async function safe(fn){try{await fn()}catch(e){if(!needAuth(e))toast(e.message||'Thao tác không thành công','error')}}
function switchPage(page){AF.page=page;render();window.scrollTo({top:0,behavior:'instant'})}
const choices=(arr,name,format,value='')=>field(name,name==='service_id'?'Dịch vụ':'Chọn tài nguyên','select',value,{options:arr.map(x=>({value:x.id,label:format(x)}))});
function assetById(id){return AF.data.assets.find(x=>x.id===Number(id))}
function requestById(id){return AF.data.requests.find(x=>x.id===Number(id))}
function formatImpact(p){if(!p?.eligible)return `<div class="notice danger">${icon('alert',17)} ${esc(p?.reason||'Không hợp lệ')}</div>`;
 const imp=p.impact||{};return `<div class="grid cols-2"><div class="panel panel-pad"><div class="muted text-small">Luật trước thay đổi</div><div style="font-size:24px;font-weight:800;margin-top:5px">${p.before_rules}</div></div><div class="panel panel-pad"><div class="muted text-small">Luật sau thay đổi</div><div style="font-size:24px;font-weight:800;margin-top:5px">${p.after_rules}</div></div></div><div class="notice ${imp.complete?'info':'warning'}" style="margin-top:13px">${icon(imp.complete?'check':'alert',17)} <div>${imp.complete?`Đã xét ${imp.checked_cells} ô phân hoạch; ${imp.changed_cells} ô có thay đổi quyết định ALLOW/DENY.`:'INCONCLUSIVE: chưa thể kết luận tác động do giới hạn phân hoạch.'}<br><span class="muted">Ô phân hoạch không phải số lượng packet thực.</span></div></div>
 ${imp.examples?.length?`<div style="margin-top:16px"><strong class="text-small">Ví dụ một kết nối bị ảnh hưởng</strong><div class="code-box" style="margin-top:7px">${esc(JSON.stringify(imp.examples[0],null,2))}</div></div>`:''}`}

async function dispatchAction(action,btn){
 const id=Number(btn?.dataset?.id),role=btn?.dataset?.role,serviceId=Number(btn?.dataset?.service);
 switch(action){
 case 'logout':await api('/auth/logout','POST');AF.data=null;closeModal();render();toast('Đã đăng xuất');break;
 case 'refresh':await refresh();break;
 case 'go-policy':switchPage('policy');break;
 case 'close-modal':closeModal();break;
 case 'new-request':{
  const services=AF.data.services.filter(s=>s.service_active&&s.asset_active);
  formModal('Yêu cầu truy cập mới','Khai báo mục đích nghiệp vụ và thời hạn. Gửi phiếu không tự tạo quyền ALLOW.',
    `<div class="wide">${choices(services,'service_id',s=>`${s.asset} · ${s.service} (${s.protocol}/${s.port})`)}</div>${field('purpose','Lý do cần truy cập','textarea','',{wide:true,placeholder:'Ví dụ: sử dụng CRM để quản lý khách hàng và đơn hàng'})}${field('days','Số ngày có hiệu lực','number',7,{min:1,max:365,wide:true})}`,'Gửi phiếu yêu cầu');
  modalEl.querySelector('form').dataset.kind='request';break}
 case 'add-asset':formModal('Thêm máy chủ / tài nguyên','Tài nguyên mới được lưu riêng, luôn xuất hiện trong danh sách dù chưa gắn dịch vụ.',
   `${field('name','Tên tài nguyên','text','CRM Lab')}${field('ip','IPv4 máy chủ','text','10.20.4.10')}${field('department','Phòng ban quản lý','text','SALES')}${field('sensitivity','Độ nhạy cảm','select','MEDIUM',{options:[{value:'LOW',label:'Thấp'},{value:'MEDIUM',label:'Trung bình'},{value:'HIGH',label:'Cao'}]})}${field('owner','Chủ sở hữu','text','Phòng Kinh doanh',{wide:true})}`,'Tạo tài nguyên');modalEl.querySelector('form').dataset.kind='asset';break;
 case 'add-service':{
  const assetId=btn.dataset.assetId||AF.data.assets.find(x=>x.active)?.id;
  formModal('Đăng ký dịch vụ mạng','Gắn giao thức và cổng đích vào một tài nguyên đã tồn tại.',
    `<div class="wide">${choices(AF.data.assets.filter(x=>x.active),'asset_id',a=>`${a.name} · ${a.ip}`,assetId)}</div>${field('name','Tên dịch vụ','text','HTTPS')}${field('protocol','Giao thức','select','TCP',{options:[{value:'TCP',label:'TCP'},{value:'UDP',label:'UDP'}]})}${field('port','Cổng đích','number',443,{min:1,max:65535,wide:true})}`,'Lưu dịch vụ');modalEl.querySelector('form').dataset.kind='service';break}
 case 'add-user':formModal('Thêm người dùng','Trong bản lab mỗi tài khoản gắn một IP tĩnh để mô phỏng chính sách mạng.',
   `${field('display_name','Họ tên','text','')}${field('username','Tên đăng nhập','text','')}${field('password','Mật khẩu (từ 10 ký tự)','password','',{minLength:10})}${field('source_ip','IPv4 thiết bị','text','10.10.40.10')}${field('business_role','Vai trò nghiệp vụ','text','SALES')}${field('system_role','Quyền hệ thống','select','EMPLOYEE',{options:['EMPLOYEE','APPROVER','ADMIN'].map(v=>({value:v,label:v}))})}`,'Tạo người dùng');modalEl.querySelector('form').dataset.kind='user';break;
 case 'add-entitlement':{
  const roleNames=[...new Set(AF.data.users.map(x=>x.business_role))].sort();
  formModal('Cấp quyền chuẩn theo vai trò','Entitlement chỉ cho phép vai trò gửi phiếu hợp lệ, chưa tự mở firewall.',
    `${field('business_role','Vai trò nghiệp vụ','select',roleNames[0],{wide:true,options:roleNames.map(v=>({value:v,label:v}))})}<div class="wide">${choices(AF.data.services.filter(s=>s.asset_active&&s.service_active),'service_id',s=>`${s.asset} · ${s.service} ${s.protocol}/${s.port}`)}</div>`,'Cấp quyền chuẩn');modalEl.querySelector('form').dataset.kind='entitlement';break}
 case 'remove-entitlement':
  openModal('Thu hồi quyền chuẩn','Các phiếu APPROVED thuộc vai trò và dịch vụ này cũng bị thu hồi.',
    `<div class="notice warning">${icon('alert',17)} Thu hồi quyền <b>${esc(role)}</b> tới service #${serviceId}. Thao tác làm thay đổi chính sách được sinh trong mô phỏng.</div>`,
    `<button class="btn btn-outline" data-action="close-modal">Hủy</button><button class="btn btn-danger" data-action="confirm-remove-entitlement" data-role="${esc(role)}" data-service="${serviceId}">Xác nhận thu hồi</button>`);break;
 case 'confirm-remove-entitlement':await mutate('/entitlements','DELETE',{business_role:role,service_id:serviceId},'Đã thu hồi quyền chuẩn');break;
 case 'view-asset':{
  const a=assetById(id);if(!a)return;
  const services=AF.data.services.filter(x=>x.asset===a.name);
  openModal(a.name,'Chi tiết tài nguyên và các dịch vụ đang đăng ký',`<div class="grid cols-2"><div><div class="muted text-small">IPv4 máy chủ</div><div class="mono" style="margin-top:5px;font-size:15px">${esc(a.ip)}</div></div><div><div class="muted text-small">Độ nhạy cảm</div><div style="margin-top:5px">${statusBadge(a.sensitivity)}</div></div><div><div class="muted text-small">Phòng ban</div><b>${esc(a.department)}</b></div><div><div class="muted text-small">Chủ sở hữu</div><b>${esc(a.owner)}</b></div></div><div class="line"></div><b class="text-small">Dịch vụ (${services.length})</b>${services.length?services.map(x=>`<div class="access-card" style="margin-top:10px"><span class="mini-icon">${icon('network',16)}</span><div><strong>${esc(x.service)}</strong><small>${esc(x.protocol)} / ${esc(x.port)}</small></div>${statusBadge(x.service_active?'APPROVED':'REVOKED')}</div>`).join(''):'<div class="notice info" style="margin-top:10px">Tài nguyên chưa có dịch vụ. Đây là trạng thái hợp lệ, không bị ẩn khỏi danh sách.</div>'}`,
    isAdmin(actor())?`<button class="btn btn-outline" data-action="close-modal">Đóng</button><button class="btn btn-primary" data-action="add-service" data-asset-id="${id}">${icon('plus',14)} Thêm dịch vụ</button>`:'');break}
 case 'request-details':{
  const r=requestById(id);if(!r)return;
  openModal(`Phiếu #${r.id} · ${r.asset_name}`,'Thông tin truy xuất nguồn gốc của chính sách truy cập',`<div class="grid cols-2"><div><p class="muted text-small">Người yêu cầu</p><b>${esc(r.requester_name)}</b></div><div><p class="muted text-small">Trạng thái</p>${statusBadge(r.status)}</div><div><p class="muted text-small">Vai trò</p><b>${esc(r.business_role)}</b></div><div><p class="muted text-small">Dịch vụ</p><b>${esc(r.service_name)} ${esc(r.protocol)}/${r.port}</b></div><div><p class="muted text-small">Ngày yêu cầu</p><b>${fmtDate(r.requested_at)}</b></div><div><p class="muted text-small">Hết hạn</p><b>${fmtDate(r.expires_at)}</b></div></div><div class="line"></div><b class="text-small">Mục đích nghiệp vụ</b><p class="text-small muted" style="line-height:1.8;margin-top:6px">${esc(r.purpose)}</p>${r.decision_reason?`<div class="notice info" style="margin-top:15px">Lý do quyết định: ${esc(r.decision_reason)}</div>`:''}`,`<button class="btn btn-primary" data-action="close-modal">Đã hiểu</button>`);break}
 case 'review-request':{
  const r=requestById(id);if(!r)return;
  const preview=await api(`/requests/${id}/preview?mode=approve`);
  const body=`<div class="split" style="margin-bottom:13px"><div><strong>${esc(r.requester_name)}</strong><p class="muted text-small">${esc(r.business_role)} → ${esc(r.asset_name)} / ${esc(r.service_name)}</p></div>${statusBadge(r.status)}</div><div class="notice ${preview.eligible?'info':'danger'}">${icon(preview.eligible?'check':'alert',16)} ${esc(preview.reason)}</div><div class="line"></div><b class="text-small">Xem trước tác động nếu phê duyệt</b><div style="margin-top:12px">${formatImpact(preview)}</div><div class="line"></div><form id="decision-form" data-form="decision" data-id="${id}" class="grid" style="gap:12px"><div class="form-field"><label for="decision-select">Quyết định</label><select class="form-select" name="decision" id="decision-select"><option value="APPROVE" ${preview.eligible?'':'disabled'}>Phê duyệt quyền</option><option value="REJECT" ${preview.eligible?'':'selected'}>Từ chối yêu cầu</option></select></div>${field('reason','Lý do quyết định','textarea','Đã kiểm tra mục đích và quyền theo vai trò')}</form>`;
  openModal(`Xét duyệt phiếu #${id}`,'Xem chứng cứ và tác động chính sách trước khi quyết định.',body,modalFooter('Xác nhận quyết định','decision-form'),true);break}
 case 'revoke-preview':{
  const r=requestById(id);if(!r)return;
  const p=await api(`/requests/${id}/preview?mode=revoke`);
  openModal(`Thu hồi quyền #${id}`,'Luật sẽ được sinh lại từ các quyền còn hiệu lực. Không tác động firewall thật.',`<div class="notice warning">${icon('alert',17)} Thu hồi quyền <b>${esc(r.requester_name)}</b> tới <b>${esc(r.asset_name)}</b>.</div><div style="margin-top:16px">${formatImpact(p)}</div><form data-form="revoke" data-id="${id}" id="revoke-form" style="margin-top:17px">${field('reason','Lý do thu hồi','textarea','Hết nhu cầu truy cập',{wide:true})}</form>`,modalFooter('Xác nhận thu hồi','revoke-form',true),true);break}
 case 'policy-audit':{
  const result=await api('/policy/audit');
  const audit=result.baseline;
  const label=audit.summary;
  const html=`<div class="outcome ${label==='PASS'?'allowed':'denied'}"><div class="text-small muted">Kết quả kiểm tra cơ sở</div><strong>${esc(label)}</strong><p>${audit.complete?`Đã xét ${audit.checked_cells} ô phân hoạch; ${audit.violating_cells} ô khác biệt.`:'INCONCLUSIVE vì vượt giới hạn phân hoạch'}</p></div><div class="notice warning" style="margin-top:12px">${icon('info',15)} ${esc(result.note)}</div>`;
  const area=document.querySelector('#audit-result');if(area)area.innerHTML=html;
  else openModal('Báo cáo kiểm toán','Baseline consistency check',html);
  break}
 case 'export-json':await downloadFile('/policy/export/json','accessflow_policy.json');toast('Đã xuất chính sách JSON');break;
 case 'export-nft':await downloadFile('/policy/export/nft','accessflow_lab_draft.nft');toast('Đã xuất bản nháp nftables (không tự áp dụng)');break;
 case 'import-log-modal':{
   openModal('Nhập nhật ký kết nối','Nhập CSV / Zeek JSONL và đối chiếu quyền truy cập hiện hành.',`<form data-form="import-logs" id="import-modal-form" class="grid" style="gap:16px">${field('format','Định dạng','select','csv',{options:[{value:'csv',label:'CSV'},{value:'zeek',label:'Zeek JSONL'}]})}<div class="form-field"><label for="mon-file">File kết nối</label><input class="form-input" id="mon-file" name="traffic" type="file" accept=".csv,.jsonl,.txt" required/></div></form>`,modalFooter('Nhập và phân tích','import-modal-form'));break}
 case 'sync-expire':await mutate('/lifecycle/expire','POST',{},'Đã đồng bộ các phiếu hết hạn');break;
 case 'download-report':await downloadFile('/report/md','accessflow_audit.md');toast('Đã tải báo cáo Markdown');break;
 case 'download-report-json':await downloadFile('/report/json','accessflow_audit.json');toast('Đã tải báo cáo JSON');break;
 case 'update-user':{
  const us=AF.data.users.filter(u=>u.username!=='admin');
  openModal('Chọn tài khoản cần cập nhật','Mỗi lần sửa vai trò hoặc IP nguồn sẽ thu hồi các quyền APPROVED của tài khoản.',us.map(u=>`<button class="action-card" style="margin-bottom:9px" data-action="update-selected" data-id="${u.id}"><span class="avatar">${esc(u.display_name.slice(0,1))}</span><div><strong>${esc(u.display_name)}</strong><span>@${esc(u.username)} · ${esc(u.business_role)} · ${esc(u.source_ip)}</span></div>${icon('chevronRight',15)}</button>`).join(''));break}
 case 'update-selected':{
  const u=AF.data.users.find(x=>x.id===id);if(!u)return;
  formModal(`Cập nhật ${u.display_name}`,'Thay vai trò, IP hoặc trạng thái: tất cả quyền đã phê duyệt trước đó có thể bị thu hồi.',`${field('business_role','Vai trò nghiệp vụ','text',u.business_role)}${field('source_ip','IP thiết bị','text',u.source_ip)}${field('active','Trạng thái tài khoản','select',u.active?'1':'0',{options:[{value:'1',label:'Đang hoạt động'},{value:'0',label:'Vô hiệu hóa'}]})}<div class="notice warning wide">${icon('alert',16)} Chỉ áp dụng với dữ liệu lab. Thao tác ghi lại lịch sử.</div>`,'Lưu thay đổi',true);const form=modalEl.querySelector('form');form.dataset.kind='update-user';form.dataset.id=id;break}
 case 'disable-asset':{
  const assets=AF.data.assets.filter(a=>a.active);
  openModal('Chọn tài nguyên cần vô hiệu hóa','Quyền thuộc tài nguyên sẽ bị thu hồi khi xác nhận.',assets.map(a=>`<button class="action-card" style="margin-bottom:8px" data-action="disable-selected" data-id="${a.id}"><span class="mini-icon">${icon('server',16)}</span><div><strong>${esc(a.name)}</strong><span>${esc(a.ip)} · ${esc(a.department)}</span></div>${icon('chevronRight',15)}</button>`).join(''));break}
 case 'disable-selected':{
  const a=assetById(id);if(!a)return;
  openModal(`Vô hiệu hóa ${a.name}`,'Hành động thay đổi dữ liệu đang có và thu hồi các quyền APPROVED liên quan.',`<div class="notice danger">${icon('alert',17)} Máy chủ <b>${esc(a.name)}</b> (${esc(a.ip)}) sẽ bị vô hiệu trong hệ thống mô phỏng. Thao tác không chặn máy chủ thật.</div>`,
     `<button class="btn btn-outline" data-action="close-modal">Hủy</button><button class="btn btn-danger" data-action="confirm-disable" data-id="${id}">Xác nhận vô hiệu hóa</button>`);break}
 case 'confirm-disable':await mutate(`/assets/${id}/disable`,'POST',{},'Đã vô hiệu hóa tài nguyên');break;
 case 'change-password':formModal('Đổi mật khẩu','Đổi mật khẩu cho tài khoản đang đăng nhập. Dữ liệu lab vẫn chạy trên máy cục bộ.',
  `${field('current_password','Mật khẩu hiện tại','password','',{wide:true})}${field('new_password','Mật khẩu mới (ít nhất 10 ký tự)','password','',{minLength:10,wide:true})}`,'Đổi mật khẩu');modalEl.querySelector('form').dataset.kind='password';break;
 }
}

async function submitForm(form){
 const data=getFormData(form),kind=form.dataset.kind||form.dataset.form;
 switch(kind){
 case 'login':{
  try{await api('/auth/login','POST',{username:data.username,password:data.password});await refresh(true);toast('Đăng nhập thành công')}catch(e){const target=document.querySelector('#login-error');if(target)target.textContent=e.message||'Đăng nhập thất bại'}
  break}
 case 'asset':await mutate('/assets','POST',data,'Máy chủ mới đã được lưu và xuất hiện trong danh sách');break;
 case 'service':await mutate('/services','POST',{...data,asset_id:Number(data.asset_id),port:Number(data.port)},'Đã đăng ký dịch vụ mạng');break;
 case 'user':await mutate('/users','POST',data,'Đã tạo người dùng');break;
 case 'entitlement':await mutate('/entitlements','POST',{business_role:data.business_role,service_id:Number(data.service_id)},'Đã cấp quyền chuẩn cho vai trò');break;
 case 'request':await mutate('/requests','POST',{service_id:Number(data.service_id),purpose:data.purpose,days:Number(data.days)},'Đã gửi phiếu. Yêu cầu vẫn chờ duyệt, chưa mở firewall');AF.page='requests';render();break;
 case 'decision':await mutate(`/requests/${Number(form.dataset.id)}/decision`,'POST',{approve:data.decision==='APPROVE',reason:data.reason},'Đã ghi nhận quyết định và cập nhật chính sách mô phỏng');break;
 case 'revoke':await mutate(`/requests/${Number(form.dataset.id)}/revoke`,'POST',{reason:data.reason},'Đã thu hồi quyền và sinh lại chính sách');break;
 case 'update-user':await mutate(`/users/${Number(form.dataset.id)}`,'PATCH',{business_role:data.business_role,source_ip:data.source_ip,active:data.active==='1'},'Đã cập nhật người dùng và thu hồi quyền cũ nếu cần');break;
 case 'password':await mutate('/auth/password','POST',data,'Đã đổi mật khẩu');break;
 case 'simulate':{
  const payload={source:data.source,destination:data.destination,protocol:data.protocol,port:data.protocol==='ICMP'?null:Number(data.port)};
  const result=await api('/policy/simulate','POST',payload);
  const ans=result.decision,allowed=ans.action==='ALLOW';
  const box=document.getElementById('simulation-result');
  if(box)box.innerHTML=`<div class="outcome ${allowed?'allowed':'denied'}"><span class="muted text-small">Kết quả mô phỏng</span><strong>${esc(ans.action)} ${allowed?icon('check',22):icon('lock',22)}</strong><p>${esc(ans.reason)}</p><p>Luật khớp: ${esc(ans.rule_id||'DEFAULT DENY')} · Phiếu: ${esc(ans.provenance?.map(x=>'#'+x).join(', ')||'Không')}</p></div><div style="margin-top:15px"><b class="text-small">Dấu vết từng luật</b>${ans.trace?.length?ans.trace.map(r=>`<div class="trace-row ${r.matched?'matched':''}"><div><b>${esc(r.rule_id)}</b> · Nguồn ${r.checks.source?'✓':'×'}, Đích ${r.checks.destination?'✓':'×'}, Protocol ${r.checks.protocol?'✓':'×'}, Port ${r.checks.port?'✓':'×'}</div>${r.matched?statusBadge('ALLOW'):'<span class="muted">Không khớp</span>'}</div>`).join(''):'<p class="note-tiny">Chính sách không chứa luật ALLOW phù hợp.</p>'}</div>`;
  break}
 case 'whatif':{
  const f=form.querySelector('input[type=file]')?.files?.[0];if(!f)throw Error('Cần chọn file JSON ứng viên');
  let obj;try{obj=JSON.parse(await f.text())}catch{throw Error('File JSON không hợp lệ')}
  const r=await api('/policy/whatif','POST',{policy:obj});const a=r.audit,imp=r.impact;
  const target=document.querySelector('#whatif-result');if(target)target.innerHTML=`<div class="outcome ${a.summary==='PASS'?'allowed':'denied'}"><span class="text-small muted">Kiểm toán chính sách ứng viên</span><strong>${esc(a.summary)}</strong><p>${a.complete?`Số ô vi phạm: ${a.violating_cells}. Phân loại: ${esc(a.types.join(', ')||'Không có')}`:'INCONCLUSIVE — không đủ điều kiện kết luận'}</p></div><div class="notice info" style="margin-top:10px">${icon('info',15)} Có ${imp.changed_cells??'—'} ô phân hoạch đổi quyết định so với chính sách hiện hành. Không phải số packet.</div>${a.examples?.length?`<pre class="code-box" style="margin-top:10px">${esc(JSON.stringify(a.examples.slice(0,3),null,2))}</pre>`:''}`;
  toast('Đã kiểm tra chính sách ứng viên');break}
 case 'import-logs':{
  const f=form.querySelector('input[type=file]')?.files?.[0];if(!f)throw Error('Chưa chọn file log');
  if(f.size>3_000_000)throw Error('File vượt 3 MB');
  const r=await mutate('/monitor/import','POST',{format:data.format,content:await f.text()},'Đã nhập log: '+(f.name||'file'));
  toast(`Đã thêm ${r.added} dòng, bỏ qua ${r.duplicates} dòng trùng`);
  break}
 }
}

// All interactions are delegated to the app root, so full rerenders remain robust.
document.addEventListener('click',ev=>{
 const nav=ev.target.closest('[data-nav]');if(nav){switchPage(nav.dataset.nav);return}
 const btn=ev.target.closest('[data-action]');if(btn){ev.preventDefault();safe(()=>dispatchAction(btn.dataset.action,btn));return}
 if(ev.target.classList?.contains('modal-overlay'))closeModal();
});
document.addEventListener('submit',ev=>{const form=ev.target.closest('form[data-form]');if(!form)return;ev.preventDefault();if(AF.busy)return;AF.busy=true;const submits=form.querySelectorAll('button[type=submit]');submits.forEach(x=>x.disabled=true);safe(()=>submitForm(form)).finally(()=>{AF.busy=false;submits.forEach(x=>x.disabled=false)})});
document.addEventListener('change',ev=>{if(ev.target.id==='request-filter'){AF.requestFilter=ev.target.value;render()}});
document.addEventListener('input',ev=>{if(ev.target.dataset.search==='asset'){AF.assetSearch=ev.target.value;
  const q=AF.assetSearch.trim().toLowerCase();const rows=document.querySelectorAll('#asset-table .data-table tbody tr');
  rows.forEach(tr=>tr.style.display=tr.textContent.toLowerCase().includes(q)?'':'none')}});
document.addEventListener('keydown',ev=>{if(ev.key==='Escape')closeModal()});
boot();
