export async function api(path,method='GET',data){
  const opt={method,credentials:'same-origin',headers:{'Accept':'application/json'}};
  if(method!=='GET')opt.headers['X-AccessFlow-Action']='1';
  if(data!==undefined){opt.headers['Content-Type']='application/json';opt.body=JSON.stringify(data)}
  let resp;
  try{resp=await fetch('/api'+path,opt)}catch{throw new Error('Không kết nối được API. Kiểm tra Terminal có đang chạy AccessFlow không.')} 
  let body;
  try{body=await resp.json()}catch{body=null}
  if(!resp.ok){let detail=body?.detail||`Lỗi HTTP ${resp.status}`;if(Array.isArray(detail))detail=detail.map(x=>x.msg).join('; ');const e=new Error(detail);e.status=resp.status;throw e}
  return body;
}
export async function downloadFile(path,filename){
  const response=await fetch('/api'+path,{credentials:'same-origin'});
  if(!response.ok){const x=await response.json().catch(()=>({}));throw new Error(x.detail||'Không tải được tệp')}
  const blob=await response.blob();
  const url=URL.createObjectURL(blob);const a=document.createElement('a');a.href=url;a.download=filename;a.click();URL.revokeObjectURL(url);
}
