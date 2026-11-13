export const esc = v => String(v ?? '').replace(/[&<>"']/g, x => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[x]));
const glyph = {
 shield:'<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10Z"/><path d="m9 12 2 2 4-4"/>',
 dashboard:'<rect x="3" y="3" width="7" height="9" rx="1"/><rect x="14" y="3" width="7" height="5" rx="1"/><rect x="14" y="12" width="7" height="9" rx="1"/><rect x="3" y="16" width="7" height="5" rx="1"/>',
 users:'<path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M22 21v-2a4 4 0 0 0-3-3.87M16 3.13a4 4 0 0 1 0 7.75"/>',
 server:'<rect x="2" y="3" width="20" height="7" rx="2"/><rect x="2" y="14" width="20" height="7" rx="2"/><path d="M6 6.5h.01M6 17.5h.01"/>',
 layers:'<path d="m12 2 9 5-9 5-9-5 9-5ZM3 12l9 5 9-5M3 17l9 5 9-5"/>',
 clipboard:'<rect x="5" y="4" width="14" height="18" rx="2"/><path d="M9 4.5V3h6v1.5M9 12h6M9 16h4"/>',
 policy:'<path d="M4 4h16v16H4zM9 2v4M15 2v4M2 10h20M8 14l2 2 5-5"/>',
 monitor:'<path d="M3 3v18h18M6 16l5-5 4 3 5-8"/>',
 history:'<path d="M3 12a9 9 0 1 0 2-6M3 3v6h6M12 7v5l3 2"/>',
 arrow:'<path d="M5 12h14M13 6l6 6-6 6"/>',
 left:'<path d="M19 12H5m6 6-6-6 6-6"/>',
 plus:'<path d="M12 5v14M5 12h14"/>',
 check:'<path d="m5 12 4 4L19 6"/>',
 alert:'<path d="m10.3 3.8-8.1 14a2 2 0 0 0 1.7 3h16.2a2 2 0 0 0 1.7-3l-8.1-14a2 2 0 0 0-3.4 0Z"/><path d="M12 9v4m0 4h.01"/>',
 info:'<circle cx="12" cy="12" r="10"/><path d="M12 16v-4m0-4h.01"/>',
 search:'<circle cx="10.5" cy="10.5" r="7"/><path d="m16 16 5 5"/>',
 download:'<path d="M12 3v12m-5-5 5 5 5-5M5 17v4h14v-4"/>',
 refresh:'<path d="M20 11a8 8 0 0 0-14.5-4M4 4v4h4M4 13a8 8 0 0 0 14.5 4M20 20v-4h-4"/>',
 logout:'<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9"/>',
 close:'<path d="M18 6 6 18M6 6l12 12"/>',
 calendar:'<rect x="3" y="5" width="18" height="16" rx="2"/><path d="M16 3v4M8 3v4M3 11h18"/>',
 lock:'<rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V7a4 4 0 1 1 8 0v4"/>',
 workflow:'<rect x="3" y="3" width="7" height="6" rx="1"/><rect x="14" y="15" width="7" height="6" rx="1"/><path d="M6 9v6h11M14 18l3-3 3 3"/>',
 file:'<path d="M5 2h9l5 5v15H5zM14 2v6h5M8 12h8M8 16h8"/>',
 shieldOff:'<path d="M3 3 21 21M12 22s8-4 8-10V5l-8-3-5 2M4 7v5c0 3 2 6 5 8"/>',
 clock:'<circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/>',
 globe:'<circle cx="12" cy="12" r="10"/><path d="M2 12h20M12 2a15 15 0 0 1 0 20M12 2a15 15 0 0 0 0 20"/>',
 sparkles:'<path d="m12 3 1.8 5.2L19 10l-5.2 1.8L12 17l-1.8-5.2L5 10l5.2-1.8L12 3ZM19 17l.8 2.2L22 20l-2.2.8L19 23l-.8-2.2L16 20l2.2-.8L19 17Z"/>',
 eye:'<path d="M2 12s4-7 10-7 10 7 10 7-4 7-10 7S2 12 2 12Z"/><circle cx="12" cy="12" r="3"/>',
 key:'<circle cx="7" cy="14" r="4"/><path d="m10 11 11-9 1 3-3 2 1 3-3 2-3-1-4 4"/>',
 arrowDown:'<path d="m6 9 6 6 6-6"/>',
 link:'<path d="M10 13a5 5 0 0 0 7 .1l3-3a5 5 0 0 0-7-7l-2 2M14 11a5 5 0 0 0-7-.1l-3 3a5 5 0 0 0 7 7l2-2"/>',
 list:'<path d="M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01"/>',
 network:'<rect x="2" y="3" width="6" height="5" rx="1"/><rect x="16" y="3" width="6" height="5" rx="1"/><rect x="9" y="16" width="6" height="5" rx="1"/><path d="M5 8v4h14V8M12 12v4"/>',
 edit:'<path d="M12 20h9M16 3l5 5L9 20H4v-5Z"/>',
 upload:'<path d="M12 16V4m-5 5 5-5 5 5M4 17v4h16v-4"/>',
 database:'<ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M3 5v14c0 4 18 4 18 0V5M3 12c0 4 18 4 18 0"/>',
 more:'<circle cx="5" cy="12" r="1"/><circle cx="12" cy="12" r="1"/><circle cx="19" cy="12" r="1"/>',
 user:'<circle cx="12" cy="8" r="4"/><path d="M4 21a8 8 0 0 1 16 0"/>',
 filter:'<path d="M4 4h16l-6 7v8l-4 2v-10Z"/>',
 zap:'<path d="M13 2 3 14h8l-1 8 11-12h-8z"/>',
 activity:'<path d="M22 12h-4l-3 9L9 3l-3 9H2"/>',
 chevronRight:'<path d="m9 18 6-6-6-6"/>'
};
export const icon=(name,size=18)=>`<svg width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${glyph[name]||glyph.info}</svg>`;
export const initials = name => (String(name||'?').trim().split(/\s+/).slice(-2).map(x=>x[0]).join('')||'?').toUpperCase();
export const statusBadge=(status)=>{const styles={PENDING:['amber','Chờ duyệt'],APPROVED:['green','Đã duyệt'],REJECTED:['red','Từ chối'],REVOKED:['dark','Đã thu hồi'],EXPIRED:['purple','Hết hạn'],ADMIN:['blue','ADMIN'],APPROVER:['purple','APPROVER'],EMPLOYEE:['dark','EMPLOYEE'],HIGH:['red','Cao'],MEDIUM:['amber','Trung bình'],LOW:['green','Thấp'],ALLOW:['green','ALLOW'],DENY:['red','DENY'],PASS:['green','PASS'],FAIL:['red','FAIL'],INCONCLUSIVE:['amber','INCONCLUSIVE']};const [cls,label]=styles[status]||['dark',status||'—'];return `<span class="badge ${cls}">${esc(label)}</span>`};
export const fmtDate = value=>{if(!value)return '—';const d=new Date(value);if(isNaN(d))return esc(value);return new Intl.DateTimeFormat('vi-VN',{day:'2-digit',month:'2-digit',year:'numeric',hour:'2-digit',minute:'2-digit',hour12:false}).format(d)};
export const fmtDay = value=>{if(!value)return '—';const d=new Date(value);if(isNaN(d))return esc(value);return new Intl.DateTimeFormat('vi-VN',{day:'2-digit',month:'2-digit',year:'numeric'}).format(d)};
export const actorRole = a => a?.system_role || 'EMPLOYEE';
export const isManager = a => ['ADMIN','APPROVER'].includes(actorRole(a));
export const isAdmin = a => actorRole(a)==='ADMIN';
export const card=(content,extra='')=>`<section class="panel ${extra}">${content}</section>`;
export const empty=(title,desc,ic='server')=>`<div class="empty-state"><div class="empty-icon">${icon(ic,24)}</div><h3>${esc(title)}</h3><p>${esc(desc)}</p></div>`;
export const header=(title,desc,actions='')=>`<div class="page-heading"><div><h1>${title}</h1><p>${desc}</p></div><div class="heading-actions">${actions}</div></div>`;
export const section=(title,desc='',right='')=>`<div class="section-head"><div><h2>${title}</h2>${desc?`<p>${desc}</p>`:''}</div>${right}</div>`;
export const field=(name,label,type='text',value='',opts={})=>`<div class="form-field ${opts.wide?'wide':''}"><label for="f_${name}">${esc(label)}</label>${type==='select'?`<select class="form-select" name="${name}" id="f_${name}" ${opts.required===false?'':'required'}>${(opts.options||[]).map(o=>`<option value="${esc(o.value)}" ${String(o.value)===String(value)?'selected':''}>${esc(o.label)}</option>`).join('')}</select>`:type==='textarea'?`<textarea class="form-textarea" name="${name}" id="f_${name}" ${opts.required===false?'':'required'} placeholder="${esc(opts.placeholder||'')}">${esc(value)}</textarea>`:`<input class="form-input" type="${type}" name="${name}" id="f_${name}" value="${esc(value)}" placeholder="${esc(opts.placeholder||'')}" ${opts.min!=null?`min="${opts.min}"`:''} ${opts.max!=null?`max="${opts.max}"`:''} ${opts.minLength!=null?`minlength="${opts.minLength}"`:''} ${opts.required===false?'':'required'}/>`}${opts.hint?`<div class="form-hint">${esc(opts.hint)}</div>`:''}</div>`;
export const fmtCompact = n=>Number.isFinite(Number(n))?new Intl.NumberFormat('vi-VN').format(Number(n)):esc(n);
