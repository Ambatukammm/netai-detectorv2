"""The dashboard pages (plain HTML/CSS/JS, no external assets): Monitor, Network & devices, SPAN."""
from . import __version__

CSS = r""".cmdline{color:#8ab4ff;font-weight:600}.err{color:#ff8d8d}

:root{color-scheme:dark;--bg:#0b1220;--panel:#121d30;--line:#26364e;--muted:#91a2ba;--text:#e8eef8;--accent:#4ea1ff;--warn:#ffd17a;--bad:#ff8d8d;--good:#8bd6a7}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:15px/1.5 Inter,Segoe UI,Arial,sans-serif}
header{padding:22px clamp(18px,4vw,56px);border-bottom:1px solid var(--line);display:flex;justify-content:space-between;align-items:center;gap:20px;flex-wrap:wrap}
h1{font-size:22px;margin:0}small,.muted{color:var(--muted)}main{max-width:1300px;margin:auto;padding:24px clamp(18px,4vw,56px)}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:14px}.card{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:18px}
.value{font-size:30px;font-weight:700;margin-top:8px}.section{margin:28px 0 12px;font-size:17px}
table{width:100%;border-collapse:collapse;font-size:13px}th,td{text-align:left;padding:11px 12px;border-bottom:1px solid var(--line);vertical-align:top}th{color:var(--muted);font-weight:600}
.high{color:var(--bad)}.medium{color:var(--warn)}.low{color:var(--good)}
.status{display:flex;align-items:center;gap:8px}.dot{width:9px;height:9px;border-radius:50%;background:#52d69a}.dot.busy{background:var(--warn)}.dot.bad{background:var(--bad)}
.banner{border:1px solid #6b5522;background:#2a2312;color:var(--warn);border-radius:10px;padding:10px 14px;margin-bottom:10px;font-size:14px}
.banner.demo{border-color:#2e4a73;background:#13243d;color:#9cc7ff}
.phase{display:flex;justify-content:space-between;align-items:center;gap:16px;flex-wrap:wrap}.phase h2{margin:0;font-size:18px}
.bar{height:8px;background:#1b2a42;border-radius:99px;overflow:hidden;margin-top:12px}.bar>div{height:100%;width:0;background:var(--accent);transition:width .4s}
button,.btn{background:#1b2d49;color:var(--text);border:1px solid var(--line);border-radius:8px;padding:8px 14px;font:inherit;cursor:pointer}button:hover{border-color:var(--accent)}
.actions{display:flex;gap:8px;flex-wrap:wrap}
#drop{border:2px dashed var(--line);border-radius:12px;padding:20px;text-align:center;color:var(--muted);transition:.15s}
#drop.over{border-color:var(--accent);color:var(--text);background:#10223a}#drop label{display:inline-flex;gap:6px;align-items:center;margin-top:8px;font-size:13px}
#dropmsg{margin-top:8px;color:var(--text);font-size:14px}
.inc-row{cursor:pointer}.inc-row:hover td{background:#16243b}.inc-row.sel td{background:#1a2b47}
.pill{display:inline-block;border:1px solid var(--line);border-radius:99px;padding:1px 9px;font-size:12px;color:var(--muted)}
.pill.open{color:var(--bad);border-color:#7a3a3a}.pill.closed{color:var(--muted)}
#detail{margin-top:14px}#detail h3{margin:0 0 4px;font-size:18px}#detail h4{margin:18px 0 6px;font-size:14px;color:var(--muted);text-transform:uppercase;letter-spacing:.04em}
#detail ol,#detail ul{margin:4px 0;padding-left:22px}#detail li{margin:5px 0}
.note{border-left:3px solid var(--accent);padding:6px 12px;background:#10223a;border-radius:6px;margin:10px 0}
.note.warn{border-color:var(--warn);background:#2a2312}
pre.cmd{background:#0a1422;border:1px solid var(--line);border-radius:8px;padding:9px 11px;margin:4px 0;white-space:pre-wrap;word-break:break-all;font:12.5px/1.45 Consolas,Menlo,monospace}
.cmdrow{display:flex;gap:8px;align-items:flex-start}.cmdrow pre{flex:1}.cmdrow button{padding:5px 10px;font-size:12px;margin-top:4px}
.two{display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:14px}
footer{text-align:center;padding:26px;color:var(--muted);border-top:1px solid var(--line);margin-top:40px}
@media(max-width:600px){header{align-items:flex-start;flex-direction:column}table{min-width:720px}.table-wrap{overflow:auto}}
nav{display:flex;gap:6px;flex-wrap:wrap}nav a{color:var(--muted);text-decoration:none;padding:7px 13px;border-radius:8px;border:1px solid transparent}
nav a:hover{color:var(--text);border-color:var(--line)}nav a.on{color:var(--text);background:#1b2d49;border-color:var(--line)}
.chip{display:inline-block;background:#16243b;border:1px solid var(--line);border-radius:6px;padding:0 6px;margin:1px 3px 1px 0;font-size:12px;white-space:nowrap}
.chip.risk{border-color:#6b5522;color:var(--warn)}input[type=text],select{background:#0a1422;color:var(--text);border:1px solid var(--line);border-radius:8px;padding:7px 10px;font:inherit}
.row{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin:8px 0}.small{font-size:12.5px}.ok{color:var(--good)}.bad{color:var(--bad)}
pre.log{background:#0a1422;border:1px solid var(--line);border-radius:8px;padding:8px 10px;font:12px/1.45 Consolas,Menlo,monospace;max-height:150px;overflow:auto;white-space:pre-wrap;margin:8px 0 0}
details{border:1px solid var(--line);border-radius:10px;padding:10px 14px;margin:8px 0;background:var(--panel)}summary{cursor:pointer;font-weight:600}
"""

SHARED_JS = r"""
const $=id=>document.getElementById(id);
const hdr=()=>{const h={'X-Requested-With':'netai'};try{const k=sessionStorage.getItem('netai_key');if(k)h['X-API-Key']=k}catch(e){}return h};
async function post(url,opts={}){
 let r=await fetch(url,{method:'POST',...opts,headers:{...hdr(),...(opts.headers||{})}});
 if(r.status===401){const k=prompt('This instance is protected. Enter the API key:');
  if(k){try{sessionStorage.setItem('netai_key',k)}catch(e){}r=await fetch(url,{method:'POST',...opts,headers:{...hdr(),...(opts.headers||{})}})}}
 const body=await r.json().catch(()=>({}));
 if(!r.ok)throw new Error(body.detail||('Request failed ('+r.status+')'));
 return body}
async function get(url){
 let r=await fetch(url,{headers:hdr()});
 if(r.status===401&&!askedKey){askedKey=true;const k=prompt('This instance is protected. Enter the API key:');
  if(k){try{sessionStorage.setItem('netai_key',k)}catch(e){}r=await fetch(url,{headers:hdr()})}}
 if(!r.ok)throw new Error('Request failed ('+r.status+')');
 return r.json()}
let askedKey=false;
const zfmt=z=>Math.abs(z)>99?(z>0?'>+99σ':'<−99σ'):(z>0?'+':'')+z+'σ';
function el(tag,props,...kids){const e=document.createElement(tag);Object.assign(e,props||{});for(const k of kids.flat()){if(k==null)continue;e.append(k instanceof Node?k:String(k))}return e}
const fmtBytes=b=>b>=1e6?(b/1e6).toFixed(1)+' MB':b>=1e3?(b/1e3).toFixed(0)+' KB':b+' B';
const when=t=>t?new Date(t).toLocaleString():'—';
function dur(a,b){if(!a||!b)return'';const s=Math.max(0,(new Date(b)-new Date(a))/1000);return s<90?Math.round(s)+'s':s<5400?Math.round(s/60)+' min':(s/3600).toFixed(1)+' h'}
const NAMES={};
async function del(url,question,after){if(!confirm(question))return;try{const r=await send('DELETE',url);if(after)after(r)}catch(e){alert(e.message)}}
const human=b=>b>=1e9?(b/1e9).toFixed(1)+' GB':b>=1e6?(b/1e6).toFixed(1)+' MB':b>=1e3?Math.round(b/1e3)+' KB':b+' B';
async function copy(text,btn){const label=btn.textContent;try{await navigator.clipboard.writeText(text);btn.textContent='Copied'}catch(e){btn.textContent='Select & copy manually'}setTimeout(()=>btn.textContent=label,1500)}

const who=ip=>ip&&NAMES[ip]?NAMES[ip]+' ('+ip+')':(ip||'');
function mainFlow(c){const f=c&&c.top_flows&&c.top_flows[0];return f?who(f.src)+' → '+who(f.dst)+' ('+f.proto.toUpperCase()+')':''}
async function send(method,url,data){
 const opts={method,headers:{...hdr(),'Content-Type':'application/json'},body:data===undefined?undefined:JSON.stringify(data)};
 let r=await fetch(url,opts);
 if(r.status===401){const k=prompt('This instance is protected. Enter the API key:');if(k){try{sessionStorage.setItem('netai_key',k)}catch(e){}opts.headers=hdr();opts.headers['Content-Type']='application/json';r=await fetch(url,opts)}}
 const b=await r.json().catch(()=>({}));if(!r.ok)throw new Error(b.detail||('Request failed ('+r.status+')'));return b}
async function pulse(){try{const s=await fetch('/api/status').then(r=>r.json());const t={starting:'Starting…',learning:'Learning',training:'Training',monitoring:'Monitoring',paused:'Paused',idle:'Waiting',error:'Needs attention',stopped:'Stopped'};
 $('health').textContent=t[s.phase]||s.phase;$('dot').className='dot'+(s.phase==='error'?' bad':(['learning','training','starting','idle'].includes(s.phase)?' busy':''));return s}catch(e){$('health').textContent='Service unavailable';$('dot').className='dot bad'}}
const elapsedText=sec=>{sec=Math.round(sec||0);const h=Math.floor(sec/3600),m=Math.floor(sec%3600/60);return h?h+'h '+m+'m':m?m+'m '+(sec%60)+'s':sec+'s'};
const ago=t=>{if(!t)return'—';const s=(Date.now()-new Date(t))/1000;return s<60?'just now':s<3600?Math.round(s/60)+' min ago':s<86400?Math.round(s/3600)+' h ago':new Date(t).toLocaleDateString()};
function portChips(ports){const keys=Object.keys(ports||{}).sort((a,b)=>parseInt(a.split('/')[1])-parseInt(b.split('/')[1]));
 if(!keys.length)return el('span',{className:'muted'},'—');
 return el('span',{},keys.map(k=>{const p=ports[k];return el('span',{className:'chip'+(p.risk?' risk':''),title:[p.service,p.product,p.risk,'seen by '+(p.source||'?')].filter(Boolean).join(' · ')},k.split('/')[1]+(k.startsWith('udp')?'/udp':'')+' '+(p.service||''))}))}
"""

PAGES = {"/": "Monitor", "/network": "Network & devices", "/span": "SPAN discovery",
         "/terminal": "Terminal", "/reports": "Reports", "/settings": "Settings"}


def page(path: str, body: str, script: str) -> str:
    on = ' class="on"'
    nav = "".join(f'<a href="{href}"{on if href == path else ""}>{label}</a>' for href, label in PAGES.items())
    title = "NetAI Detector" if path == "/" else f"{PAGES[path]} · NetAI Detector"
    return (f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title}</title><style>{CSS}</style></head><body>
<header><div><h1>◈ NetAI Detector</h1><small>Network monitoring, investigation &amp; discovery</small></div>
<nav>{nav}</nav>
<div class="status"><span class="dot" id="dot"></span><span id="health">Connecting…</span></div></header>
<main>{body}</main><footer>NetAI Detector · Made by Ruel · Version {__version__}</footer>
<script>{SHARED_JS}{script}</script></body></html>""")


MONITOR_BODY = r"""
<div id="banners"></div>
<div class="card"><div class="phase"><div><h2 id="phasetitle">Starting…</h2><div class="muted" id="phasemsg"></div></div>
<div class="actions"><button id="pausebtn">Pause</button><button id="relearnbtn" title="Forget the current baseline and learn normal traffic again">Relearn baseline</button></div></div>
<div class="bar" id="barwrap" hidden><div id="bar"></div></div></div>
<h2 class="section">Overview</h2>
<div class="grid">
<div class="card"><div class="muted">Events recorded</div><div class="value" id="events">—</div></div>
<div class="card"><div class="muted">Anomalies detected</div><div class="value" id="anomalies">—</div></div>
<div class="card"><div class="muted">High-severity incidents</div><div class="value" id="high">—</div></div>
<div class="card"><div class="muted">Incidents (open now)</div><div class="value" id="incidents">—</div></div>
<div class="card"><div class="muted">Model last trained</div><div class="value" id="trained" style="font-size:18px">—</div></div>
<div class="card"><div class="muted">Watching</div><div class="value" id="watching" style="font-size:18px;word-break:break-all">—</div></div>
</div>
<div class="row" style="justify-content:space-between;margin:26px 0 10px"><h2 class="section" style="margin:0">Incidents</h2><span class="actions"><button class="small" id="clearincidents">Clear ended incidents</button></span></div>
<p class="muted" style="margin-top:-6px">Consecutive flagged windows are grouped into one incident. Click one to see who was involved, what it looks like, and suggested next steps.</p>
<div class="card table-wrap"><table>
<thead><tr><th>#</th><th>Started</th><th>Status</th><th>Severity</th><th>Looks like</th><th>Main traffic</th><th>Windows</th><th>Evidence</th></tr></thead>
<tbody id="incrows"><tr><td colspan="8" class="muted">Loading…</td></tr></tbody></table></div>
<div id="detail" class="card" hidden></div>
<div class="actions" style="margin-top:12px"><button id="notifybtn">Enable browser notifications</button><button id="testalert">Send test alert</button><span class="muted" id="alertinfo" style="align-self:center;font-size:13px"></span></div>
<div class="row" style="justify-content:space-between;margin:26px 0 10px"><h2 class="section" style="margin:0">Recent detection events</h2><span class="actions"><button class="small" id="clearevents">Clear events</button></span></div><div class="card table-wrap"><table>
<thead><tr><th>Time</th><th>Source</th><th>Severity</th><th>Result</th><th>Score</th><th>Why flagged</th><th>Who</th></tr></thead>
<tbody id="rows"><tr><td colspan="7" class="muted">Loading events…</td></tr></tbody></table></div>
<h2 class="section">Analyse a capture file</h2>
<div id="drop"><div>Drop a <b>.pcap</b> / <b>.pcapng</b> file here, or <a href="#" id="pick">choose a file</a></div>
<label><input type="checkbox" id="asbase"> Use it as the new baseline of normal traffic</label>
<div id="dropmsg"></div><input type="file" id="file" accept=".pcap,.pcapng,.cap" hidden></div>
<p class="muted">This dashboard reports model outputs, not confirmed incidents. Validate alerts before taking action.</p>
"""
MONITOR_JS = r"""let selected=null,selectedSig='',maxIncident=null;
async function download(id){try{const r=await fetch('/api/incidents/'+id+'/evidence',{headers:hdr()});if(!r.ok)throw new Error((await r.json().catch(()=>({}))).detail||r.status);
 const blob=await r.blob();const name=(r.headers.get('Content-Disposition')||'').match(/filename="?([^";]+)/);const a=el('a',{href:URL.createObjectURL(blob),download:name?name[1]:'incident-'+id+'.pcap'});document.body.append(a);a.click();a.remove()}catch(e){alert('Could not download evidence: '+e.message)}}
function table(head,rows){return el('div',{className:'table-wrap'},el('table',{},el('thead',{},el('tr',{},head.map(h=>el('th',{},h)))),el('tbody',{},rows.map(r=>el('tr',{},r.map(v=>el('td',{},v)))))))}
async function showIncident(id,force){
 const d=await get('/api/incidents/'+id);const sig=d.status+d.windows+d.peak_severity+d.evidence_packets;
 if(!force&&selected===id&&sig===selectedSig)return;selected=id;selectedSig=sig;
 Object.assign(NAMES,d.names||{});const p=d.plan,box=$('detail');box.hidden=false;box.replaceChildren();
 box.append(el('div',{className:'phase'},el('div',{},el('h3',{},'Incident #'+d.id+' — '+p.title),
   el('div',{className:'muted'},(d.status==='open'?'Ongoing since ':'From ')+when(d.started_at)+(d.status==='open'?'':' to '+when(d.ended_at)+' ('+(d.close_reason||'closed')+')')+' · peak severity ',el('span',{className:d.peak_severity},d.peak_severity),d.severity_reason?' ('+d.severity_reason+')':'',' · '+d.windows+' flagged window(s) · source '+d.source)),
  el('div',{className:'actions'},d.evidence_available?el('button',{onclick:()=>download(d.id)},'Download evidence (.pcap)'):null,d.status!=='open'?el('button',{onclick:()=>del('/api/incidents/'+d.id,'Delete incident #'+d.id+(d.evidence_available?' and its evidence file':'')+'?',()=>{box.hidden=true;selected=null;refresh()})},'Delete'):null,el('button',{onclick:()=>{box.hidden=true;selected=null;renderIncidents(lastIncidents)}},'Close'))));
 if(String(d.source).startsWith('demo'))box.append(el('div',{className:'note'},'Simulated incident (demo mode). The addresses are made up.'));
 box.append(el('div',{className:'note'},el('b',{},'What is happening: '),p.summary,' ',el('span',{className:'muted'},'(confidence: '+p.confidence+')')));
 if(p.trusted_note)box.append(el('div',{className:'note warn'},p.trusted_note));
 if(p.also_seen&&p.also_seen.length)box.append(el('div',{className:'muted'},'Also matched: '+p.also_seen.join(', ')));
 const c=d.culprits||{};const left=el('div'),right=el('div');
 left.append(el('h4',{},'Who was involved'));
 if(c.top_flows&&c.top_flows.length)left.append(table(['From','To','Proto','Packets','Data','Ports'],c.top_flows.slice(0,6).map(f=>[who(f.src),who(f.dst),f.proto.toUpperCase(),f.packets,fmtBytes(f.bytes),f.distinct_dst_ports>5?f.distinct_dst_ports+' different':(f.top_dst_ports||[]).join(', ')])));
 else left.append(el('div',{className:'muted'},'No packet details were available for this incident.'));
 if(c.top_sources&&c.top_sources.length)left.append(el('div',{className:'muted',style:'margin-top:8px'},'Busiest senders: '+c.top_sources.slice(0,4).map(s=>who(s.ip)+(s.internal?' (your network)':' (outside)')).join(', ')));
 right.append(el('h4',{},'Why NetAI thinks so'),el('ul',{},(d.hints||[]).map(h=>el('li',{},el('b',{},h.title),' — '+h.evidence+' ',el('span',{className:'muted'},'['+h.confidence+(h.windows?', '+h.windows+' window(s)':'')+']')))));
 if(d.top_features&&d.top_features.length)right.append(el('div',{className:'muted'},'Biggest deviations from normal: '+d.top_features.map(f=>f.feature+' ('+zfmt(f.z)+')').join(', ')));
 box.append(el('div',{className:'two'},left,right));
 box.append(el('h4',{},'Suggested response'));
 for(const s of p.steps)box.append(el('div',{},el('b',{},s.phase),el('ol',{},s.items.map(i=>el('li',{},i)))));
 if(p.commands&&p.commands.length){box.append(el('h4',{},'Copy-paste commands (run only after confirming)'));
  for(const cmd of p.commands){const b1=el('button',{},'Copy'),b2=el('button',{},'Copy');b1.onclick=()=>copy(cmd.run,b1);b2.onclick=()=>copy(cmd.undo,b2);
   box.append(el('div',{},el('div',{className:'muted'},cmd.os),el('div',{className:'cmdrow'},el('pre',{className:'cmd'},cmd.run),b1),el('div',{className:'cmdrow'},el('pre',{className:'cmd',style:'opacity:.75'},'Undo: '+cmd.undo),b2)))}}
 box.append(el('h4',{},'Evidence'),el('div',{},d.evidence_note));
 box.append(el('p',{className:'muted'},p.disclaimer))}
let lastIncidents=[];
function renderIncidents(items){lastIncidents=items;const rows=$('incrows');rows.replaceChildren();
 if(!items.length){rows.append(el('tr',{},el('td',{colSpan:8,className:'muted'},'No incidents. Flagged traffic will be grouped here.')));return}
 for(const it of items){const h=(it.hints||[])[0];
  const tr=el('tr',{className:'inc-row'+(selected===it.id?' sel':''),onclick:()=>showIncident(it.id,true).then(()=>renderIncidents(lastIncidents)).catch(e=>alert(e.message))},
   el('td',{},it.id),el('td',{},when(it.started_at)),el('td',{},el('span',{className:'pill '+it.status},it.status==='open'?'ongoing':'ended'),' '+dur(it.started_at,it.ended_at||it.last_seen_at)),
   el('td',{className:it.peak_severity},it.peak_severity),el('td',{},h?h.title:'—'),el('td',{},mainFlow(it.culprits)),el('td',{},it.windows),el('td',{},it.evidence_available?'✓ '+it.evidence_packets+' pkts':'—'));
  rows.append(tr)}}
function notifyNew(items){if(!items.length)return;const top=items[0].id;
 if(maxIncident===null){maxIncident=top;return}
 for(const it of items.filter(i=>i.id>maxIncident).reverse()){
  if(window.Notification&&Notification.permission==='granted'&&!String(it.source).startsWith('demo')){
   const h=(it.hints||[])[0];try{new Notification('NetAI '+it.peak_severity.toUpperCase()+' — '+(h?h.title:'unusual traffic'),{body:mainFlow(it.culprits)})}catch(e){}}}
 maxIncident=Math.max(maxIncident,top)}
const TITLES={starting:'Starting…',learning:'Learning your normal traffic',training:'Training the model',monitoring:'Monitoring',paused:'Paused',idle:'Waiting',error:'Needs attention',stopped:'Stopped'};
let alertsSeen=null,paused=false;
function banner(text,cls){const d=document.createElement('div');d.className='banner '+(cls||'');d.textContent=text;return d}
async function refresh(){try{
 const [s,st,e,inc]=await Promise.all([fetch('/api/status').then(r=>r.json()),fetch('/api/stats').then(r=>r.json()),get('/api/events?limit=50'),get('/api/incidents?limit=30')]);
 Object.assign(NAMES,inc.names||{},e.names||{});renderIncidents(inc.items);notifyNew(inc.items);
 if(selected!==null&&inc.items.some(i=>i.id===selected))showIncident(selected,false).catch(()=>{});
 const a=s.investigation&&s.investigation.alerts;
 if(a)$('alertinfo').textContent='Alerts: '+[a.desktop&&'desktop',a.email&&'email',a.slack&&'Slack'].filter(Boolean).join(', ')+(a.desktop||a.email||a.slack?' (at '+a.min_severity+' severity and above)':'none configured')+' · Evidence files: '+(s.investigation.evidence==='off'?'off':s.investigation.evidence+' severity and above');
 if(window.Notification&&Notification.permission!=='default')$('notifybtn').hidden=true;
 paused=s.paused;
 $('health').textContent=TITLES[s.phase]||s.phase;
 $('dot').className='dot'+(s.phase==='error'?' bad':(['learning','training','starting','idle'].includes(s.phase)?' busy':''));
 $('phasetitle').textContent=TITLES[s.phase]||s.phase;$('phasemsg').textContent=s.message||'';
 const learning=s.phase==='learning';$('barwrap').hidden=!learning;
 if(learning){const p=s.progress;$('bar').style.width=Math.min(100,100*p.done/p.target)+'%';$('phasemsg').textContent=(s.message||'')+' ('+p.done+' of '+p.target+' samples)'}
 $('pausebtn').textContent=paused?'Resume':'Pause';
 const b=$('banners');b.replaceChildren();
 if(s.source==='demo'||(s.model&&s.model.simulated))b.appendChild(banner('DEMO MODE: the traffic below is simulated, not your real network. It switches to live monitoring automatically once packet capture is available.','demo'));
 (s.warnings||[]).forEach(w=>b.appendChild(banner(w)));
 $('incidents').textContent=st.incidents+' ('+st.open_incidents+')';$('events').textContent=st.events;$('anomalies').textContent=st.anomalies;$('high').textContent=st.high_incidents;
 $('trained').textContent=s.model&&s.model.trained_at?new Date(s.model.trained_at).toLocaleString():'—';
 $('watching').textContent=s.source==='demo'?'Simulated traffic':(s.interface||'—');
 if(alertsSeen===null)alertsSeen=st.anomalies;
 document.title=(st.anomalies>alertsSeen?'('+(st.anomalies-alertsSeen)+' new) ':'')+'NetAI Detector';
 const rows=$('rows');rows.replaceChildren();
 if(!e.items.length){const tr=rows.insertRow();const td=tr.insertCell();td.colSpan=7;td.className='muted';
  td.textContent=s.phase==='learning'?'Learning in progress. Events will appear once the baseline is ready.':'No events yet.';return}
 for(const it of e.items){const tr=document.createElement('tr');
  const dt=it.details||{};const hint=(dt.hints||[])[0];
  const feats=(dt.top_features||[]).map(f=>f.feature+' ('+zfmt(f.z)+')').join(', ');
  const why=(hint&&hint.type!=='unknown'?hint.title+(dt.incident_id?' · incident #'+dt.incident_id:'')+(feats?' — ':''):(dt.incident_id?'incident #'+dt.incident_id+' — ':''))+feats||(dt.simulated_scenario&&dt.simulated_scenario!=='normal'?'simulated: '+dt.simulated_scenario:'');
  [new Date(it.created_at).toLocaleString(),it.source,it.severity,it.is_anomaly?'Anomaly':'Normal',it.score==null?'—':Number(it.score).toFixed(4),why,mainFlow(dt.culprits)].forEach((v,i)=>{const td=document.createElement('td');td.textContent=v;if(i===2)td.className=it.severity;tr.appendChild(td)});
  rows.appendChild(tr)}
 }catch(err){$('health').textContent='Service unavailable';$('dot').className='dot bad'}}
$('clearincidents').onclick=()=>del('/api/incidents','Delete all ended incidents and their evidence files? Ongoing incidents are kept.',()=>{$('detail').hidden=true;selected=null;refresh()});
$('clearevents').onclick=()=>del('/api/events','Clear all detection events? Incidents, reports and the learned baseline are kept.',refresh);
$('notifybtn').onclick=()=>{if(!window.Notification){alert('This browser does not support notifications.');return}Notification.requestPermission().then(()=>refresh())};
$('testalert').onclick=()=>post('/api/alerts/test').then(r=>alert(Object.entries(r.results).map(([k,v])=>k+': '+v).join('\n'))).catch(e=>alert(e.message));
$('pausebtn').onclick=()=>post('/api/monitor/'+(paused?'resume':'pause')).then(refresh).catch(e=>alert(e.message));
$('relearnbtn').onclick=()=>{if(confirm('Learn normal traffic again? The current model keeps working until the new one is ready.'))post('/api/monitor/relearn').then(refresh).catch(e=>alert(e.message))};
async function upload(f){if(!f)return;$('dropmsg').textContent='Analysing '+f.name+'…';
 try{const r=await post('/api/pcap?name='+encodeURIComponent(f.name)+'&baseline='+$('asbase').checked,{body:f,headers:{'Content-Type':'application/octet-stream'}});
  $('dropmsg').textContent=r.message;refresh()}catch(e){$('dropmsg').textContent='Could not analyse file: '+e.message}}
const drop=$('drop');
['dragenter','dragover'].forEach(n=>drop.addEventListener(n,e=>{e.preventDefault();drop.classList.add('over')}));
['dragleave','drop'].forEach(n=>drop.addEventListener(n,e=>{e.preventDefault();drop.classList.remove('over')}));
drop.addEventListener('drop',e=>upload(e.dataTransfer.files[0]));
$('pick').onclick=e=>{e.preventDefault();$('file').click()};$('file').onchange=e=>{upload(e.target.files[0]);e.target.value=''};
refresh();setInterval(refresh,3000);
"""
NETWORK_BODY = r"""
<div class="card"><div class="phase"><div><h2>Network &amp; devices</h2>
<div class="muted">Find every device on your subnets and VLANs with nmap, name them, and see what they're running.</div></div>
<div id="nmapinfo" class="small muted">Checking for nmap…</div></div></div>
<div id="nmapwarn"></div>
<h2 class="section">1. Choose subnets and VLANs</h2>
<div class="card"><p class="muted small" style="margin-top:0">Suggested from this computer's interfaces, its routes to other VLANs, addresses seen in traffic, and your own list. You can only scan VLANs this computer can reach through your router/firewall.</p>
<div class="table-wrap"><table><thead><tr><th></th><th>Subnet</th><th>Found from</th><th>Detail</th><th>Addresses</th><th></th></tr></thead><tbody id="subnets"><tr><td colspan="6" class="muted">Loading…</td></tr></tbody></table></div>
<div class="row"><input type="text" id="newsubnet" placeholder="Add a subnet/VLAN, e.g. 192.168.30.0/24" size="34"><button id="addsubnet">Add</button></div></div>
<h2 class="section">2. Scan</h2>
<div class="card"><div class="row"><label>Scan type <select id="profile"></select></label>
<input type="text" id="exclude" placeholder="Skip these addresses (optional), e.g. 192.168.15.1" size="36"></div>
<div class="row"><label><input type="checkbox" id="authorised"> I own these networks or am authorised to scan them</label></div>
<div class="row"><button id="startscan">Start scan</button><button id="cancelscan" hidden>Cancel</button><span id="scanmsg" class="muted small"></span></div>
<div class="bar" id="scanbarwrap" hidden><div id="scanbar"></div></div><pre class="log" id="scanlog" hidden></pre>
</div>
<div class="row" style="justify-content:space-between;margin:26px 0 10px"><h2 class="section" style="margin:0">Scan history</h2><span class="actions"><button class="small" id="clearscans">Clear scan history</button></span></div>
<div class="card table-wrap"><p class="muted small" style="margin-top:0">Every scan's results are stored on this computer. Aya reviews each finished scan and compares it with the previous scan of the same networks.</p>
<table><thead><tr><th>When</th><th>Scanned</th><th>Type</th><th>Result</th><th>Aya's review</th><th>Data</th></tr></thead><tbody id="jobs"><tr><td colspan="6" class="muted">No scans yet.</td></tr></tbody></table></div>
<div class="row" style="justify-content:space-between;margin:26px 0 10px"><h2 class="section" style="margin:0">3. Device inventory</h2><span class="actions"><button class="small" id="cleardevices">Clear inventory</button></span></div>
<div class="card">
<div class="row"><input type="text" id="filter" placeholder="Search name, IP, vendor, OS, port…" size="30">
<label class="small">Sort <select id="sort">
<option value="relevant">Most relevant first</option><option value="newest">Newest devices first</option><option value="oldest">Oldest devices first</option>
<option value="name">Name A → Z</option><option value="name_desc">Name Z → A</option><option value="ip">IP address</option>
<option value="seen">Last seen (recent first)</option><option value="ports">Most open ports</option></select></label>
<label class="small">Status <select id="fstatus"><option value="">All</option><option value="online">Online</option><option value="offline">Offline</option><option value="unknown">Unknown</option></select></label>
<label class="small">Found by <select id="fsource"><option value="">Anything</option><option value="nmap">nmap scans</option><option value="passive">Traffic (SPAN)</option><option value="manual">Added by you</option></select></label>
<label class="small">Added <select id="fage"><option value="">Any time</option><option value="1">Last 24 hours</option><option value="7">Last 7 days</option><option value="30">Last 30 days</option></select></label>
<label class="small">Names <select id="fnamed"><option value="">All</option><option value="named">Named</option><option value="unnamed">Unnamed</option></select></label>
<label class="small"><input type="checkbox" id="riskyonly"> Risky services only</label>
<label class="small"><input type="checkbox" id="portsonly"> With open ports</label>
<button class="small" id="resetfilters">Reset</button></div>
<div class="row small" style="background:#10223a;border:1px solid var(--line);border-radius:10px;padding:10px 12px">
<b>Port &amp; OS scan of inventory devices</b><span class="muted">(skips device discovery: goes straight to the devices below)</span>
<select id="invprofile"></select>
<select id="invscope"></select>
<button id="invscan">Scan ports</button><span id="invmsg" class="muted"></span></div>
<div class="row"><span id="devcount" class="muted small"></span><span style="flex:1"></span><span id="selcount" class="muted small"></span></div>
<div class="table-wrap"><table><thead><tr><th><input type="checkbox" id="selall" title="Select all shown"></th><th>Device</th><th>IP</th><th>Hardware</th><th>Open ports / services</th><th>Seen by</th><th>Last seen</th><th></th></tr></thead><tbody id="devices"><tr><td colspan="8" class="muted">Loading…</td></tr></tbody></table></div>
<p class="muted small">Names come from (best first): your label, the nmap hostname, the Windows computer name (NetBIOS), reverse DNS. Ports marked in yellow are worth a second look; hover for why.</p></div>
"""
NETWORK_JS = r"""
let devs=[],scanning=false;
async function loadNetwork(){try{const n=await get('/api/network');
 const i=n.nmap;$('nmapinfo').textContent=i.installed?('nmap '+(i.version||'')+' ready'):'nmap not installed';
 $('nmapwarn').replaceChildren(...(i.installed?[]:[el('div',{className:'banner'},i.hint)]));$('startscan').disabled=!i.installed;
 const sel=$('profile');if(!sel.options.length)for(const [k,v] of Object.entries(n.scan.profiles))sel.append(el('option',{value:k},v));
 const ip=$('invprofile');if(!ip.options.length)for(const [k,v] of Object.entries(n.scan.inventory_profiles||{}))ip.append(el('option',{value:k},v.replace('Inventory: ','')));
 const rows=$('subnets');rows.replaceChildren();
 if(!n.subnets.length)rows.append(el('tr',{},el('td',{colSpan:6,className:'muted'},'No subnets found yet. Add one below.')));
 for(const s of n.subnets){const cb=el('input',{type:'checkbox',value:s.cidr,checked:s.source==='this computer'||!!s.custom});cb.className='subnet';
  rows.append(el('tr',{},el('td',{},cb),el('td',{},el('b',{},s.cidr)),el('td',{},s.source),el('td',{className:'muted'},s.detail||''),el('td',{},s.hosts.toLocaleString()+(s.internal?'':' (public!)')),
   el('td',{},s.custom?el('button',{className:'small',onclick:()=>saveSubnets(n.custom.filter(c=>c!==s.cidr))},'Remove'):'')))}
 window._custom=n.custom;renderScan(n.scan)}catch(e){$('nmapinfo').textContent='Could not load: '+e.message}}
async function saveSubnets(list){try{await send('POST','/api/network/subnets',{subnets:list});loadNetwork()}catch(e){alert(e.message)}}
$('addsubnet').onclick=()=>{const v=$('newsubnet').value.trim();if(!v)return;saveSubnets([...(window._custom||[]),v]).then(()=>$('newsubnet').value='')};
const openTargets=new Set();
/* Short summary of what a scan covered; long device lists collapse behind "show all". */
function targetCell(targets){const num=t=>t.split('/')[0].split('.').reduce((a,b)=>a*256+(+b),0);
 const items=[...targets].sort((x,y)=>num(x)-num(y)).map(t=>t.replace(/\/32$/,''));
 if(items.length<=3)return items.join(', ');
 const key=targets.join(','),open=openTargets.has(key),singles=targets.every(t=>t.endsWith('/32'));
 const toggle=el('button',{className:'small',style:'padding:1px 8px;margin-left:6px',onclick:()=>{open?openTargets.delete(key):openTargets.add(key);renderJobs(window._jobs||[])}},open?'hide':'show all');
 const label=el('b',{},items.length+(singles?' devices':' networks/devices'));
 if(!open)return el('span',{},label,el('span',{className:'muted'},' · '+items.slice(0,3).join(', ')+' …'),toggle);
 return el('div',{},label,toggle,el('div',{className:'muted',style:'margin-top:4px;max-height:160px;overflow:auto;font-family:Consolas,Menlo,monospace;font-size:12px;line-height:1.5'},items.join(', ')))}
function renderScan(st){const c=st.current;if(!st.jobs.length&&window._jobs)st.jobs=window._jobs;window._jobs=st.jobs;scanning=!!(c&&c.status==='running');
 $('cancelscan').hidden=!scanning;$('startscan').hidden=scanning;$('scanbarwrap').hidden=!c;$('scanlog').hidden=!(c&&c.log&&c.log.length);
 if(c){$('scanbar').style.width=(c.progress||0)+'%';$('scanmsg').textContent=(scanning?'Scanning '+(c.targets.length>3?c.targets.length+' devices':c.targets.map(t=>t.replace('/32','')).join(', '))+' · '+(c.phase||'')+' · '+Math.round(c.progress||0)+'%'+(c.remaining?' · about '+c.remaining+' left':'')+' · running '+elapsedText(c.elapsed):c.message||c.status);$('scanlog').textContent=(c.log||[]).join('\n')}
 renderJobs(st.jobs)}
function renderJobs(jobs){const PN={discover:'Find devices',ports:'Top 100 ports',services:'1000 ports + versions',inventory:'Inventory: 1000 ports + OS',inventory_full:'Inventory: all ports + OS',terminal:'Terminal'};
 $('jobs').replaceChildren(...(jobs.length?jobs.map(j=>{const done=j.status==='done';
  const rev=j.report_id?el('div',{className:'actions',style:'flex-wrap:nowrap'},el('a',{href:'/reports?view='+j.report_id,className:'btn small',style:'text-decoration:none;padding:4px 9px;white-space:nowrap'},'Read review'),el('button',{className:'small',style:'padding:4px 9px;white-space:nowrap',onclick:e=>reReview(j.id,e.target)},'Ask Aya again')):done?el('span',{className:'muted small'},'Aya is reviewing…'):el('span',{className:'muted small'},'—');
  const data=done?el('div',{className:'actions',style:'flex-wrap:nowrap'},el('button',{className:'small',style:'padding:4px 9px',onclick:()=>dlScan(j.id,'csv')},'CSV'),el('button',{className:'small',style:'padding:4px 9px',onclick:()=>dlScan(j.id,'json')},'JSON')):'';
  return el('tr',{},el('td',{className:'small'},when(j.started_at)),el('td',{className:'small'},targetCell(j.targets)),el('td',{className:'small'},PN[j.profile]||j.profile),
   el('td',{className:'small'+(done?'':' muted')},j.status+(j.hosts_up!=null?' · '+j.hosts_up+' device(s)':'')),el('td',{},rev),el('td',{},el('div',{className:'actions',style:'flex-wrap:nowrap'},data,j.status!=='running'?el('button',{className:'small',style:'padding:4px 9px',onclick:()=>del('/api/scans/'+j.id,'Delete this scan, its stored results and Aya’s review? (Devices it found stay in the inventory.)',()=>{window._jobs=null;pollScan()})},'Delete'):'')))}):[el('tr',{},el('td',{colSpan:6,className:'muted'},'No scans yet.'))]))}
async function pollScan(){try{const st=await get('/api/scan');const was=scanning;renderScan(st);if(was&&!scanning){loadDevices();setTimeout(pollScan,2500)}}catch(e){}}
async function dlScan(id,fmt){try{const r=await fetch('/api/scans/'+id+'/results?format='+fmt,{headers:hdr()});if(!r.ok)throw new Error('Request failed ('+r.status+')');
 const blob=fmt==='csv'?await r.blob():new Blob([JSON.stringify(await r.json(),null,1)],{type:'application/json'});const a=el('a',{href:URL.createObjectURL(blob),download:'netai-scan-'+id+'.'+fmt});document.body.append(a);a.click();a.remove()}catch(e){alert(e.message)}}
async function reReview(id,btn){btn.disabled=true;btn.textContent='Aya is reviewing…';try{const r=await send('POST','/api/scans/'+id+'/review');location.href='/reports?view='+r.report_id}catch(e){alert(e.message);btn.disabled=false;btn.textContent='Ask Aya again'}}
$('startscan').onclick=async()=>{const targets=[...document.querySelectorAll('input.subnet:checked')].map(c=>c.value);
 const exclude=$('exclude').value.split(/[\s,]+/).filter(Boolean);
 try{renderScan({current:await send('POST','/api/scan',{targets,profile:$('profile').value,exclude,authorised:$('authorised').checked}),jobs:[]});pollScan()}catch(e){alert(e.message)}};
$('cancelscan').onclick=()=>send('POST','/api/scan/cancel').then(pollScan).catch(e=>alert(e.message));
async function loadDevices(){try{const d=await get('/api/devices');devs=d.items;renderDevices()}catch(e){$('devices').replaceChildren(el('tr',{},el('td',{colSpan:7,className:'muted'},'Could not load devices: '+e.message)))}}
const ipNum=ip=>ip.split('.').reduce((a,b)=>a*256+(+b),0);
const RISK_W={23:100,69:100,5900:100,6379:100,27017:100,21:40,1883:40,3389:20};
const ageDays=t=>t?(Date.now()-new Date(t))/864e5:1e9;
function relevance(d){let r=0;for(const k of Object.keys(d.ports)){const port=+k.split('/')[1];if(d.ports[k].risk||RISK_W[port])r+=RISK_W[port]||10}
 if(ageDays(d.first_seen)<7)r+=30;if(!d.name)r+=5;if(d.up)r+=3;return r}
const SORTS={relevant:(a,b)=>relevance(b)-relevance(a)||ipNum(a.ip)-ipNum(b.ip),newest:(a,b)=>(b.first_seen||'').localeCompare(a.first_seen||''),
 oldest:(a,b)=>(a.first_seen||'').localeCompare(b.first_seen||''),name:(a,b)=>(!a.name)-(!b.name)||(a.name||'').localeCompare(b.name||'',undefined,{numeric:true,sensitivity:'base'})||ipNum(a.ip)-ipNum(b.ip),
 name_desc:(a,b)=>(!a.name)-(!b.name)||(b.name||'').localeCompare(a.name||'',undefined,{numeric:true,sensitivity:'base'}),ip:(a,b)=>ipNum(a.ip)-ipNum(b.ip),
 seen:(a,b)=>(b.last_seen||'').localeCompare(a.last_seen||''),ports:(a,b)=>Object.keys(b.ports).length-Object.keys(a.ports).length||ipNum(a.ip)-ipNum(b.ip)};
const FILTERS=['filter','sort','fstatus','fsource','fage','fnamed','riskyonly','portsonly'];
const selected=new Set();let shown=[];
function saveFilters(){try{localStorage.setItem('netai_inv',JSON.stringify(Object.fromEntries(FILTERS.map(f=>[f,$(f).type==='checkbox'?$(f).checked:$(f).value]))))}catch(e){}}
function loadFilters(){try{const v=JSON.parse(localStorage.getItem('netai_inv')||'{}');for(const f of FILTERS)if(f in v){if($(f).type==='checkbox')$(f).checked=v[f];else $(f).value=v[f]}}catch(e){}}
function visible(){const q=$('filter').value.toLowerCase(),st=$('fstatus').value,src=$('fsource').value,age=+$('fage').value,nm=$('fnamed').value;
 return devs.filter(d=>(!$('riskyonly').checked||Object.values(d.ports).some(p=>p.risk))&&(!$('portsonly').checked||Object.keys(d.ports).length)
  &&(!st||(st==='online'?d.up===true:st==='offline'?d.up===false:d.up==null))&&(!src||d.seen_by.includes(src))&&(!age||ageDays(d.first_seen)<=age)
  &&(!nm||(nm==='named')===!!d.name)
  &&(!q||JSON.stringify([d.name,d.ip,d.vendor,d.mac,d.os,Object.keys(d.ports),Object.values(d.ports).map(p=>p.service)]).toLowerCase().includes(q))).sort(SORTS[$('sort').value]||SORTS.relevant)}
function scopeOptions(){const sc=$('invscope'),cur=sc.value;const online=devs.filter(d=>d.up!==false).length;sc.replaceChildren(
 el('option',{value:'shown'},'Devices shown below ('+shown.length+')'),el('option',{value:'selected',disabled:!selected.size},'Selected devices ('+selected.size+')'),
 el('option',{value:'online'},'Inventory, not offline ('+online+')'),el('option',{value:'all'},'Whole inventory ('+devs.length+')'));
 if(cur&&!(cur==='selected'&&!selected.size))sc.value=cur;else if(selected.size)sc.value='selected'}
function selectionChanged(){$('selcount').textContent=selected.size?selected.size+' selected':'';$('selall').checked=shown.length>0&&shown.every(d=>selected.has(d.ip));scopeOptions();
 if(selected.size)$('invscope').value='selected'}
function renderDevices(){const rows=$('devices');rows.replaceChildren();shown=visible();saveFilters();
 for(const ip of [...selected])if(!devs.some(d=>d.ip===ip))selected.delete(ip);
 $('devcount').textContent=shown.length+' of '+devs.length+' devices';$('selcount').textContent=selected.size?selected.size+' selected':'';
 $('selall').checked=shown.length>0&&shown.every(d=>selected.has(d.ip));scopeOptions();
 if(!shown.length)rows.append(el('tr',{},el('td',{colSpan:8,className:'muted'},devs.length?'No devices match these filters.':'No devices yet. Run a scan, or let NetAI discover them from traffic (see SPAN discovery).')));
 for(const d of shown){const st=d.up===false?el('span',{className:'bad small'},' offline'):d.up?el('span',{className:'ok small'},' online'):'';
  const cb=el('input',{type:'checkbox',checked:selected.has(d.ip),onchange:e=>{e.target.checked?selected.add(d.ip):selected.delete(d.ip);selectionChanged()}});
  const rename=el('button',{className:'small',style:'padding:4px 9px;white-space:nowrap',onclick:async()=>{const v=prompt('Name for '+d.ip+' (leave empty to clear):',d.label||d.name||'');if(v===null)return;try{await send('POST','/api/devices/'+d.ip+'/label',{label:v});loadDevices()}catch(e){alert(e.message)}}},'Rename');
  const scan=el('button',{className:'small',style:'padding:4px 9px;white-space:nowrap',title:'nmap: 1000 ports, service versions and OS, without device discovery',onclick:()=>inventoryScan([d.ip],'inventory')},'Scan ports');
  const isNew=ageDays(d.first_seen)<1;
  rows.append(el('tr',{},el('td',{},cb),el('td',{},el('b',{},d.name||'—'),st,isNew?el('span',{className:'chip',style:'margin-left:6px;color:var(--accent)'},'new'):null,d.label?el('div',{className:'muted small'},'your label'):null),el('td',{},d.ip),
   el('td',{className:'small'},[d.vendor,d.mac,d.os].filter(Boolean).join(' · ')||'—'),el('td',{},portChips(d.ports)),el('td',{className:'small'},d.seen_by.join(', ')),
   el('td',{className:'small'},ago(d.last_seen),el('div',{className:'muted'},'added '+ago(d.first_seen))),el('td',{},el('div',{className:'actions',style:'flex-wrap:nowrap'},rename,scan,el('button',{className:'small',style:'padding:4px 9px',onclick:()=>del('/api/devices/'+d.ip,'Forget '+(d.name||d.ip)+'? It will reappear if it’s seen or scanned again.',loadDevices)},'Forget')))))}}
async function inventoryScan(ips,profile){if(!ips.length){alert('No devices to scan.');return}
 if(!$('authorised').checked){if(!confirm('Do you own these devices or have permission to scan them?'))return;$('authorised').checked=true}
 const full=profile==='inventory_full';
 if(ips.length>1&&!confirm('Scan '+ips.length+' device(s): '+(full?'all 65,535 ports, versions and OS. This can take many hours on a large inventory.':'top 1000 ports, versions and OS. Roughly a few minutes per batch of devices.')+'\n\nThere is no time limit; you can cancel at any time and keep what was finished.'))return;
 try{renderScan({current:await send('POST','/api/scan',{targets:ips.map(ip=>ip+'/32'),profile,authorised:true}),jobs:[]});$('invmsg').textContent='';window.scrollTo({top:0,behavior:'smooth'})}catch(e){alert(e.message)}}
$('invscan').onclick=()=>{const sc=$('invscope').value;const ips=sc==='selected'?[...selected]:sc==='all'?devs.map(d=>d.ip):sc==='online'?devs.filter(d=>d.up!==false).map(d=>d.ip):shown.map(d=>d.ip);inventoryScan(ips,$('invprofile').value)};
$('selall').onchange=e=>{for(const d of shown)e.target.checked?selected.add(d.ip):selected.delete(d.ip);
 document.querySelectorAll('#devices input[type=checkbox]').forEach(c=>c.checked=e.target.checked);selectionChanged()};
$('resetfilters').onclick=()=>{for(const f of FILTERS){if($(f).type==='checkbox')$(f).checked=false;else $(f).value=f==='sort'?'relevant':''}renderDevices()};
for(const f of FILTERS)$(f)[f==='filter'?'oninput':'onchange']=renderDevices;
loadFilters();
$('clearscans').onclick=()=>del('/api/scans','Delete the whole scan history (stored results and Aya’s scan reviews)? Running scans are kept.',()=>{window._jobs=null;pollScan()});
$('cleardevices').onclick=()=>del('/api/devices','Clear the whole device inventory, including your device names? Devices reappear as they’re seen or scanned again.',loadDevices);
pulse();loadNetwork();loadDevices();setInterval(pollScan,2000);setInterval(loadDevices,15000);setInterval(pulse,5000);
"""
SPAN_BODY = r"""
<div class="card"><div class="phase"><div><h2>SPAN discovery</h2>
<div class="muted">Listen to a switch's mirror (SPAN) port and map every device and the services it offers, without sending a single packet. Use <a href="/network" style="color:var(--accent)">Network &amp; devices</a> to actively port-scan any of them.</div></div></div></div>
<div class="grid" style="margin-top:14px">
<div class="card"><div class="muted">Mirroring</div><div class="value" id="mirror" style="font-size:20px">—</div><div class="muted small" id="mirrormsg"></div></div>
<div class="card"><div class="muted">Listening on</div><div class="value" id="iface" style="font-size:20px;word-break:break-all">—</div><div class="muted small" id="ifacemsg"></div></div>
<div class="card"><div class="muted">Packets examined</div><div class="value" id="pkts">—</div></div>
<div class="card"><div class="muted">Devices / services found</div><div class="value" id="found">—</div></div>
</div>
<h2 class="section">Services discovered</h2>
<div class="card"><div class="row"><input type="text" id="filter" placeholder="Search device, IP, service, port…" size="34"><label class="small"><input type="checkbox" id="riskyonly"> Only risky services</label><span id="svccount" class="muted small"></span></div>
<div class="table-wrap"><table><thead><tr><th>Device</th><th>IP</th><th>Service</th><th>Port</th><th>Found by</th><th>Last seen</th><th>Why it matters</th></tr></thead><tbody id="services"><tr><td colspan="7" class="muted">Loading…</td></tr></tbody></table></div>
<p class="muted small">Passive discovery only sees services that are actually used while NetAI listens (a server answering a connection). Quiet services won't appear until something talks to them; an active nmap scan finds those.</p></div>
<h2 class="section">Setting up a SPAN / mirror port</h2>
<div class="card small"><p style="margin-top:0">1. Pick a free switch port as the <b>destination</b> and plug a <b>second network card</b> of this computer into it (keep your normal connection on the first). 2. Mirror the uplink to your router/firewall (sees traffic between VLANs and to the internet) or the ports/VLANs you care about, <b>both directions</b>. 3. Set <code>NETAI_INTERFACE</code> in <code>.env</code> to that card's name (shown under <i>Listening on</i>) and restart. On Windows, install <a style="color:var(--accent)" href="https://npcap.com" target="_blank" rel="noopener">Npcap</a> (included with nmap) so NetAI can capture in promiscuous mode. Don't mirror more traffic than the destination port's speed, or packets are dropped.</p></div>
<details><summary>Cisco IOS / IOS-XE (Catalyst)</summary><pre class="cmd">monitor session 1 source interface Gi1/0/1 - 24 both
monitor session 1 destination interface Gi1/0/48
! or mirror whole VLANs instead of ports (one or the other per session):
! monitor session 1 source vlan 10,20,30 both
show monitor session 1</pre><div class="muted">Remove with <code>no monitor session 1</code>.</div></details>
<details><summary>HPE Aruba (AOS-CX)</summary><pre class="cmd">mirror session 1
  destination interface 1/1/48
  source interface 1/1/1 both
  enable</pre><div class="muted">Older ProCurve/AOS-S: <code>mirror-port 48</code>, then <code>interface 1-24 monitor</code>.</div></details>
<details><summary>Ubiquiti UniFi</summary><div>UniFi Network → Devices → your switch → Ports → select the destination port → set its operation to <b>Mirroring</b> and choose the port to mirror (e.g. the uplink) → Apply.</div></details>
<details><summary>Netgear smart / managed switches</summary><div>Web UI → Monitoring (or System) → Mirroring → Port Mirroring: tick the source ports, choose the destination port, Direction: Tx and Rx, enable.</div></details>
<details><summary>MikroTik (CRS series)</summary><pre class="cmd">/interface ethernet switch set switch1 mirror-source=ether2 mirror-target=ether8</pre><div class="muted">RouterOS 7 per-port: <code>/interface ethernet switch rule add switch=switch1 ports=ether2 mirror=yes</code> with <code>mirror-target=ether8</code> on the switch.</div></details>
<details><summary>No managed switch?</summary><div>Use a cheap network TAP or a small managed switch with port mirroring between your router and main switch, or run NetAI on the router/firewall itself. Without mirroring NetAI still sees this computer's own traffic and everything it talks to.</div></details>
"""
SPAN_JS = r"""
let svcs=[];
async function loadSpan(){try{const s=await pulse();const d=await get('/api/span');const p=d.status;
 const m=p.mirroring_detected;$('mirror').textContent=m===true?'Working':m===false?'Not detected':'Measuring…';$('mirror').className='value '+(m===true?'ok':m===false?'medium':'');
 $('mirrormsg').textContent=!p.enabled?'Passive discovery is off (NETAI_PASSIVE_DISCOVERY=0).':m===true?Math.round(p.foreign_traffic_ratio*100)+'% of packets are between other devices: the mirror is delivering traffic.':m===false?'Only this computer’s own traffic is visible ('+Math.round((p.foreign_traffic_ratio||0)*100)+'% other). Set up SPAN below to see the whole network.':'Needs a few hundred live packets.';
 $('iface').textContent=d.source==='demo'?'Demo (no live capture)':(d.interface||'—');$('ifacemsg').textContent=d.source==='demo'?'Passive discovery needs live capture.':'This computer: '+p.local_ips.filter(i=>i!=='127.0.0.1').join(', ');
 $('pkts').textContent=p.packets_seen.toLocaleString();$('found').textContent=d.devices+' / '+d.items.length;
 svcs=d.items;renderSvcs()}catch(e){$('services').replaceChildren(el('tr',{},el('td',{colSpan:7,className:'muted'},'Could not load: '+e.message)))}}
function renderSvcs(){const q=$('filter').value.toLowerCase(),risky=$('riskyonly').checked,rows=$('services');rows.replaceChildren();
 const list=svcs.filter(s=>(!risky||s.risk)&&(!q||[s.name,s.ip,s.service,s.port,s.product].join(' ').toLowerCase().includes(q)));
 $('svccount').textContent=list.length+' of '+svcs.length+' services';
 if(!list.length)rows.append(el('tr',{},el('td',{colSpan:7,className:'muted'},svcs.length?'No services match.':'Nothing yet. Services appear as devices answer connections in the traffic NetAI can see.')));
 for(const s of list)rows.append(el('tr',{},el('td',{},el('b',{},s.name||'—')),el('td',{},s.ip),el('td',{},s.service+(s.product?' · '+s.product:'')),el('td',{},s.port+'/'+s.proto),
  el('td',{className:'small'},s.source),el('td',{className:'small'},ago(s.last_seen)),el('td',{className:'small'+(s.risk?' medium':' muted')},s.risk||'—')))}
$('filter').oninput=renderSvcs;$('riskyonly').onchange=renderSvcs;
loadSpan();setInterval(loadSpan,5000);
"""

REPORTS_BODY = r"""
<div class="card"><div class="phase"><div><h2>Reports</h2>
<div class="muted">Plain-English reports with a health grade, prioritised findings and what changed since last time, each reviewed by Aya, your local AI analyst. Every finished scan gets Aya's review automatically. Reports are stored on this computer.</div></div></div></div>
<h2 class="section">Create a report</h2>
<div class="card"><div class="row" id="kinds"></div>
<div class="row small"><span style="width:26px;height:26px;border-radius:50%;background:#7c4dff;color:#fff;font-weight:700;display:inline-flex;align-items:center;justify-content:center">A</span><span id="ayahint" class="muted"></span></div>
<div id="createmsg" class="muted small"></div></div>
<div class="row" style="justify-content:space-between;margin:26px 0 10px"><h2 class="section" style="margin:0">Saved reports</h2><span class="actions"><button class="small" id="delallreports">Delete all reports</button></span></div>
<div class="card table-wrap"><table><thead><tr><th>Created</th><th>Report</th><th>Grade</th><th></th></tr></thead><tbody id="reports"><tr><td colspan="4" class="muted">Loading…</td></tr></tbody></table></div>
<div id="viewer" class="card" style="margin-top:14px;padding:0;overflow:hidden" hidden><div class="row" style="padding:10px 14px;margin:0;border-bottom:1px solid var(--line)"><b id="viewtitle"></b><span style="flex:1"></span><button id="closeview">Close</button></div>
<div id="reporthost" style="max-height:1100px;overflow:auto;background:#f4f6f9"></div></div>
"""
REPORTS_JS = r"""
let info=null;
async function loadReports(){try{info=await get('/api/reports');
 const k=$('kinds');if(!k.children.length)for(const [kind,label] of Object.entries(info.kinds))k.append(el('button',{onclick:()=>create(kind)},label));
 $('ayahint').textContent=info.aya_uses_model?'Aya reviews each report with your local model ('+info.aya_model+'). Local models can take a few minutes.':'Aya reviews each report with her built-in analysis. Connect a local model in Settings for richer reviews.';
 const rows=$('reports');rows.replaceChildren();
 if(!info.items.length)rows.append(el('tr',{},el('td',{colSpan:4,className:'muted'},'No reports yet. Create one above.')));
 for(const r of info.items){const mail=el('button',{className:'small',disabled:!info.email_ready,title:info.email_ready?'Email to your recipients':'Set up email in Settings first',onclick:async()=>{try{const x=await send('POST','/api/reports/'+r.id+'/email');alert('Sent to '+x.sent_to.join(', '))}catch(e){alert(e.message)}}},'Email');
  rows.append(el('tr',{},el('td',{},when(r.created_at)),el('td',{},r.title),el('td',{},el('b',{className:{A:'low',B:'low',C:'medium',D:'high',F:'high'}[r.grade]||''},r.grade||'—')),
   el('td',{},el('div',{className:'actions',style:'flex-wrap:nowrap'},el('button',{className:'small',onclick:()=>view(r)},'View'),el('button',{className:'small',onclick:()=>dl(r)},'Download'),mail,el('button',{className:'small',onclick:()=>del('/api/reports/'+r.id,'Delete “'+r.title+'”?',()=>{if(shown===r.id)$('viewer').hidden=true;loadReports()})},'Delete')))))}}
 catch(e){$('reports').replaceChildren(el('tr',{},el('td',{colSpan:4,className:'muted'},'Could not load: '+e.message)))}}
async function html(id,download){const r=await fetch('/api/reports/'+id+'/html'+(download?'?download=1':''),{headers:hdr()});if(!r.ok)throw new Error('Request failed ('+r.status+')');return r.text()}
function cleanReport(doc){doc.querySelectorAll('script,iframe,object,embed,link,meta,base,form,style').forEach(n=>n.remove());
 doc.querySelectorAll('*').forEach(n=>{for(const a of [...n.attributes]){if(/^on/i.test(a.name)||/^\s*javascript:/i.test(a.value))n.removeAttribute(a.name)}})}
function reportBox(...nodes){const host=$('reporthost');const root=host.shadowRoot||host.attachShadow({mode:'open'});root.replaceChildren(...nodes);host.scrollTop=0}
function reportNote(text,bad){return el('div',{style:'padding:40px;text-align:center;font:15px Segoe UI,Arial,sans-serif;color:'+(bad?'#c62828':'#5b6b7f')},text)}
/* Reports are drawn straight into the page (in an isolated shadow root) rather than an iframe:
   some browsers' privacy features showed sandboxed iframes as a blank white page. */
let shown=null;
async function view(r){shown=r.id;$('viewtitle').textContent=r.title+' · '+when(r.created_at);$('viewer').hidden=false;reportBox(reportNote('Loading report…'));
 $('viewer').scrollIntoView({behavior:'smooth'});
 try{const text=await html(r.id);const doc=new DOMParser().parseFromString(text,'text/html');cleanReport(doc);
  if(!doc.body||!doc.body.textContent.trim())throw new Error('The report came back empty. Try creating it again.');
  const wrap=document.createElement('div');wrap.setAttribute('style',(doc.body.getAttribute('style')||'')+';font-size:15px;line-height:1.4;text-align:left');
  wrap.append(...[...doc.body.childNodes].map(n=>document.importNode(n,true)));reportBox(wrap)}
 catch(e){reportBox(reportNote('Could not show this report: '+e.message,true))}}
async function dl(r){try{const blob=new Blob([await html(r.id,true)],{type:'text/html'});const a=el('a',{href:URL.createObjectURL(blob),download:'netai-'+r.kind+'-report-'+r.id+'.html'});document.body.append(a);a.click();a.remove()}catch(e){alert(e.message)}}
async function create(kind){$('createmsg').textContent='Creating '+info.kinds[kind].toLowerCase()+' and asking Aya'+(info.aya_uses_model?' (her local model can take a few minutes)':'')+'…';
 try{const r=await send('POST','/api/reports',{kind});$('createmsg').textContent='Done: grade '+r.grade+'. '+r.headline+' Reviewed by Aya ('+r.aya_engine+').'+(r.aya_note?' '+r.aya_note:'');
  await loadReports();const row=info.items.find(x=>x.id===r.id);if(row)view(row)}catch(e){$('createmsg').textContent='Failed: '+e.message}}
$('closeview').onclick=()=>{$('viewer').hidden=true;shown=null};
$('delallreports').onclick=()=>del('/api/reports','Delete ALL saved reports? This can’t be undone.',r=>{$('viewer').hidden=true;loadReports()});
pulse();loadReports().then(()=>{const v=+new URLSearchParams(location.search).get('view');const row=info&&info.items.find(x=>x.id===v);if(row)view(row)});setInterval(pulse,5000);
"""
SETTINGS_BODY = r"""
<div class="card"><div class="phase"><div><h2>Settings</h2>
<div class="muted">Email notifications, scheduled reports and Aya, your local AI analyst. Saved on this computer; passwords and keys are never shown again after saving.</div></div>
<div class="actions"><button id="save">Save settings</button></div></div><div id="savemsg" class="small" style="margin-top:8px"></div></div>
<h2 class="section">Email</h2>
<div class="card"><div class="row"><label><input type="checkbox" id="email_enabled"> Send email notifications</label><span id="emailstate" class="small"></span></div>
<div class="row small muted">Quick setup: <button class="small" data-preset="gmail">Gmail</button><button class="small" data-preset="m365">Microsoft 365</button><button class="small" data-preset="outlook">Outlook.com</button>
<span>(Gmail and Microsoft accounts with 2-step verification need an <b>app password</b>, not your normal password.)</span></div>
<div class="two"><div>
<div class="row"><label style="width:110px">Mail server</label><input type="text" id="smtp_host" placeholder="smtp.example.com" size="26"></div>
<div class="row"><label style="width:110px">Port</label><input type="text" id="smtp_port" size="6"><select id="smtp_tls"><option value="starttls">STARTTLS (587)</option><option value="ssl">SSL/TLS (465)</option><option value="none">None (not recommended)</option></select></div>
<div class="row"><label style="width:110px">Username</label><input type="text" id="smtp_user" placeholder="you@example.com" size="26" autocomplete="off"></div>
<div class="row"><label style="width:110px">Password</label><input type="password" id="smtp_password" size="26" autocomplete="new-password" style="background:#0a1422;color:var(--text);border:1px solid var(--line);border-radius:8px;padding:7px 10px;font:inherit"></div>
</div><div>
<div class="row"><label style="width:110px">From</label><input type="text" id="smtp_from" placeholder="(defaults to username)" size="26"></div>
<div class="row"><label style="width:110px">Send to</label><input type="text" id="email_to" placeholder="it@example.com, boss@example.com" size="34"></div>
<div class="row"><label><input type="checkbox" id="include_hosts"> Include IP addresses and device names in emails</label></div>
<div class="row"><button id="testemail">Send test email</button><span id="testmsg" class="small muted"></span></div>
</div></div></div>
<h2 class="section">What to email</h2>
<div class="card"><div class="row"><label><input type="checkbox" id="notify_incidents"> Incidents at</label><select id="min_severity"><option value="high">high severity</option><option value="medium">medium severity and above</option></select></div>
<div class="row"><label><input type="checkbox" id="notify_new_devices"> New devices on the network</label></div>
<div class="row"><label><input type="checkbox" id="notify_risky_services"> Newly found risky services (Telnet, RDP, open databases…)</label></div>
<div class="row"><label><input type="checkbox" id="notify_scans"> Aya's review when an nmap scan finishes</label></div>
<div class="row"><label>Scheduled report</label><select id="report_schedule"><option value="off">Off</option><option value="daily">Daily</option><option value="weekly">Weekly</option></select>
<select id="report_kind"></select><label>on</label><select id="report_weekday"></select><label>at</label><select id="report_hour"></select></div>
<p class="muted small">Desktop and Slack alerts are set in the .env file. Scheduled reports use this computer's local time. Aya reviews every report and every finished scan; tick the scan option to have her scan reviews emailed.</p></div>
<h2 class="section">Aya, your local AI analyst</h2>
<div class="card"><div class="row" style="align-items:flex-start"><div style="width:44px;height:44px;border-radius:50%;background:#7c4dff;color:#fff;font-weight:700;display:flex;align-items:center;justify-content:center;font-size:20px;flex:none">A</div>
<p class="muted small" style="margin:0">Aya reviews every report and every finished scan: what she found, what she thinks of it, and what to improve. She runs <b>on this computer</b>. With <b>Built-in</b> she uses NetAI's expert rules (no setup). Connect a local language model through <a style="color:var(--accent)" href="https://ollama.com" target="_blank" rel="noopener">Ollama</a> or LM Studio for richer, more natural reviews. Your network data goes only to that local server.</p></div>
<div class="row"><label style="width:110px">Engine</label><select id="aya_engine"><option value="builtin">Built-in (no setup)</option><option value="ollama">Ollama</option><option value="openai">LM Studio / llama.cpp / LocalAI (OpenAI-compatible)</option></select></div>
<div id="ayamodel">
<div class="row"><label style="width:110px">Server</label><input type="text" id="aya_url" size="30" placeholder="http://127.0.0.1:11434"></div>
<div class="row"><label style="width:110px">Model</label><input type="text" id="aya_model" size="30" list="ayamodels" placeholder="e.g. llama3.1:8b"><datalist id="ayamodels"></datalist><button id="ayarefresh" class="small">Check server</button></div>
<div class="row"><label style="width:110px">API key</label><input type="password" id="aya_api_key" size="30" autocomplete="new-password" placeholder="usually not needed" style="background:#0a1422;color:var(--text);border:1px solid var(--line);border-radius:8px;padding:7px 10px;font:inherit"></div>
<div id="ayastatus" class="small" style="margin:6px 0"></div>
<details><summary class="small">How to set up a local model (5 minutes)</summary><div class="small"><ol>
<li>Install Ollama from <a style="color:var(--accent)" href="https://ollama.com/download" target="_blank" rel="noopener">ollama.com/download</a> (Windows, macOS, Linux).</li>
<li>Open a terminal and download a model, for example <code>ollama pull llama3.1:8b</code> (about 5 GB; needs 8 GB+ RAM). A graphics card makes Aya much faster; on a CPU a review can take a few minutes.</li>
<li>Choose <b>Ollama</b> above, press <b>Check server</b>, pick the model, <b>Save</b>, then <b>Test Aya</b>.</li></ol>
LM Studio: load a model, start its local server (port 1234), choose the OpenAI-compatible engine with <code>http://127.0.0.1:1234</code>.</div></details>
</div>
<div class="row"><button id="testaya">Test Aya</button><span id="ayamsg" class="small muted"></span></div>
<pre class="log" id="ayaout" hidden></pre></div>
<h2 class="section">Data &amp; storage</h2>
<div class="card"><p class="muted small" style="margin-top:0">Everything NetAI stores stays on this computer. Remove what you no longer need. Your settings and the learned baseline are never removed here (use <i>Relearn baseline</i> on the Monitor page for that).</p>
<div class="table-wrap"><table><thead><tr><th>What</th><th>Stored</th><th></th></tr></thead><tbody id="datarows"><tr><td colspan="3" class="muted">Loading…</td></tr></tbody></table></div>
<div class="row" style="margin-top:12px"><button id="wipe" style="border-color:#7a3a3a;color:var(--bad)">Delete all data…</button><span id="datamsg" class="small muted"></span></div></div>
"""
SETTINGS_JS = r"""
const FIELDS=['email_enabled','smtp_host','smtp_port','smtp_tls','smtp_user','smtp_password','smtp_from','email_to','include_hosts','notify_incidents','min_severity','notify_new_devices','notify_risky_services','notify_scans','report_schedule','report_kind','report_weekday','report_hour','aya_engine','aya_url','aya_model','aya_api_key'];
const PRESETS={gmail:['smtp.gmail.com',587,'starttls'],m365:['smtp.office365.com',587,'starttls'],outlook:['smtp-mail.outlook.com',587,'starttls']};
const DAYS=['Monday','Tuesday','Wednesday','Thursday','Friday','Saturday','Sunday'];
DAYS.forEach((d,i)=>$('report_weekday').append(el('option',{value:i},d)));
for(let h=0;h<24;h++)$('report_hour').append(el('option',{value:h},String(h).padStart(2,'0')+':00'));
[['full','Full report'],['network','Network & devices'],['span','SPAN discovery'],['incidents','Incidents']].forEach(([v,l])=>$('report_kind').append(el('option',{value:v},l)));
function fill(s){for(const f of FIELDS){const e=$(f);if(!e)continue;const v=s[f];
 if(e.type==='checkbox')e.checked=!!v;else if(f==='email_to')e.value=(v||[]).join(', ');else if(e.type==='password'){e.value='';e.placeholder=v?'saved (leave empty to keep)':'not set'}else e.value=v??''}
 $('emailstate').textContent=s.email_ready?'✓ ready':'not set up yet';$('emailstate').className='small '+(s.email_ready?'ok':'muted');
 $('report_weekday').disabled=s.report_schedule!=='weekly'}
function collect(){const out={};for(const f of FIELDS){const e=$(f);if(!e)continue;if(e.type==='checkbox')out[f]=e.checked;else if(e.type==='password'){if(e.value)out[f]=e.value}else out[f]=e.value}return out}
async function load(){try{fill(await get('/api/settings/notifications'))}catch(e){$('savemsg').textContent='Could not load settings: '+e.message}}
async function save(){try{fill(await send('POST','/api/settings/notifications',collect()));$('savemsg').textContent='Saved.';$('savemsg').className='small ok';return true}
 catch(e){$('savemsg').textContent=e.message;$('savemsg').className='small bad';return false}}
$('save').onclick=save;$('report_schedule').onchange=e=>{$('report_weekday').disabled=e.target.value!=='weekly'};
document.querySelectorAll('[data-preset]').forEach(b=>b.onclick=()=>{const [h,p,t]=PRESETS[b.dataset.preset];$('smtp_host').value=h;$('smtp_port').value=p;$('smtp_tls').value=t;$('email_enabled').checked=true});
$('testemail').onclick=async()=>{if(!await save())return;$('testmsg').textContent='Sending…';try{const r=await send('POST','/api/settings/notifications/test-email');$('testmsg').textContent='Sent to '+r.sent_to.join(', ')+'. Check the inbox (and spam folder).';$('testmsg').className='small ok'}catch(e){$('testmsg').textContent=e.message;$('testmsg').className='small bad'}};
const AYA_URLS={ollama:'http://127.0.0.1:11434',openai:'http://127.0.0.1:1234'};
function ayaMode(){const e=$('aya_engine').value;$('ayamodel').hidden=e==='builtin';$('testaya').hidden=e==='builtin';if(e!=='builtin')$('aya_url').placeholder=AYA_URLS[e]}
$('aya_engine').onchange=()=>{ayaMode();$('ayastatus').textContent=''};
async function ayaCheck(doSave){if($('aya_engine').value==='builtin')return;$('ayastatus').textContent='Checking…';$('ayastatus').className='small muted';
 try{if(doSave&&!await save())return;const a=await get('/api/aya');const dl=$('ayamodels');dl.replaceChildren(...a.models.map(m=>el('option',{value:m})));
  if(a.reachable){$('ayastatus').textContent='✓ Server answering at '+a.url+' · '+(a.models.length?a.models.length+' model(s): '+a.models.join(', '):'no models installed yet (run: ollama pull llama3.1:8b)')+(a.model&&a.models.length&&!a.models.includes(a.model)?' · ⚠ "'+a.model+'" is not installed':'');$('ayastatus').className='small ok'}
  else{$('ayastatus').textContent='✗ '+a.error;$('ayastatus').className='small bad'}
  if(!a.local){$('ayastatus').textContent+=' · ⚠ This server is not on your local network: your data would leave it.';$('ayastatus').className='small bad'}}catch(e){$('ayastatus').textContent=e.message;$('ayastatus').className='small bad'}}
$('ayarefresh').onclick=()=>ayaCheck(true);
$('testaya').onclick=async()=>{if(!await save())return;$('ayamsg').textContent='Aya is reading your network (local models can take a few minutes)…';$('ayamsg').className='small muted';$('ayaout').hidden=true;
 try{const r=await send('POST','/api/aya/test');$('ayamsg').textContent='Aya is working.';$('ayamsg').className='small ok';$('ayaout').textContent=r.review;$('ayaout').hidden=false}catch(e){$('ayamsg').textContent=e.message;$('ayamsg').className='small bad'}};
async function loadData(){try{const d=await get('/api/data');const rows=$('datarows');rows.replaceChildren();
 const items=[['Detection events',d.events.toLocaleString(),'/api/events','Clear all detection events?'],
  ['Incidents',d.incidents+(d.open_incidents?' ('+d.open_incidents+' ongoing, kept)':''),'/api/incidents','Delete all ended incidents and their evidence files?'],
  ['Evidence files (.pcap)',d.evidence_files+' · '+human(d.evidence_bytes),'/api/incidents','Evidence files belong to incidents: delete all ended incidents and their evidence?'],
  ['Reports',d.reports,'/api/reports','Delete all saved reports?'],
  ['Scan history',d.scans,'/api/scans','Delete the whole scan history and Aya’s scan reviews?'],
  ['Device inventory',d.devices+' devices','/api/devices','Clear the device inventory, including device names you gave?'],
  ['Terminal log',d.terminal+' commands','/api/terminal/history','Clear the terminal command log?']];
 for(const [label,value,url,q] of items)rows.append(el('tr',{},el('td',{},label),el('td',{},String(value)),el('td',{},el('button',{className:'small',onclick:()=>del(url,q,loadData)},'Clear'))));
 rows.append(el('tr',{},el('td',{className:'muted'},'Database file'),el('td',{className:'muted'},human(d.database_bytes)),el('td',{})))}
 catch(e){$('datarows').replaceChildren(el('tr',{},el('td',{colSpan:3,className:'muted'},'Could not load: '+e.message)))}}
$('wipe').onclick=async()=>{const t=prompt('This deletes all detection events, ended incidents and evidence, reports, scan history, the device inventory and the terminal log. Settings and the learned baseline are kept.\n\nType DELETE to confirm:');
 if(t===null)return;try{const r=await send('POST','/api/data/wipe',{confirm:t.trim()});$('datamsg').textContent='Deleted: '+Object.entries(r).map(([k,v])=>v+' '+k.replace('_',' ')).join(', ')+'.';$('datamsg').className='small ok';loadData()}
 catch(e){$('datamsg').textContent=e.message;$('datamsg').className='small bad'}};
pulse();load().then(()=>{ayaMode();ayaCheck(false)});loadData();setInterval(pulse,5000);
"""

TERMINAL_BODY = r"""
<div class="card"><div class="phase"><div><h2>Terminal</h2>
<div class="muted">Run nmap, ping or any other command on this computer and watch the output live. nmap scans run here are added to the device inventory and scan history, and Aya reviews them.</div></div>
<label class="small">Shell <select id="shell"></select></label></div>
<div id="termwarn" class="banner" style="margin:12px 0 0">Commands run on this computer with NetAI's administrator rights. Every command is logged below.</div></div>
<div class="two" style="margin-top:14px;grid-template-columns:minmax(260px,1fr) 3fr">
<div class="card small"><div style="font-weight:600;margin-bottom:6px">Target</div>
<input type="text" id="target" list="targets" placeholder="IP, subnet or host" style="width:100%"><datalist id="targets"></datalist>
<div style="font-weight:600;margin:14px 0 6px">nmap</div><div class="actions" id="nmapbtns"></div>
<div style="font-weight:600;margin:14px 0 6px">Network tools</div><div class="actions" id="toolbtns"></div>
<p class="muted" style="margin-bottom:0">Buttons fill in the command so you can check or edit it; press Enter to run. Commands can't ask for keyboard input.</p></div>
<div class="card" style="padding:0;overflow:hidden;display:flex;flex-direction:column">
<div class="row" style="padding:8px 12px;margin:0;border-bottom:1px solid var(--line)"><span id="runstate" class="small muted">Ready</span><span style="flex:1"></span>
<button id="stopbtn" class="small" hidden>Stop</button><button id="copybtn" class="small">Copy output</button><button id="clearbtn" class="small">Clear</button></div>
<pre id="screen" style="margin:0;background:#05090f;color:#d5e4f5;font:13px/1.45 Consolas,Menlo,monospace;padding:12px 14px;height:460px;overflow:auto;white-space:pre-wrap;word-break:break-word"></pre>
<div style="display:flex;align-items:center;gap:8px;padding:8px 12px;border-top:1px solid var(--line);background:#070d16">
<span style="font:13px Consolas,Menlo,monospace;color:#7c4dff">netai&gt;</span>
<input type="text" id="cmd" autocomplete="off" spellcheck="false" placeholder="nmap -sn 192.168.1.0/24" style="flex:1;font:13px Consolas,Menlo,monospace;background:transparent;border:0;outline:0;color:var(--text)">
<button id="runbtn" class="small">Run</button></div></div></div>
<div class="row" style="justify-content:space-between;margin:26px 0 10px"><h2 class="section" style="margin:0">Command log</h2><span class="actions"><button class="small" id="clearlog">Clear log</button></span></div>
<div class="card table-wrap"><table><thead><tr><th>When</th><th>Command</th><th>Shell</th><th>Exit</th><th>Time</th><th></th></tr></thead><tbody id="log"><tr><td colspan="6" class="muted">Loading…</td></tr></tbody></table></div>
"""
TERMINAL_JS = r"""
let info=null,cur=null,offset=0,hist=[],hpos=-1,timer=null;
const T=()=>$('target').value.trim()||'192.168.1.0/24';
function presets(win){return{
 nmap:[['Find devices',t=>'nmap -sn '+t],['Quick ports',t=>'nmap -F '+t],['Services & versions',t=>'nmap -sV --top-ports 1000 '+t],['OS detection',t=>'nmap -O '+t],
  ['All TCP ports',t=>'nmap -p- -T4 '+t],['Top UDP ports',t=>'nmap -sU --top-ports 50 '+t],['Vulnerability scripts (intrusive)',t=>'nmap -sV --script vuln '+t]],
 tools:[['Ping',t=>(win?'ping -n 4 ':'ping -c 4 ')+t.split('/')[0]],['Traceroute',t=>(win?'tracert -d ':'traceroute -n ')+t.split('/')[0]],['DNS lookup',t=>'nslookup '+t.split('/')[0]],
  ['ARP table',()=>win?'arp -a':'ip neigh'],['IP config',()=>win?'ipconfig /all':'ip addr'],['Connections',()=>win?'netstat -ano':'ss -tunap']]}}
function write(text,cls){const scr=$('screen');const atEnd=scr.scrollTop+scr.clientHeight>=scr.scrollHeight-30;const span=el('span',{className:cls||''},text);scr.append(span);
 while(scr.childNodes.length>4000)scr.firstChild.remove();if(atEnd)scr.scrollTop=scr.scrollHeight}
function busy(on){$('stopbtn').hidden=!on;$('runbtn').disabled=on;$('cmd').disabled=on||!info.enabled;if(!on)setTimeout(()=>$('cmd').focus(),0)}
async function load(){info=await get('/api/terminal');
 if(!$('shell').options.length)for(const [k,v] of Object.entries(info.shells))$('shell').append(el('option',{value:k},v));
 if(!info.enabled){$('termwarn').textContent=info.reason;$('cmd').disabled=true;$('runbtn').disabled=true}
 if(!$('nmapbtns').children.length){const P=presets(info.windows);
  for(const [l,f] of P.nmap)$('nmapbtns').append(el('button',{className:'small',onclick:()=>fill(f(T()))},l));
  for(const [l,f] of P.tools)$('toolbtns').append(el('button',{className:'small',onclick:()=>fill(f(T()))},l));
  if(!info.nmap)$('nmapbtns').append(el('div',{className:'muted',style:'width:100%'},'nmap isn’t installed: get it free from nmap.org.'))}
 renderLog();if(info.running.length&&!cur)attach(info.running[0])}
function renderLog(){const rows=$('log');rows.replaceChildren();hist=info.history.map(h=>h.command);
 if(!info.history.length)rows.append(el('tr',{},el('td',{colSpan:6,className:'muted'},'No commands yet.')));
 for(const h of info.history)rows.append(el('tr',{},el('td',{className:'small'},when(h.started_at)),el('td',{},el('code',{style:'font-size:12.5px'},h.command)),el('td',{className:'small'},h.shell),
  el('td',{className:'small '+(h.exit_code===0?'ok':h.exit_code==null?'muted':'bad')},h.exit_code==null?'running':String(h.exit_code)),el('td',{className:'small'},h.seconds!=null?h.seconds+'s':''),
  el('td',{},el('button',{className:'small',style:'padding:4px 9px',onclick:()=>fill(h.command)},'Use again'))))}
function fill(c){$('cmd').value=c;$('cmd').focus()}
function attach(r){cur=r.id;offset=0;busy(true);$('runstate').textContent='Running…';poll()}
async function run(){const c=$('cmd').value.trim();if(!c||!info.enabled)return;
 if(c==='clear'||c==='cls'){$('screen').replaceChildren();$('cmd').value='';return}
 write('netai> '+c+'\n','cmdline');$('cmd').value='';hpos=-1;
 try{const r=await send('POST','/api/terminal/run',{command:c,shell:$('shell').value});attach(r)}catch(e){write(e.message+'\n','err')}}
async function poll(){clearTimeout(timer);if(!cur)return;try{const r=await get('/api/terminal/runs/'+cur+'?offset='+offset);if(r.output)write(r.output);offset=r.offset;
 $('runstate').textContent=(r.running?'Running · ':'Finished · exit code '+r.exit_code+' · ')+r.elapsed+'s';
 if(r.running){timer=setTimeout(poll,400)}else{cur=null;busy(false);write('\n','');load()}}catch(e){write('\n'+e.message+'\n','err');cur=null;busy(false)}}
$('cmd').addEventListener('keydown',e=>{if(e.key==='Enter'){e.preventDefault();run()}
 else if(e.key==='ArrowUp'){if(hpos<hist.length-1){hpos++;$('cmd').value=hist[hpos]}e.preventDefault()}
 else if(e.key==='ArrowDown'){if(hpos>0){hpos--;$('cmd').value=hist[hpos]}else{hpos=-1;$('cmd').value=''}e.preventDefault()}});
$('runbtn').onclick=run;
$('clearlog').onclick=()=>del('/api/terminal/history','Clear the terminal command log?',load);$('stopbtn').onclick=()=>cur&&send('POST','/api/terminal/runs/'+cur+'/stop').catch(e=>alert(e.message));
$('clearbtn').onclick=()=>$('screen').replaceChildren();
$('copybtn').onclick=e=>copy($('screen').textContent,e.target);
document.addEventListener('keydown',e=>{if(e.ctrlKey&&e.key==='c'&&cur&&!window.getSelection().toString()){e.preventDefault();$('stopbtn').click()}});
async function targets(){try{const [d,n]=await Promise.all([get('/api/devices'),get('/api/network')]);const dl=$('targets');
 for(const s of n.subnets)dl.append(el('option',{value:s.cidr},s.source));for(const x of d.items)dl.append(el('option',{value:x.ip},x.name||''));
 if(!$('target').value&&n.subnets.length)$('target').value=n.subnets[0].cidr}catch(e){}}
pulse();load().catch(e=>{$('termwarn').textContent='Could not load the terminal: '+e.message});targets();setInterval(pulse,5000);
"""

DASHBOARD = page("/", MONITOR_BODY, MONITOR_JS)
NETWORK_PAGE = page("/network", NETWORK_BODY, NETWORK_JS)
SPAN_PAGE = page("/span", SPAN_BODY, SPAN_JS)
REPORTS_PAGE = page("/reports", REPORTS_BODY, REPORTS_JS)
SETTINGS_PAGE = page("/settings", SETTINGS_BODY, SETTINGS_JS)
TERMINAL_PAGE = page("/terminal", TERMINAL_BODY, TERMINAL_JS)
