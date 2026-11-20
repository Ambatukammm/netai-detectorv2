"""The single-page dashboard (plain HTML/CSS/JS, no external assets)."""
from . import __version__

DASHBOARD = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>NetAI Detector</title><style>
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
</style></head><body>
<header><div><h1>◈ NetAI Detector</h1><small>Automatic network anomaly detection &amp; monitoring</small></div>
<div class="status"><span class="dot" id="dot"></span><span id="health">Connecting…</span></div></header>
<main>
<div id="banners"></div>
<div class="card"><div class="phase"><div><h2 id="phasetitle">Starting…</h2><div class="muted" id="phasemsg"></div></div>
<div class="actions"><button id="pausebtn">Pause</button><button id="relearnbtn" title="Forget the current baseline and learn normal traffic again">Relearn baseline</button></div></div>
<div class="bar" id="barwrap" hidden><div id="bar"></div></div></div>
<h2 class="section">Overview</h2>
<div class="grid">
<div class="card"><div class="muted">Events recorded</div><div class="value" id="events">—</div></div>
<div class="card"><div class="muted">Anomalies detected</div><div class="value" id="anomalies">—</div></div>
<div class="card"><div class="muted">High severity</div><div class="value" id="high">—</div></div>
<div class="card"><div class="muted">Incidents (open now)</div><div class="value" id="incidents">—</div></div>
<div class="card"><div class="muted">Model last trained</div><div class="value" id="trained" style="font-size:18px">—</div></div>
<div class="card"><div class="muted">Watching</div><div class="value" id="watching" style="font-size:18px;word-break:break-all">—</div></div>
</div>
<h2 class="section">Incidents</h2>
<p class="muted" style="margin-top:-6px">Consecutive flagged windows are grouped into one incident. Click one to see who was involved, what it looks like, and suggested next steps.</p>
<div class="card table-wrap"><table>
<thead><tr><th>#</th><th>Started</th><th>Status</th><th>Severity</th><th>Looks like</th><th>Main traffic</th><th>Windows</th><th>Evidence</th></tr></thead>
<tbody id="incrows"><tr><td colspan="8" class="muted">Loading…</td></tr></tbody></table></div>
<div id="detail" class="card" hidden></div>
<div class="actions" style="margin-top:12px"><button id="notifybtn">Enable browser notifications</button><button id="testalert">Send test alert</button><span class="muted" id="alertinfo" style="align-self:center;font-size:13px"></span></div>
<h2 class="section">Recent detection events</h2><div class="card table-wrap"><table>
<thead><tr><th>Time</th><th>Source</th><th>Severity</th><th>Result</th><th>Score</th><th>Why flagged</th><th>Who</th></tr></thead>
<tbody id="rows"><tr><td colspan="7" class="muted">Loading events…</td></tr></tbody></table></div>
<h2 class="section">Analyse a capture file</h2>
<div id="drop"><div>Drop a <b>.pcap</b> / <b>.pcapng</b> file here, or <a href="#" id="pick">choose a file</a></div>
<label><input type="checkbox" id="asbase"> Use it as the new baseline of normal traffic</label>
<div id="dropmsg"></div><input type="file" id="file" accept=".pcap,.pcapng,.cap" hidden></div>
<p class="muted">This dashboard reports model outputs, not confirmed incidents. Validate alerts before taking action.</p>
</main><footer>NetAI Detector · Made by Ruel · Version __VERSION__</footer>
<script>
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
function mainFlow(c){const f=c&&c.top_flows&&c.top_flows[0];return f?f.src+' → '+f.dst+' ('+f.proto.toUpperCase()+')':''}
let selected=null,selectedSig='',maxIncident=null;
async function copy(text,btn){try{await navigator.clipboard.writeText(text);btn.textContent='Copied'}catch(e){btn.textContent='Select & copy manually'}setTimeout(()=>btn.textContent='Copy',1500)}
async function download(id){try{const r=await fetch('/api/incidents/'+id+'/evidence',{headers:hdr()});if(!r.ok)throw new Error((await r.json().catch(()=>({}))).detail||r.status);
 const blob=await r.blob();const name=(r.headers.get('Content-Disposition')||'').match(/filename="?([^";]+)/);const a=el('a',{href:URL.createObjectURL(blob),download:name?name[1]:'incident-'+id+'.pcap'});document.body.append(a);a.click();a.remove()}catch(e){alert('Could not download evidence: '+e.message)}}
function table(head,rows){return el('div',{className:'table-wrap'},el('table',{},el('thead',{},el('tr',{},head.map(h=>el('th',{},h)))),el('tbody',{},rows.map(r=>el('tr',{},r.map(v=>el('td',{},v)))))))}
async function showIncident(id,force){
 const d=await get('/api/incidents/'+id);const sig=d.status+d.windows+d.peak_severity+d.evidence_packets;
 if(!force&&selected===id&&sig===selectedSig)return;selected=id;selectedSig=sig;
 const p=d.plan,box=$('detail');box.hidden=false;box.replaceChildren();
 box.append(el('div',{className:'phase'},el('div',{},el('h3',{},'Incident #'+d.id+' — '+p.title),
   el('div',{className:'muted'},(d.status==='open'?'Ongoing since ':'From ')+when(d.started_at)+(d.status==='open'?'':' to '+when(d.ended_at)+' ('+(d.close_reason||'closed')+')')+' · peak severity ',el('span',{className:d.peak_severity},d.peak_severity),d.severity_reason?' ('+d.severity_reason+')':'',' · '+d.windows+' flagged window(s) · source '+d.source)),
  el('div',{className:'actions'},d.evidence_available?el('button',{onclick:()=>download(d.id)},'Download evidence (.pcap)'):null,el('button',{onclick:()=>{box.hidden=true;selected=null;renderIncidents(lastIncidents)}},'Close'))));
 if(String(d.source).startsWith('demo'))box.append(el('div',{className:'note'},'Simulated incident (demo mode). The addresses are made up.'));
 box.append(el('div',{className:'note'},el('b',{},'What is happening: '),p.summary,' ',el('span',{className:'muted'},'(confidence: '+p.confidence+')')));
 if(p.trusted_note)box.append(el('div',{className:'note warn'},p.trusted_note));
 if(p.also_seen&&p.also_seen.length)box.append(el('div',{className:'muted'},'Also matched: '+p.also_seen.join(', ')));
 const c=d.culprits||{};const left=el('div'),right=el('div');
 left.append(el('h4',{},'Who was involved'));
 if(c.top_flows&&c.top_flows.length)left.append(table(['From','To','Proto','Packets','Data','Ports'],c.top_flows.slice(0,6).map(f=>[f.src,f.dst,f.proto.toUpperCase(),f.packets,fmtBytes(f.bytes),f.distinct_dst_ports>5?f.distinct_dst_ports+' different':(f.top_dst_ports||[]).join(', ')])));
 else left.append(el('div',{className:'muted'},'No packet details were available for this incident.'));
 if(c.top_sources&&c.top_sources.length)left.append(el('div',{className:'muted',style:'margin-top:8px'},'Busiest senders: '+c.top_sources.slice(0,4).map(s=>s.ip+(s.internal?' (your network)':' (outside)')).join(', ')));
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
 renderIncidents(inc.items);notifyNew(inc.items);
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
 $('incidents').textContent=st.incidents+' ('+st.open_incidents+')';$('events').textContent=st.events;$('anomalies').textContent=st.anomalies;$('high').textContent=st.high_severity;
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
</script></body></html>""".replace("__VERSION__", __version__)
