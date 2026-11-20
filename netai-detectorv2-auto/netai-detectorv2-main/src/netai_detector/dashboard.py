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
<div class="card"><div class="muted">Model last trained</div><div class="value" id="trained" style="font-size:18px">—</div></div>
<div class="card"><div class="muted">Watching</div><div class="value" id="watching" style="font-size:18px;word-break:break-all">—</div></div>
</div>
<h2 class="section">Recent detection events</h2><div class="card table-wrap"><table>
<thead><tr><th>Time</th><th>Source</th><th>Severity</th><th>Result</th><th>Score</th><th>Why flagged (largest deviations from normal)</th></tr></thead>
<tbody id="rows"><tr><td colspan="6" class="muted">Loading events…</td></tr></tbody></table></div>
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
const TITLES={starting:'Starting…',learning:'Learning your normal traffic',training:'Training the model',monitoring:'Monitoring',paused:'Paused',idle:'Waiting',error:'Needs attention',stopped:'Stopped'};
let alertsSeen=null,paused=false;
function banner(text,cls){const d=document.createElement('div');d.className='banner '+(cls||'');d.textContent=text;return d}
async function refresh(){try{
 const [s,st,e]=await Promise.all([fetch('/api/status').then(r=>r.json()),fetch('/api/stats').then(r=>r.json()),fetch('/api/events?limit=50').then(r=>r.json())]);
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
 $('events').textContent=st.events;$('anomalies').textContent=st.anomalies;$('high').textContent=st.high_severity;
 $('trained').textContent=s.model&&s.model.trained_at?new Date(s.model.trained_at).toLocaleString():'—';
 $('watching').textContent=s.source==='demo'?'Simulated traffic':(s.interface||'—');
 if(alertsSeen===null)alertsSeen=st.anomalies;
 document.title=(st.anomalies>alertsSeen?'('+(st.anomalies-alertsSeen)+' new) ':'')+'NetAI Detector';
 const rows=$('rows');rows.replaceChildren();
 if(!e.items.length){const tr=rows.insertRow();const td=tr.insertCell();td.colSpan=6;td.className='muted';
  td.textContent=s.phase==='learning'?'Learning in progress. Events will appear once the baseline is ready.':'No events yet.';return}
 for(const it of e.items){const tr=document.createElement('tr');
  const why=(it.details&&it.details.top_features||[]).map(f=>f.feature+' ('+(f.z>0?'+':'')+f.z+'σ)').join(', ')||(it.details&&it.details.simulated_scenario&&it.details.simulated_scenario!=='normal'?'simulated: '+it.details.simulated_scenario:'');
  [new Date(it.created_at).toLocaleString(),it.source,it.severity,it.is_anomaly?'Anomaly':'Normal',it.score==null?'—':Number(it.score).toFixed(4),why].forEach((v,i)=>{const td=document.createElement('td');td.textContent=v;if(i===2)td.className=it.severity;tr.appendChild(td)});
  rows.appendChild(tr)}
 }catch(err){$('health').textContent='Service unavailable';$('dot').className='dot bad'}}
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
