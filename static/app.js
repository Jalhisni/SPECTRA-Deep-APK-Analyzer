'use strict';
let scan=null,view='overview',severity='all';
const $=id=>document.getElementById(id);
const esc=x=>String(x??'').replace(/[&<>"']/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]));
const sz=b=>b>=1048576?(b/1048576).toFixed(2)+' MB':b>=1024?(b/1024).toFixed(1)+' KB':b+' B';
const sev=s=>`<span class="sev ${esc(s)}">${esc(s)}</span>`;
const el=(tag,text,cl)=>{const e=document.createElement(tag);e.textContent=text;if(cl)e.className=cl;return e;};
function chooseView(v){view=v;document.querySelectorAll('.nav').forEach(b=>b.classList.toggle('active',b.dataset.view===v));document.querySelectorAll('.section').forEach(s=>s.classList.toggle('hidden',s.id!=='panel-'+v));const titles={stages:'Recovered payload stages',commands:'Spyware command evidence',code:'DEX code references',settings:'Embedded configuration',overview:'Investigation overview',findings:'Threat findings',permissions:'Manifest permissions',network:'Network indicators',components:'Android components',files:'APK inventory'};$('sectionTitle').textContent=titles[v];}
document.querySelectorAll('.nav').forEach(b=>b.addEventListener('click',()=>chooseView(b.dataset.view)));
function row(k,v){return `<div class="coverage-item"><span>${esc(k)}</span><b>${esc(v)}</b></div>`}
function show(){
 $('empty').classList.add('hidden');$('results').classList.remove('hidden');
 $('fileName').textContent=scan.filename;
 $('packageName').textContent=scan.metadata.package||'Package name unavailable';
 $('fileSize').textContent=sz(scan.size_bytes);
 $('scanTime').textContent=new Date(scan.scan_utc).toLocaleString('en-US',{hour12:false});
 $('priority').textContent=scan.assessment.priority+' review';
 $('priority').className='kpi-value priority-'+scan.assessment.priority.toLowerCase();
 $('prioritySub').textContent='Score '+scan.assessment.review_score+'/100 · not malware probability';
 $('findingsCount').textContent=scan.findings.length;
 $('permissionCount').textContent=scan.permissions.length;
 $('stageCount').textContent=scan.stage_count||1;
 $('navCount').textContent=scan.findings.length;
 $('sha').textContent=scan.sha256;
 renderDeep();
 $('topFindings').innerHTML=scan.findings.length?scan.findings.slice(0,7).map(f=>`<div class="lead"><div><strong>${esc(f.title)}</strong><small>Stage ${esc(f.stage||1)} · ${esc(f.confidence)} evidence confidence · ${esc(f.status)}</small></div>${sev(f.severity)}</div>`).join(''):'<div class="none">No enabled signatures matched. This does NOT certify the APK as safe.</div>';
 const c=scan.coverage;
 $('coverage').innerHTML=row('Manifest',c.manifest)+row('DEX files parsed',c.dex_files)+row('DEX strings scanned',c.dex_strings.toLocaleString('en-US'))+row('DEX method references',c.dex_method_refs.toLocaleString('en-US'))+row('Native libraries',c.native_libraries)+row('Runtime execution','Not performed')+row('Observed outbound traffic','None — not monitored')+(scan.warnings.length?row('Analysis warnings',scan.warnings.length):'');
 renderFindings();
 $('permissionList').innerHTML=scan.permissions.length?`<table class="table"><thead><tr><th style="width:75%">Permission</th><th>Review note</th></tr></thead><tbody>${scan.permissions.map(p=>`<tr><td><code>${esc(p)}</code></td><td>${/CAMERA|RECORD_AUDIO|BIND_ACCESSIBILITY_SERVICE|READ_SMS|BIND_INPUT_METHOD|MANAGE_EXTERNAL_STORAGE/.test(p)?sev('high'):'<span class="muted">Declared</span>'}</td></tr>`).join('')}</tbody></table>`:'<div class="none">No manifest permissions parsed or declared.</div>';
 $('iocList').innerHTML=scan.indicators.length?`<table class="table"><thead><tr><th style="width:38%">Host / address candidate</th><th style="width:20%">Type</th><th>Evidence origin</th></tr></thead><tbody>${scan.indicators.map(i=>`<tr><td><code>${esc(i.value)}</code></td><td>${esc(i.kind)}</td><td><code>${esc(i.source.join(', '))}</code></td></tr>`).join('')}</tbody></table>`:'<div class="none">No network candidates found in scanned data. This does not rule out encrypted/constructed endpoints.</div>';
 $('componentList').innerHTML=scan.components.length?`<table class="table"><thead><tr><th>Kind / name</th><th>Permission</th><th>Exported</th><th>Intent actions</th></tr></thead><tbody>${scan.components.map(c=>`<tr><td><small class="muted">${esc(c.kind)}</small><br><code>${esc(c.name)}</code></td><td><code>${esc(c.permission||'—')}</code></td><td>${esc(c.exported)}</td><td>${esc(c.actions.join(' · ')||'—')}</td></tr>`).join('')}</tbody></table>`:'<div class="none">No application components decoded.</div>';
 $('fileList').innerHTML=scan.files.length?`<table class="table"><thead><tr><th>ZIP entry</th><th style="width:125px">Uncompressed</th></tr></thead><tbody>${scan.files.map(f=>`<tr><td><code>${esc(f.path)}</code></td><td>${sz(f.size_bytes)}</td></tr>`).join('')}</tbody></table>`:'<div class="none">No entries.</div>';
 chooseView(view);
}
function renderFindings(){const fs=scan.findings.filter(f=>severity==='all'||f.severity===severity);
 $('findingList').innerHTML=fs.length?fs.map(f=>`<article class="finding"><div class="finding-head">${sev(f.severity)}<h4>${esc(f.title)}</h4><span class="mini-badge">Stage ${esc(f.stage||1)}</span><span class="mini-badge">${esc(f.confidence)} confidence</span></div><p>${esc(f.assessment)}</p><div class="chips">${f.evidence_types.map(t=>`<span class="chip">${esc(t)}</span>`).join('')}</div><small>${esc(f.status)}</small><details><summary>Inspect evidence (${f.evidence.length} shown)</summary>${f.evidence.map(e=>`<code>${esc(e.source)}<br>${esc(e.match)}</code>`).join('')}</details></article>`).join(''):'<div class="none">No findings in this category.</div>';
}
document.querySelectorAll('.filter').forEach(b=>b.addEventListener('click',()=>{severity=b.dataset.severity;document.querySelectorAll('.filter').forEach(e=>e.classList.toggle('active',e===b));if(scan)renderFindings()}));
async function load(f){
 if(!f)return;
 $('error').classList.add('hidden');
 if(!f.name.toLowerCase().endsWith('.apk')){error('Select an .apk file.');return}
 if(f.size>120*1024*1024){error('APK exceeds 120 MB limit.');return}
 $('progress').classList.remove('hidden');$('progressTitle').textContent='Analyzing '+f.name+' ...';
 const fd=new FormData();fd.append('file',f,f.name);
 try{
  const res=await fetch('/api/scan',{method:'POST',body:fd});let body=await res.json();
  if(!res.ok)throw Error(body.error||'Analysis failed');
  scan=body;view='overview';severity='all';document.querySelectorAll('.filter').forEach(b=>b.classList.toggle('active',b.dataset.severity==='all'));show();
 }catch(e){error(e.message||String(e))}finally{$('progress').classList.add('hidden');$('file').value=''}
}
function error(message){$('error').textContent='Analysis error: '+message;$('error').classList.remove('hidden')}
$('dropzone').addEventListener('click',()=>$('file').click());
$('dropzone').addEventListener('keydown',e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();$('file').click()}});
$('file').addEventListener('change',e=>load(e.target.files[0]));
for(const type of ['dragenter','dragover'])$('dropzone').addEventListener(type,e=>{e.preventDefault();$('dropzone').classList.add('drag')});
for(const type of ['dragleave','drop'])$('dropzone').addEventListener(type,e=>{e.preventDefault();$('dropzone').classList.remove('drag')});
$('dropzone').addEventListener('drop',e=>{if(e.dataTransfer.files.length)load(e.dataTransfer.files[0])});
$('copySha').addEventListener('click',()=>{if(scan)navigator.clipboard.writeText(scan.sha256)});
function download(name,content,mime){const blob=new Blob([content],{type:mime});const url=URL.createObjectURL(blob);const a=document.createElement('a');a.href=url;a.download=name;document.body.appendChild(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),1000)}
$('downloadJson').addEventListener('click',()=>{if(scan)download('SPECTRA_'+scan.sha256.slice(0,12)+'.json',JSON.stringify(scan,null,2),'application/json')});
function renderDeep(){
 const stages=scan.stages||[];
 $('stageList').innerHTML=stages.length?stages.map(s=>`<article class="finding"><div class="finding-head"><span class="mini-badge">STAGE ${s.stage}</span><h4>${esc(s.metadata.package||'Unknown package')}</h4>${sev(s.risk_priority==='High'?'high':s.risk_priority==='Medium'?'medium':'info')}</div><p>Version ${esc(s.metadata.version_name||'unknown')} · ${sz(s.size_bytes)} · ${s.file_count} files · ${s.dex_files} DEX</p><div class="hash-label">SHA-256</div><code class="evidence-code">${esc(s.sha256)}</code><details><summary>Full permissions (${s.permissions.length})</summary>${s.permissions.map(p=>`<code class="evidence-code">${esc(p)}</code>`).join('')}</details></article>`).join(''):'<div class="none">No stage recovered.</div>';
 $('loaderNotes').innerHTML=(scan.loader_notes||[]).map(n=>`<div class="lead"><small>${esc(n)}</small></div>`).join('')||'<div class="none">No additional packed stage was identified with supported decoders. This does not rule out one.</div>';
 const commands=scan.command_indicators||[];
 const groups=Object.groupBy?Object.groupBy(commands,c=>c.category):commands.reduce((o,c)=>((o[c.category]??=[]).push(c),o),{});
 $('commandList').innerHTML=commands.length?Object.entries(groups).map(([cat,cs])=>`<div class="cmd-section"><div class="cmd-title">${esc(cat)} <span class="mini-badge">${cs.length}</span></div><div class="code-grid">${cs.map(c=>`<div class="code-pill"><code>${esc(c.value)}</code><small>Stage ${c.stage} · ${esc(c.source.join(', '))}</small></div>`).join('')}</div></div>`).join(''):'<div class="none">No known spyware command labels found. This is not a clean verdict.</div>';
 const refs=scan.code_references||[];
 $('codeList').innerHTML=refs.length?`<div class="tablewrap"><table class="table"><thead><tr><th>Stage / DEX</th><th>Method reference</th></tr></thead><tbody>${refs.map(r=>`<tr><td>${r.stage} · ${esc(r.file)}<br><span class="muted">ref ${r.ref_index}</span></td><td><code>${esc(r.method)}</code></td></tr>`).join('')}</tbody></table></div>`:'<div class="none">No selected method references found.</div>';
 const texts=scan.text_evidence||[];
 $('textEvidence').innerHTML=texts.length?texts.map(v=>`<div class="snippet"><small>Stage ${v.stage} / ${esc(v.file)} / line ${v.line}</small><pre>${esc(v.snippet)}</pre></div>`).join(''):'<div class="none">No notable text/HTML excerpts detected.</div>';
 const settings=scan.settings_evidence||[];
 $('settingsList').innerHTML=settings.length?`<table class="table"><thead><tr><th>Stage / Source</th><th>Key</th><th>Value</th></tr></thead><tbody>${settings.map(x=>`<tr><td>${x.stage} · <code>${esc(x.source)}</code></td><td><code>${esc(x.key)}</code></td><td><code>${esc(String(x.value))}</code></td></tr>`).join('')}</tbody></table>`:'<div class="none">No supported configuration keys found.</div>';
 const eps=scan.configured_endpoints||[];
 $('endpointList').innerHTML=eps.length?eps.map(x=>`<div class="lead"><div><strong>${esc(x.setting)}: <code>${esc(x.value)}</code></strong><small>Stage ${x.stage} · ${esc(x.source)} · ${esc(x.interpretation)}</small></div></div>`).join(''):'<div class="none">No configured endpoint found in supported JSON properties. Encoded endpoints may remain hidden.</div>';
}
const htmlTag=(v)=>esc(v).replace(/\n/g,'<br>');
function reportHtml(s){
 const color=(sev)=>sev==='high'?'#a13245':sev==='medium'?'#9a641c':'#206b80';
 const body=s.findings.map((f,n)=>`<section class="finding"><h3>${n+1}. ${esc(f.title)} <span style="color:${color(f.severity)}">${esc(f.severity.toUpperCase())}</span></h3><p><b>Confidence:</b> ${esc(f.confidence)}<br><b>Interpretation:</b> ${esc(f.assessment)}<br><b>Status:</b> ${esc(f.status)}</p><p><b>Evidence:</b></p><ul>${f.evidence.map(e=>`<li><code>${esc(e.source)}</code> — <code>${esc(e.match)}</code></li>`).join('')}</ul></section>`).join('');
 return `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>SPECTRA Investigation Report</title><style>body{font:12px/1.55 Arial,sans-serif;color:#182635;margin:35px auto;max-width:980px;padding:0 30px}h1{font-size:28px}h2{font-size:17px;margin-top:32px;border-bottom:2px solid #bdd0df;padding-bottom:8px}h3{font-size:14px}header{border-bottom:4px solid #157dd0;padding-bottom:13px}header small{color:#44738e;font-weight:700;letter-spacing:2px}table{border-collapse:collapse;width:100%}td,th{border:1px solid #ccd7df;padding:8px;text-align:left;vertical-align:top;overflow-wrap:anywhere}th{background:#eaf2f8}code{font:11px Consolas,monospace;overflow-wrap:anywhere}.finding{page-break-inside:avoid;border-bottom:1px solid #dee5ea;padding:8px 0}.notice{background:#fff5e3;border-left:4px solid #bf8d27;padding:14px;margin:20px 0}@media print{body{margin:0;padding:0}button{display:none}}</style></head><body><header><small>SPECTRA / DIGITAL FORENSICS</small><h1>Android APK Static Investigation Report</h1><p>Evidence-driven capability assessment • Static analysis only</p></header>
 <h2>Evidence identification</h2><table><tr><th>Filename</th><td>${esc(s.filename)}</td></tr><tr><th>Package</th><td>${esc(s.metadata.package||'Unavailable')}</td></tr><tr><th>File size</th><td>${esc(sz(s.size_bytes))}</td></tr><tr><th>SHA-256</th><td><code>${esc(s.sha256)}</code></td></tr><tr><th>Scan timestamp (UTC)</th><td>${esc(s.scan_utc)}</td></tr><tr><th>Review priority</th><td>${esc(s.assessment.priority)} (${s.assessment.review_score}/100 heuristic review score; NOT malware likelihood)</td></tr></table>
 <div class="notice"><b>Scope and limitations:</b> This tool does not run APKs, capture camera data, observe traffic, verify a live C2 server, or confirm keylogging / exfiltration. Declared permissions, method references and embedded strings may be present in unused libraries. Obfuscation, encrypted strings, reflection and native code may hide behaviors. A lack of findings is not a clean bill of health.</div>
 <h2>Summary</h2><p>${s.findings.length} findings; ${s.permissions.length} manifest permissions; ${s.indicators.length} embedded network candidates; ${s.coverage.dex_files} DEX files parsed; ${s.coverage.dex_strings} strings inspected; ${s.coverage.dex_method_refs} method references inspected.</p>
 <h2>Recovered APK stages</h2><table><tr><th>Stage</th><th>Package</th><th>SHA-256</th><th>DEX</th><th>Permissions</th></tr>${(s.stages||[]).map(v=>`<tr><td>${v.stage}</td><td><code>${esc(v.metadata.package)}</code></td><td><code>${esc(v.sha256)}</code></td><td>${v.dex_files}</td><td>${v.permissions.length}</td></tr>`).join('')}</table>
 <h2>Unpacking notes</h2><ul>${(s.loader_notes||[]).map(n=>`<li>${esc(n)}</li>`).join('')}</ul>
 <h2>Surveillance command labels from DEX</h2><table><tr><th>Stage</th><th>Category</th><th>Command</th><th>Evidence</th></tr>${(s.command_indicators||[]).map(x=>`<tr><td>${x.stage}</td><td>${esc(x.category)}</td><td><code>${esc(x.value)}</code></td><td><code>${esc(x.source.join(', '))}</code></td></tr>`).join('')}</table>
 <h2>Configured endpoints and settings</h2><table><tr><th>Stage</th><th>Source</th><th>Property</th><th>Value</th></tr>${(s.settings_evidence||[]).map(x=>`<tr><td>${x.stage}</td><td><code>${esc(x.source)}</code></td><td>${esc(x.key)}</td><td><code>${esc(String(x.value))}</code></td></tr>`).join('')}</table>
 <h2>Selected DEX code references</h2><table><tr><th>Stage/DEX</th><th>Method reference (not decompiled source)</th></tr>${(s.code_references||[]).map(x=>`<tr><td>${x.stage} / ${esc(x.file)}</td><td><code>${esc(x.method)}</code></td></tr>`).join('')}</table>
 <h2>Selected HTML / text excerpts</h2><table><tr><th>Source</th><th>Line</th><th>Content</th></tr>${(s.text_evidence||[]).map(x=>`<tr><td>${esc(x.file)}</td><td>${x.line}</td><td><code>${esc(x.snippet)}</code></td></tr>`).join('')}</table>
 <h2>Technical findings</h2>${body||'<p>No signatures detected in scanned content. This does not prove the APK is benign.</p>'}
 <h2>Declared permissions</h2><table>${s.permissions.map(p=>`<tr><td><code>${esc(p)}</code></td></tr>`).join('')}</table>
 <h2>Embedded network indicators (unverified)</h2><table><tr><th>Candidate</th><th>Type</th><th>Source</th></tr>${s.indicators.map(i=>`<tr><td>${esc(i.value)}</td><td>${esc(i.kind)}</td><td><code>${esc(i.source.join(', '))}</code></td></tr>`).join('')}</table>
 <h2>Processing coverage</h2><table>${Object.entries(s.coverage).map(([k,v])=>`<tr><th>${esc(k)}</th><td>${esc(v)}</td></tr>`).join('')}</table>
 <h2>Warnings</h2>${s.warnings.length?`<ul>${s.warnings.map(w=>`<li>${esc(w)}</li>`).join('')}</ul>`:'<p>No parser warnings.</p>'}
 <h2>Recommended forensic next steps</h2><p>Correlate related permissions with actual code call sites; inspect hardcoded host ownership and protocol; perform isolated emulator-based runtime testing; capture network traffic with authorization; and validate any apparent sensitive-data transfers before characterizing behavior as spyware.</p>
 <footer><hr>Generated offline by SPECTRA APK Threat Analyzer. Preserve original APK and hash separately.</footer></body></html>`;
}
$('downloadHtml').addEventListener('click',()=>{if(scan)download('SPECTRA_Report_'+scan.sha256.slice(0,12)+'.html',reportHtml(scan),'text/html')});
