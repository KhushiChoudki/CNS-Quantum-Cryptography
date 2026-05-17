import re

with open('public/index.html', encoding='utf-8') as f:
    html = f.read()

# Fix showTab arrays
html = html.replace(
    "['dash','auth','vpn','attacks','audit','arch'].forEach",
    "['dash','auth','vpn','attacks','audit','arch','bench','stats','hndl'].forEach"
)
html = html.replace(
    "['dash','auth','vpn','attacks','audit','arch'][i]===t",
    "['dash','auth','vpn','attacks','audit','arch','bench','stats','hndl'][i]===t"
)

extra = (
    '<div class="ni" title="Benchmark" onclick="showTab(\'bench\')">'
    '<svg fill="none" stroke="currentColor" viewBox="0 0 24 24">'
    '<path d="M3 3v18h18"/><path d="m19 9-5 5-4-4-3 3"/></svg></div>\n'
    '<div class="ni" title="Stats/ROC" onclick="showTab(\'stats\')">'
    '<svg fill="none" stroke="currentColor" viewBox="0 0 24 24">'
    '<path d="M3 3v18h18"/><path d="m7 16 4-8 4 8"/></svg></div>\n'
    '<div class="ni" title="HNDL Attack" onclick="showTab(\'hndl\')">'
    '<svg fill="none" stroke="currentColor" viewBox="0 0 24 24">'
    '<path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/></svg></div>\n'
)

html = html.replace('</aside>', extra + '</aside>', 1)

# Inject benchmark+stats+hndl JS before </script>
bench_js = """
// ── Benchmark ───────────────────────────────────────────────────────────────
let chBench=null, chSizes=null, chDist=null, chROC=null, chNoise=null;
async function runBench(){
  const st=document.getElementById('bench-status');
  st.textContent='Running Kyber-512 + Dilithium-2 benchmark... (may take 5-10s)';
  st.style.color='var(--cyan)';
  try{
    const d=await(await fetch('/auth/benchmark?runs=20')).json();
    st.textContent='Benchmark complete!';
    st.style.color='var(--green)';
    // Latency chart
    const labels=['Kyber KeyGen','Kyber Encaps','Kyber Decaps','Dilithium KeyGen','Dilithium Sign','Dilithium Verify','RSA KeyGen*','RSA Sign*','ECDH Derive*'];
    const vals=[
      d.kyber_512.keygen.mean_ms, d.kyber_512.encapsulate.mean_ms, d.kyber_512.decapsulate.mean_ms,
      d.dilithium_2.keygen.mean_ms, d.dilithium_2.sign.mean_ms, d.dilithium_2.verify.mean_ms,
      d.rsa_2048_simulated.keygen.mean_ms, d.rsa_2048_simulated.sign.mean_ms, d.ecdh_p256_simulated.derive.mean_ms
    ];
    const colors=['rgba(0,212,255,.7)','rgba(0,212,255,.7)','rgba(0,212,255,.7)','rgba(124,58,237,.7)','rgba(124,58,237,.7)','rgba(124,58,237,.7)','rgba(239,68,68,.5)','rgba(239,68,68,.5)','rgba(239,68,68,.5)'];
    const ctx=document.getElementById('cBench').getContext('2d');
    if(chBench)chBench.destroy();
    chBench=new Chart(ctx,{type:'bar',data:{labels,datasets:[{data:vals,backgroundColor:colors,borderRadius:4}]},options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false},tooltip:{callbacks:{label:c=>c.raw.toFixed(3)+' ms'}}},scales:{y:{grid:{color:'rgba(255,255,255,.04)'},ticks:{color:'#64748b',callback:v=>v.toFixed(1)+'ms'}},x:{ticks:{color:'#64748b',font:{size:9}},grid:{display:false}}}}});
    // Sizes chart
    const ks=d.key_sizes;
    const sCtx=document.getElementById('cSizes').getContext('2d');
    if(chSizes)chSizes.destroy();
    chSizes=new Chart(sCtx,{type:'bar',data:{labels:['Kyber-512 PK','Kyber-512 SK','Kyber CT','Dilithium-2 PK','Dilithium-2 SK','Dilithium Sig','RSA-2048 PK','RSA-2048 SK','RSA Sig'],datasets:[{data:[ks.kyber_512.pk,ks.kyber_512.sk,ks.kyber_512.ct,ks.dilithium_2.pk,ks.dilithium_2.sk,ks.dilithium_2.sig,ks.rsa_2048.pk,ks.rsa_2048.sk,ks.rsa_2048.sig],backgroundColor:['rgba(0,212,255,.6)','rgba(0,212,255,.6)','rgba(0,212,255,.6)','rgba(124,58,237,.6)','rgba(124,58,237,.6)','rgba(124,58,237,.6)','rgba(239,68,68,.5)','rgba(239,68,68,.5)','rgba(239,68,68,.5)'],borderRadius:4}]},options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false}},scales:{y:{grid:{color:'rgba(255,255,255,.04)'},ticks:{color:'#64748b',callback:v=>v+' B'}},x:{ticks:{color:'#64748b',font:{size:9}},grid:{display:false}}}}});
    // Table
    const rows=[
      {op:'Kyber-512 KeyGen',  pqc:d.kyber_512.keygen.mean_ms,     cls:d.rsa_2048_simulated.keygen.mean_ms, qsafe:true},
      {op:'Kyber-512 Encaps',  pqc:d.kyber_512.encapsulate.mean_ms, cls:'N/A (ECDH)', qsafe:true},
      {op:'Kyber-512 Decaps',  pqc:d.kyber_512.decapsulate.mean_ms, cls:'N/A (ECDH)', qsafe:true},
      {op:'Dilithium-2 KeyGen',pqc:d.dilithium_2.keygen.mean_ms,   cls:d.rsa_2048_simulated.keygen.mean_ms, qsafe:true},
      {op:'Dilithium-2 Sign',  pqc:d.dilithium_2.sign.mean_ms,     cls:d.rsa_2048_simulated.sign.mean_ms, qsafe:true},
      {op:'Dilithium-2 Verify',pqc:d.dilithium_2.verify.mean_ms,   cls:d.rsa_2048_simulated.verify.mean_ms, qsafe:true},
    ];
    document.getElementById('bench-table').innerHTML='<table class="token-table"><thead><tr><th>Operation</th><th>PQC (ms)</th><th>Classical (ms)*</th><th>Quantum Safe</th></tr></thead><tbody>'+
      rows.map(r=>`<tr><td style="text-align:left">${r.op}</td><td>${typeof r.pqc==='number'?r.pqc.toFixed(3):r.pqc}</td><td>${typeof r.cls==='number'?r.cls.toFixed(3):r.cls}</td><td>${r.qsafe?'<span class=\\"tag-ok\\">YES</span>':'<span class=\\"tag-err\\">NO</span>'}</td></tr>`).join('')+
      '</tbody></table><div style="font-size:.68rem;color:var(--muted);margin-top:8px">*Classical timings simulated via SHA-256 loops scaled to published OpenSSL benchmark ratios</div>';
  }catch(e){st.textContent='Bridge offline: '+e.message;st.style.color='var(--red)';}
}

// ── Stats/ROC ───────────────────────────────────────────────────────────────
async function loadStats(){
  try{
    const d=await(await fetch('/auth/security-analysis?samples=300')).json();
    // Distribution means chart
    const dCtx=document.getElementById('cDist').getContext('2d');
    if(chDist)chDist.destroy();
    const scens=['benign','noisy_05pct','noisy_15pct','random','partial_50','partial_75'];
    const labels=['Benign','Noisy 5%','Noisy 15%','Random','Partial 50%','Partial 75%'];
    const means=scens.map(s=>d.distributions[s].stats.mean);
    const stds=scens.map(s=>d.distributions[s].stats.std);
    chDist=new Chart(dCtx,{type:'bar',data:{labels,datasets:[{label:'Mean Confidence',data:means,backgroundColor:means.map(v=>v>=0.85?'rgba(16,185,129,.6)':v>=0.6?'rgba(245,158,11,.6)':'rgba(239,68,68,.6)'),borderRadius:4}]},options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false},annotation:{annotations:{line1:{type:'line',yMin:0.85,yMax:0.85,borderColor:'rgba(0,212,255,.7)',borderWidth:1.5,borderDash:[4,4]}}}},scales:{y:{min:0,max:1,grid:{color:'rgba(255,255,255,.04)'},ticks:{color:'#64748b',callback:v=>(v*100).toFixed(0)+'%'}},x:{ticks:{color:'#64748b',font:{size:9}},grid:{display:false}}}}});
    // ROC chart
    const rCtx=document.getElementById('cROC').getContext('2d');
    if(chROC)chROC.destroy();
    const roc=d.roc_benign_vs_random;
    chROC=new Chart(rCtx,{type:'line',data:{labels:roc.fpr,datasets:[{label:'ROC (Benign vs Random) AUC='+roc.auc,data:roc.tpr,borderColor:'#00d4ff',backgroundColor:'rgba(0,212,255,.05)',fill:true,tension:.3,pointRadius:0},{label:'Random Classifier',data:roc.fpr,borderColor:'rgba(255,255,255,.2)',borderDash:[4,4],pointRadius:0}]},options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{labels:{color:'#64748b',font:{size:9}}}},scales:{x:{title:{display:true,text:'FPR',color:'#64748b'},ticks:{color:'#64748b',maxTicksLimit:6},grid:{color:'rgba(255,255,255,.04)'}},y:{title:{display:true,text:'TPR',color:'#64748b'},ticks:{color:'#64748b'},grid:{color:'rgba(255,255,255,.04)'}}}}});
    // Noise tolerance chart
    const nCtx=document.getElementById('cNoise').getContext('2d');
    if(chNoise)chNoise.destroy();
    const nt=d.noise_tolerance_curve;
    chNoise=new Chart(nCtx,{type:'line',data:{labels:nt.map(r=>(r.noise_level*100).toFixed(0)+'%'),datasets:[{label:'False Negative Rate',data:nt.map(r=>r.fnr),borderColor:'#ef4444',backgroundColor:'rgba(239,68,68,.06)',fill:true,tension:.4,pointRadius:3},{label:'Mean Confidence',data:nt.map(r=>r.mean_conf),borderColor:'#00d4ff',tension:.4,pointRadius:2}]},options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{labels:{color:'#64748b',font:{size:9}}}},scales:{x:{title:{display:true,text:'Noise Level',color:'#64748b'},ticks:{color:'#64748b'},grid:{color:'rgba(255,255,255,.04)'}},y:{min:0,max:1,ticks:{color:'#64748b'},grid:{color:'rgba(255,255,255,.04)'}}}}});
    // Accept rate table
    const m=d.metrics_at_threshold_85;
    document.getElementById('stats-table').innerHTML='<table class="token-table"><thead><tr><th>Scenario</th><th>Accept Rate</th><th>Accepted</th><th>Rejected</th><th>Decision</th></tr></thead><tbody>'+
      Object.entries(m).map(([k,v])=>`<tr><td style="text-align:left">${k.replace(/_/g,' ')}</td><td><strong>${(v.accept_rate*100).toFixed(1)}%</strong></td><td>${v.accepted}</td><td>${v.rejected}</td><td>${v.accept_rate>=0.7?'<span class=\\"tag-ok\\">ACCEPT</span>':'<span class=\\"tag-err\\">BLOCK</span>'}</td></tr>`).join('')+
      '</tbody></table>';
  }catch(e){console.error(e);}
}

// ── HNDL ───────────────────────────────────────────────────────────────────
async function loadHNDL(){
  const cap=document.getElementById('hndl-capture');
  const def=document.getElementById('hndl-defenses');
  cap.textContent='Simulating HNDL scenario...';
  try{
    const d=await(await fetch('/auth/hndl-demo')).json();
    cap.textContent=JSON.stringify(d.captured_today,null,2);
    cap.className='result warn';
    def.innerHTML=d.maqraf_defenses.map(x=>`<div class="flow active" style="margin:4px 0"><div class="flow-icon" style="background:rgba(16,185,129,.1)">🛡</div><div><strong>${x.defense}</strong> <span class="tag-ok">${x.status}</span><br><span style="font-size:.72rem;color:var(--muted)">${x.detail}</span></div></div>`).join('');
  }catch(e){cap.textContent='Bridge offline';cap.className='result err';}
}
"""

html = html.replace('function delay(ms)', bench_js + '\nfunction delay(ms)')

with open('public/index.html', 'w', encoding='utf-8') as f:
    f.write(html)

print('All JS injected. Final size:', len(html), 'bytes')
