// ATTMAP-AI — ATT&CK Technique Mapper

const PROVIDERS = {
  anthropic: { name:'Claude', defaultModel:'claude-sonnet-4-6',      storageKey:'attmap_key_anthropic', modelKey:'attmap_model_anthropic' },
  openai:    { name:'GPT',    defaultModel:'gpt-4o',                  storageKey:'attmap_key_openai',   modelKey:'attmap_model_openai'   },
  gemini:    { name:'Gemini', defaultModel:'gemini-2.0-flash',        storageKey:'attmap_key_gemini',   modelKey:'attmap_model_gemini'   },
  groq:      { name:'Groq',   defaultModel:'llama-3.3-70b-versatile', storageKey:'attmap_key_groq',    modelKey:'attmap_model_groq'    }
};
const PROVIDER_KEY = 'attmap_active_provider';

// ── QUERYBASE lookup ──────────────────────────────────────────────────────────
const QB_INDEX = 'https://raw.githubusercontent.com/h3ad-sec/QUERYBASE/main/index/queries.json';
const QB_RAW   = 'https://raw.githubusercontent.com/h3ad-sec/QUERYBASE/main/';
let _qbIndex   = null;

async function fetchQueriesForTechniques(techniqueIds) {
  try {
    if (!_qbIndex) {
      const r = await fetch(QB_INDEX);
      if (!r.ok) return [];
      _qbIndex = await r.json();
    }
    const useOrder = { detection: 0, hunting: 1, triage: 2, forensic: 3 };
    const matches = (_qbIndex.queries || []).filter(q =>
      techniqueIds.some(tid => q.technique === tid || q.technique.startsWith(tid.split('.')[0]))
    ).sort((a, b) => {
      const src = (a.source === 'original' ? 0 : 1) - (b.source === 'original' ? 0 : 1);
      return src !== 0 ? src : (useOrder[a.use_case] ?? 9) - (useOrder[b.use_case] ?? 9);
    }).slice(0, 6);
    if (!matches.length) return [];
    return (await Promise.all(matches.map(q => fetch(QB_RAW + q.file).then(r => r.json()).catch(() => null)))).filter(Boolean);
  } catch { return []; }
}

const SYSTEM_PROMPT = `You are an L3 SOC analyst and threat intelligence analyst with deep expertise in MITRE ATT&CK, adversary TTPs, and detection engineering.
CRITICAL: Return ONLY raw JSON. No markdown fences, no preamble, no explanation. Invalid JSON breaks the tool.

INPUT TYPES — handle each precisely:
- ARTICLE/REPORT: Extract only explicitly described adversary behaviors from the text. Ignore speculative or hedged language ("may", "could", "typically"). Only map what the article states happened.
- LOGS: Parse each log entry for observable behaviors (process creation, parent-child chains, network connections, file writes, registry ops, scheduled tasks, service installs, etc.). Map each observable to its most specific technique.
- ALERT: Read the alert title, description, rule logic, and metadata fields. Map the specific behavior that triggered the alert — not the alert category name.
- BEHAVIOR: Map the described action directly.
- AUTO: Infer the input type and apply the matching approach above.

STRICT DATA DISCIPLINE:
- Only map techniques directly evidenced by the input — not adjacent, inferred, or speculative
- Use the most specific sub-technique available (T1003.001, not T1003)
- Confidence: HIGH = directly evidenced; MEDIUM = strongly implied; LOW = possible given limited signal
- Detection gaps: only those relevant to the specific techniques mapped
- Hunting pivots: specific and actionable — name exact fields, process names, or conditions to hunt on
- If known threat actors or malware families use these techniques in the given context, name them
- No filler, no generic advice, no em dashes

Return JSON with exactly these four keys:
{
  "techniques": [
    {
      "id": "TXXXX.XXX",
      "name": "Technique Name (most specific sub-technique)",
      "tactic": "Tactic Name",
      "confidence": "HIGH or MEDIUM or LOW",
      "relevance": "1-2 sentences: how this maps to the input evidence. Name known actors if applicable."
    }
  ],
  "kill_chain": {
    "stages": ["Tactic names in kill chain order — only those evidenced by the input"],
    "summary": "2-3 sentences on what attack phase or campaign pattern this suggests."
  },
  "detection_gaps": ["Specific gap — what telemetry is missing or what coverage needs improvement for these techniques"],
  "hunting_pivots": ["Specific actionable hunt — name exact process, field, or condition, e.g. 'Hunt for LSASS handles from non-system processes with PROCESS_VM_READ access rights across all DCs in the last 30 days'"]
}
Map 3-8 techniques. Write 2-4 detection gaps and 3-5 hunting pivots.`;

let activeProvider  = localStorage.getItem(PROVIDER_KEY) || 'anthropic';
let activeInputType = 'auto';
let currentResult   = null;

async function callAI(userMessage) {
  const p      = PROVIDERS[activeProvider];
  const apiKey = localStorage.getItem(p.storageKey) || '';
  const model  = localStorage.getItem(p.modelKey) || p.defaultModel;
  if (!apiKey) throw new Error('No API key set for ' + p.name + '. Click ⚙ to add your key.');

  if (activeProvider === 'anthropic') {
    const r = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: { 'Content-Type':'application/json', 'x-api-key':apiKey, 'anthropic-version':'2023-06-01', 'anthropic-dangerous-direct-browser-access':'true' },
      body: JSON.stringify({ model, max_tokens:2500, system:SYSTEM_PROMPT, messages:[{role:'user',content:userMessage}] })
    });
    const d = await r.json();
    if (!r.ok) throw new Error(d.error?.message || r.statusText);
    return d.content[0].text;
  }
  if (activeProvider === 'openai') {
    const r = await fetch('https://api.openai.com/v1/chat/completions', {
      method: 'POST',
      headers: { 'Content-Type':'application/json', 'Authorization':'Bearer '+apiKey },
      body: JSON.stringify({ model, max_tokens:2500, messages:[{role:'system',content:SYSTEM_PROMPT},{role:'user',content:userMessage}] })
    });
    const d = await r.json();
    if (!r.ok) throw new Error(d.error?.message || r.statusText);
    return d.choices[0].message.content;
  }
  if (activeProvider === 'gemini') {
    const r = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${apiKey}`, {
      method: 'POST',
      headers: { 'Content-Type':'application/json' },
      body: JSON.stringify({ contents:[{parts:[{text:SYSTEM_PROMPT+'\n\n'+userMessage}]}], generationConfig:{maxOutputTokens:2500} })
    });
    const d = await r.json();
    if (!r.ok) throw new Error(d.error?.message || r.statusText);
    return d.candidates[0].content.parts[0].text;
  }
  if (activeProvider === 'groq') {
    const r = await fetch('https://api.groq.com/openai/v1/chat/completions', {
      method: 'POST',
      headers: { 'Content-Type':'application/json', 'Authorization':'Bearer '+apiKey },
      body: JSON.stringify({ model, max_tokens:2500, messages:[{role:'system',content:SYSTEM_PROMPT},{role:'user',content:userMessage}] })
    });
    const d = await r.json();
    if (!r.ok) throw new Error(d.error?.message || r.statusText);
    return d.choices[0].message.content;
  }
}

function parseJSON(raw) {
  let s = raw.trim();
  s = s.replace(/^```(?:json)?\n?/i,'').replace(/\n?```$/,'');
  try {
    return JSON.parse(s);
  } catch(_) {
    // Fix unescaped backslashes (Windows paths in log inputs, e.g. C:\Windows\)
    s = s.replace(/\\(?!["\\/bfnrtu])/g, '\\\\');
    return JSON.parse(s);
  }
}

function esc(s) {
  return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

function makeCard(icon, title, bodyHTML) {
  return `<div class="section-card">
    <div class="section-header" onclick="this.closest('.section-card').classList.toggle('collapsed')">
      <div class="section-title"><span class="section-icon">${icon}</span>${esc(title)}</div>
      <div class="section-actions">
        <button class="copy-btn" onclick="event.stopPropagation();copyCard(this)">⧉ Copy</button>
        <span class="collapse-icon">▾</span>
      </div>
    </div>
    <div class="section-body">${bodyHTML}</div>
  </div>`;
}

function confClass(c) { return c==='HIGH'?'conf-high':c==='MEDIUM'?'conf-medium':'conf-low'; }

function renderTechniques(techniques) {
  if (!techniques?.length) return '<p class="summary-text" style="color:var(--muted)">No techniques mapped.</p>';
  return techniques.map(t => `
    <div class="technique-card">
      <div class="technique-header">
        <span class="technique-id">${esc(t.id)}</span>
        <span class="technique-name">${esc(t.name)}</span>
        <span class="confidence-badge ${confClass(t.confidence)}">${esc(t.confidence)}</span>
      </div>
      <div class="technique-tactic">${esc(t.tactic)}</div>
      <div class="technique-relevance">${esc(t.relevance)}</div>
    </div>`).join('');
}

function renderKillChain(kc) {
  if (!kc) return '';
  const tacticSet = new Set((kc.stages||[]).map(s=>s.toLowerCase()));
  const badges = (kc.stages||[]).map(s =>
    `<span class="tactic-badge has-technique">${esc(s)}</span>`
  ).join('');
  return `<p class="summary-text" style="margin-bottom:12px;">${esc(kc.summary)}</p>
  <div class="tactic-chain">${badges}</div>`;
}

function renderList(items, cls) {
  if (!items?.length) return '';
  return items.map(item => `<div class="${cls}">${esc(item)}</div>`).join('');
}

function renderPivots(pivots) {
  if (!pivots?.length) return '';
  return pivots.map((p,i) => `
    <div class="pivot-item">
      <span class="pivot-num">${i+1}</span>
      <span style="font-size:var(--fs-sm);line-height:1.6;">${esc(p)}</span>
    </div>`).join('');
}

function renderRelatedQueries(queries) {
  if (!queries.length) return;
  const html = queries.map(q => {
    const qText = (q.query || '').replace(/\\n/g, '\n');
    const langBadge = `<span class="confidence-badge conf-medium" style="text-transform:uppercase;font-size:9px;">${esc(q.language)}</span>`;
    const ucBadge   = `<span class="confidence-badge conf-low" style="font-size:9px;">${esc(q.use_case)}</span>`;
    return `<div class="technique-card" style="margin-bottom:10px;">
      <div class="technique-header">
        <span class="technique-id">${esc(q.technique)}</span>
        <span class="technique-name">${esc(q.title)}</span>
        ${langBadge}${ucBadge}
        <button class="copy-btn" style="font-size:10px;padding:2px 8px;margin-left:auto;" onclick="navigator.clipboard.writeText(${JSON.stringify(qText)})">⧉</button>
      </div>
      <pre style="margin:8px 0 0;padding:10px;background:var(--surface);border-radius:6px;font-size:11px;white-space:pre-wrap;word-break:break-all;color:var(--text);">${esc(qText)}</pre>
    </div>`;
  }).join('');
  document.getElementById('cards-container').insertAdjacentHTML('beforeend',
    makeCard('⌕', 'Related Queries from QUERYBASE', html)
  );
}

function renderOutput(result, title) {
  currentResult = result;
  document.getElementById('output-title').textContent = title;
  const c = document.getElementById('cards-container');
  c.innerHTML = [
    makeCard('◇', 'ATT&CK Techniques',     renderTechniques(result.techniques)),
    makeCard('▶', 'Kill Chain Progression', renderKillChain(result.kill_chain)),
    makeCard('○', 'Detection Gaps',         renderList(result.detection_gaps, 'gap-item')),
    makeCard('⌕', 'Hunting Pivots',         renderPivots(result.hunting_pivots))
  ].join('');
  const ids = (result.techniques || []).map(t => t.id).filter(Boolean);
  if (ids.length) fetchQueriesForTechniques(ids).then(renderRelatedQueries);
}

function copyCard(btn) {
  const body = btn.closest('.section-card').querySelector('.section-body');
  navigator.clipboard.writeText(body.innerText);
  const orig = btn.textContent;
  btn.textContent = '✓';
  setTimeout(() => { btn.textContent = orig; }, 1500);
}

function buildExportText(fmt) {
  if (!currentResult) return '';
  const lines = [];
  const sec = (title, content) => lines.push(fmt==='md' ? `## ${title}\n\n${content}\n` : `=== ${title} ===\n\n${content}\n`);
  if (currentResult.techniques?.length) sec('ATT&CK Techniques', currentResult.techniques.map(t=>`${t.id} — ${t.name} [${t.tactic}] [${t.confidence}]\n${t.relevance}`).join('\n\n'));
  if (currentResult.kill_chain) sec('Kill Chain', `${(currentResult.kill_chain.stages||[]).join(' → ')}\n\n${currentResult.kill_chain.summary}`);
  if (currentResult.detection_gaps?.length) sec('Detection Gaps', currentResult.detection_gaps.map(g=>`- ${g}`).join('\n'));
  if (currentResult.hunting_pivots?.length) sec('Hunting Pivots', currentResult.hunting_pivots.map((p,i)=>`${i+1}. ${p}`).join('\n'));
  return lines.join('\n');
}

// ── DOM
const generateBtn   = document.getElementById('generate-btn');
const clearBtn      = document.getElementById('clear-btn');
const behaviorInput = document.getElementById('behavior-input');
const loadingEl     = document.getElementById('loading-state');
const errorEl       = document.getElementById('error-state');
const outputEl      = document.getElementById('output-section');

function getActiveKey() { return localStorage.getItem(PROVIDERS[activeProvider].storageKey)||''; }
function updateBtn()    { generateBtn.disabled = !behaviorInput.value.trim() || !getActiveKey(); }

generateBtn.addEventListener('click', async () => {
  const behavior = behaviorInput.value.trim();
  if (!behavior) return;
  errorEl.classList.add('hidden');
  outputEl.classList.add('hidden');
  loadingEl.classList.remove('hidden');
  generateBtn.disabled = true;
  try {
    const ctx = document.getElementById('threat-context').value.trim();
    const typeLabels = { auto:'AUTO', article:'ARTICLE/REPORT', logs:'LOGS', alert:'ALERT', behavior:'BEHAVIOR' };
    const typeLabel  = typeLabels[activeInputType] || 'AUTO';
    const msg = `Input type: ${typeLabel}\n\n${behavior}${ctx?'\n\nKnown context: '+ctx:''}`;
    const raw    = await callAI(msg);
    const result = parseJSON(raw);
    loadingEl.classList.add('hidden');
    renderOutput(result, behavior.slice(0,60)+(behavior.length>60?'…':''));
    outputEl.classList.remove('hidden');
  } catch(e) {
    loadingEl.classList.add('hidden');
    document.getElementById('error-message').textContent = e.message;
    errorEl.classList.remove('hidden');
  } finally { updateBtn(); }
});

clearBtn.addEventListener('click', () => {
  behaviorInput.value = '';
  document.getElementById('threat-context').value = '';
  errorEl.classList.add('hidden');
  outputEl.classList.add('hidden');
  updateBtn();
});
behaviorInput.addEventListener('input', updateBtn);

document.getElementById('copy-all-btn').addEventListener('click', () => navigator.clipboard.writeText(buildExportText('md')));
document.getElementById('export-btn').addEventListener('click', () => {
  const fmt  = document.querySelector('.export-tab.active')?.dataset.fmt||'md';
  const blob = new Blob([buildExportText(fmt)],{type:'text/plain'});
  const a    = document.createElement('a'); a.href=URL.createObjectURL(blob); a.download=`attmap-${Date.now()}.${fmt}`; a.click();
});
document.querySelectorAll('.export-tab').forEach(t=>t.addEventListener('click',()=>{document.querySelectorAll('.export-tab').forEach(x=>x.classList.remove('active'));t.classList.add('active');}));
document.getElementById('new-btn').addEventListener('click',()=>{outputEl.classList.add('hidden');behaviorInput.focus();});

// ── Settings modal
const overlay = document.getElementById('modal-overlay');
document.getElementById('settings-btn').addEventListener('click',()=>{overlay.classList.remove('hidden');loadModal();});
document.getElementById('close-modal').addEventListener('click',()=>overlay.classList.add('hidden'));
overlay.addEventListener('click',e=>{if(e.target===overlay)overlay.classList.add('hidden');});

function loadModal(){Object.entries(PROVIDERS).forEach(([id,p])=>{const k=document.getElementById('key-'+id);const m=document.getElementById('model-'+id);if(k)k.value=localStorage.getItem(p.storageKey)||'';if(m)m.value=localStorage.getItem(p.modelKey)||p.defaultModel;});document.querySelectorAll('.provider-tab').forEach(t=>t.classList.toggle('active',t.dataset.provider===activeProvider));}
document.getElementById('save-key-btn').addEventListener('click',()=>{Object.entries(PROVIDERS).forEach(([id,p])=>{const k=document.getElementById('key-'+id);const m=document.getElementById('model-'+id);if(k)localStorage.setItem(p.storageKey,k.value.trim());if(m)localStorage.setItem(p.modelKey,m.value);});localStorage.setItem(PROVIDER_KEY,activeProvider);overlay.classList.add('hidden');updateKeyStatus();updateBtn();updateBadge();updateNotice();});
document.querySelectorAll('.provider-tab').forEach(tab=>tab.addEventListener('click',()=>{activeProvider=tab.dataset.provider;document.querySelectorAll('.provider-tab').forEach(t=>t.classList.toggle('active',t.dataset.provider===activeProvider));}));
document.querySelectorAll('.toggle-key-btn').forEach(btn=>btn.addEventListener('click',()=>{const inp=document.getElementById(btn.dataset.target);inp.type=inp.type==='password'?'text':'password';}));

function updateKeyStatus(){const el=document.getElementById('key-status');const ok=!!getActiveKey();el.textContent=ok?'API Key Set':'No API Key';el.className='key-status '+(ok?'has-key':'no-key');}
function updateBadge(){const b=document.getElementById('active-provider-badge');const names={anthropic:'Claude',openai:'GPT-4o',gemini:'Gemini',groq:'Groq'};b.textContent=names[activeProvider]||activeProvider;b.className='provider-badge '+activeProvider;}
function updateNotice(){const el=document.getElementById('notice-provider');if(el)el.textContent=PROVIDERS[activeProvider]?.name||activeProvider;}

function applyTheme(t){document.body.classList.toggle('light',t==='light');document.body.classList.toggle('dark',t!=='light');const logo=document.getElementById('navLogo');if(logo)logo.src=`https://raw.githubusercontent.com/h3ad-sec/h3ad-sec.github.io/main/logo-${t==='light'?'light':'dark'}.png`;}
applyTheme(localStorage.getItem('h3ad-theme')||'dark');
document.getElementById('theme-toggle').addEventListener('click',()=>{const next=document.body.classList.contains('light')?'dark':'light';localStorage.setItem('h3ad-theme',next);applyTheme(next);});

window.addEventListener('scroll',()=>document.body.classList.toggle('scrolled',window.scrollY>40),{passive:true});
function toggleDrawer(){document.getElementById('navDrawer').classList.toggle('open');}
function closeDrawer(){document.getElementById('navDrawer').classList.remove('open');}

document.querySelectorAll('.type-pill').forEach(pill => {
  pill.addEventListener('click', () => {
    document.querySelectorAll('.type-pill').forEach(p => p.classList.remove('active'));
    pill.classList.add('active');
    activeInputType = pill.dataset.type;
  });
});

updateKeyStatus(); updateBadge(); updateNotice(); updateBtn(); loadModal();
