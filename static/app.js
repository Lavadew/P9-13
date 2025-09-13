// This script powers the interactive parts of the page.
// It highlights risky words, wraps links safely, and updates the progress bar.
// ---------- Whitelist JSON ----------
let TRUSTED_DOMAINS = [];
try {
  TRUSTED_DOMAINS = JSON.parse(document.getElementById("trusted-json")?.textContent || "[]");
} catch (_) { TRUSTED_DOMAINS = []; }

// ---------- Brand / rules ----------
const BRAND_TO_DOMAINS = {
  paypal: ["paypal.com"],
  github: ["github.com"],
  microsoft: ["microsoft.com","office.com","outlook.com"],
  "office 365": ["microsoft.com","office.com","outlook.com"],
  o365: ["microsoft.com","office.com","outlook.com"],
  dbs: ["dbs.com.sg","posb.com.sg"],
  singpass: ["singpass.gov.sg"],
  iras: ["iras.gov.sg"]
};

const BAD_WORDS = ["urgent","verify","password","account","login","click","reset","secure","update"];
const HREF_RE = /https?:\/\/[^\s)>'"]+/gi;
const IP_RE = /\b(?:(?:25[0-5]|2[0-4]\d|1?\d{1,2})\.){3}(?:25[0-5]|2[0-4]\d|1?\d{1,2})\b/gi;

function esc(s){return (s||"").replace(/[&<>"]/g, m=>({ "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;" }[m]))}

function collectTrustedHosts(text){
  const out = new Set();
  (text.match(HREF_RE)||[]).forEach(u=>{
    try{
      const h = new URL(u).hostname.toLowerCase().replace(/^www\./,"");
      TRUSTED_DOMAINS.forEach(d=>{
        if (h===d || h.endsWith("."+d)) out.add(h);
      });
    }catch(_){}
  });
  return Array.from(out).sort();
}

function brandWordsToSkip(hosts){
  const skip = new Set();
  hosts.forEach(h=>{
    const bare = h.toLowerCase();
    Object.entries(BRAND_TO_DOMAINS).forEach(([brand, doms])=>{
      if (doms.some(d => bare===d || bare.endsWith("."+d))) skip.add(brand);
    });
  });
  return skip;
}

// highlight(): turns raw text into safe HTML and marks risky parts.
function highlight(text){
  // escape first to avoid HTML injection
  let html = esc(text);

  // STEP 1: wrap URLs as badges
  html = html.replace(HREF_RE, u=>{
    let host = "";
    try { host = new URL(u).hostname.toLowerCase().replace(/^www\./,""); } catch(_){}
    let cls = "warn";
    if (TRUSTED_DOMAINS.some(d => host===d || host.endsWith("."+d))) cls = "safe";
    if (IP_RE.test(u)) cls = "danger";
    IP_RE.lastIndex = 0; // reset after test
    return `<a href="${esc(u)}" target="_blank" rel="nofollow noopener" class="badge ${cls}">${esc(u)}</a>`;
  });

  // STEP 2: highlight bad words ONLY outside <a>...</a>
  // Split into chunks that are either anchors or non-anchor text.
  const parts = html.split(/(<a\b[^>]*>.*?<\/a>)/gi);
  for (let i = 0; i < parts.length; i++) {
    const chunk = parts[i];
    if (!chunk || /^<a\b/i.test(chunk)) continue; // skip anchors
    let out = chunk;
    BAD_WORDS.forEach(w=>{
      const re = new RegExp(`\\b${w}\\b`, "gi");
      out = out.replace(re, m => `<mark class="danger">${m}</mark>`);
    });
    parts[i] = out;
  }

  return parts.join("");
}

// setRiskBar(): updates the width and color of the risk meter.
function setRiskBar(score){
  const el = document.getElementById("meterBar");
  if (!el) return;
  const pct = Math.max(0, Math.min(100, (Number(score)||0) * 10));
  el.style.width = `${pct}%`;
}

document.addEventListener("DOMContentLoaded", ()=>{
  const prev = document.getElementById("preview");
  const ta = document.getElementById("email_text");
  if (ta && prev){
    ta.addEventListener("input", ()=>{
      prev.innerHTML = highlight(ta.value);
    });
    prev.innerHTML = highlight(ta.value || "");
  }

  // Button: Clear
  document.getElementById("btnClear")?.addEventListener("click", () => {
    if (prev) prev.innerHTML = "";
    if (ta) ta.value = "";
    setRiskBar(0);
    const n = document.getElementById("riskNum"); if (n) n.textContent = "0";
  });

  // Auto-render after POST: if textarea already has content, render + set bar from caption
  if (ta && ta.value.trim() && prev) {
    prev.innerHTML = highlight(ta.value);
    const riskNum = parseFloat(document.getElementById("riskNum")?.textContent || "0");
    setRiskBar(riskNum);
  }
});
