import re
from heuristics import URL_REGEX, IP_URL_REGEX

KEYWORDS = {"urgent","verify","account","password","login","suspend","locked","update"}

WORD_RE = re.compile(r'\b[a-z0-9]+\b', flags=re.I)

def extract_hosts(text):
    hosts = []
    for u in URL_REGEX.findall(text or ""):
        # simple host extraction
        try:
            if u.startswith("www.") or u.startswith("http"):
                # naive
                host = re.sub(r'^https?://', '', u, flags=re.I).split('/')[0]
            else:
                host = u.split('/')[0]
            host = host.lower().lstrip("www.")
            hosts.append(host)
        except:
            continue
    return hosts

def phishing_score(text: str):
    txt = (text or "").strip()
    urls = URL_REGEX.findall(txt)
    n_urls = len(urls)
    n_ip = len(IP_URL_REGEX.findall(txt))
    words = set(m.group(0).lower() for m in WORD_RE.finditer(txt))
    kw = len(KEYWORDS & words)
    excl = txt.count("!")
    # simple scoring with capped contributions
    score = 0.0
    score += min(5.0, n_urls * 0.6)
    score += min(3.0, n_ip * 1.5)
    score += min(1.5, kw * 0.4)
    score += min(1.0, excl / 5.0)
    score = max(0.0, min(10.0, score))
    risk = "High" if score >= 7.5 else ("Medium" if score >= 4.0 else "Low")
    details = {"urls": n_urls, "ip_urls": n_ip, "keywords": kw, "exclamations": excl, "hosts": extract_hosts(txt)}
    return {"score": round(score,2), "risk": risk, "details": details}
