from pathlib import Path

def load_trusted(path="trusted_domains.txt"):
    p = Path(path)
    doms = set()
    if not p.exists():
        return doms
    for line in p.read_text(encoding="utf-8").splitlines():
        s = line.strip().lower()
        if not s or s.startswith("#"):
            continue
        if s.startswith("www."):
            s = s[4:]
        doms.add(s)
    return doms

def is_trusted(host, trusted_set):
    return any(host == t or host.endswith("." + t) for t in trusted_set)
