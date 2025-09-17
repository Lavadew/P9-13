from typing import List, Dict, Set

BRAND_TO_DOMAINS = {
    "paypal": {"paypal.com"},
    "github": {"github.com"},
    "microsoft": {"microsoft.com", "office.com"}
}

def find_brands(text: str) -> Set[str]:
    text = (text or "").lower()
    found = set()
    for b in BRAND_TO_DOMAINS:
        if b in text:
            found.add(b)
    return found

def sender_brand_check(sender_domain: str, text: str):
    sender = (sender_domain or "").lower()
    notes = []
    brands = find_brands(text)
    for b in brands:
        good = any(sender == d or sender.endswith("." + d) for d in BRAND_TO_DOMAINS.get(b, []))
        if not good:
            notes.append(f"Brand '{b}' mentioned but sender domain '{sender}' not matching trusted domains.")
    return {"sender": sender or None, "brands": sorted(list(brands)), "notes": notes}
