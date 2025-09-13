# This file is part of the phishing detector project.
# The comments explain in simple words what each part does for non-coders.
# We import the packages and modules that this file needs below.
from flask import Flask, render_template, request
# Flask = small web server, render templates = show HTML pages, request = read user input

# We import the packages and modules that this file needs below.
from brand_rules import brand_mismatch_boost, sender_brand_crosscheck
# brand_mismatch_boost = checks if links match brands mentioned
# sender_brand_crosscheck = checks if sender's domain matches brands

# We import the packages and modules that this file needs below.
from heuristics import URL_REGEX, IP_URL_REGEX, SUSPICIOUS_TLDS, KEYWORDS, URLHeuristics
# heuristics = small rules like “does URL look suspicious?”

# We import the packages and modules that this file needs below.
from scoring import phishing_score, apply_strict_whitelist
# phishing_score = base rules scoring
# apply_strict_whitelist = lowers score if domain is trusted

# We import the packages and modules that this file needs below.
from trusted import load_trusted_domains, is_trusted
# load_trusted_domains = loads list of good/trusted sites

# We import the packages and modules that this file needs below.
import pickle, joblib, os, urllib.parse, pandas as pd
# pickle/joblib = load ML models
# pandas = helps wrap input for ML

# --- Setup web app ---
app = Flask(__name__)

# Load trusted domains (from file)
TRUSTED_DOMAINS = load_trusted_domains()

# Function 'parse_hosts': this is a reusable block of logic used by the app.
def parse_hosts(text):
    """
    ELI5: Pull out all website addresses (hosts/domains) from the text.
    Remove 'www.' at start so we can compare more easily.
    """
    hosts = set()
    for u in URL_REGEX.findall(text):   # find all things that look like URLs
        try:
            h = urllib.parse.urlparse(u if u.startswith("http") else "http://" + u).hostname
            if h:
                h = h.lower()
                if h.startswith("www."): h = h[4:]
                hosts.add(h)
        except:
            pass
    return hosts

# Load machine learning models (spam + phishing)
spam_clf = pickle.load(open("email_spam_pipeline.pkl", "rb"))
phish_clf = joblib.load("phishing_pipeline.joblib")

@app.route("/", methods=["GET", "POST"])
# Function 'index': this is a reusable block of logic used by the app.
def index():
    """
    ELI5: This is the main webpage.
    - If GET: just show the form
    - If POST: user pasted email, we run checks and show results
    """
    result = None
    txt = ""
    if request.method == "POST":
        # Get pasted email text
        txt = request.form.get("email_text", "").strip()
        if txt:
            # Also get optional sender domain typed by user
            sender_domain_input = request.form.get("sender_domain", "").strip().lower()
            if sender_domain_input.startswith("www."):
                sender_domain_input = sender_domain_input[4:]
            sender_domain_input = sender_domain_input or None

            # --- Step 1: ML spam classifier ---
            s_pred = spam_clf.predict([txt])[0]               # is it spam (yes/no)?
            s_prob = spam_clf.predict_proba([txt])[0]          # probability
            s_label = "Spam" if s_pred == 1 else "Not Spam"
            s_conf = round(float(s_prob[s_pred]) * 100, 2)

            # --- Step 2: ML phishing classifier ---
            df = pd.DataFrame({"text": [txt], "raw": [txt]})
            p_pred = phish_clf.predict(df)[0]
            try:
                p_prob = float(phish_clf.predict_proba(df)[0][1]) * 100
                p_conf = round(p_prob, 2)
            except:
                p_conf = None
            p_label = "Phishing" if p_pred == 1 else "Not Phishing"

            # --- Step 3: Rule-based scoring (simple heuristics) ---
            rules = phishing_score(txt)

            # --- Step 4: Brand check ---
            all_hosts = parse_hosts(txt)
            brand_info = brand_mismatch_boost(txt, all_hosts)   # do brands & links match?
            brand_note = None
            if brand_info["notes"]:
                # if mismatch, push score higher
                rules["score"] = min(10.0, rules["score"] + 2.5)
                rules["risk"] = "High" if rules["score"] >= 7.5 else ("Medium" if rules["score"] >= 4 else "Low")
                if p_conf is None or p_conf >= 20 or p_label == "Phishing":
                    p_label = "Phishing"
                brand_note = "; ".join(brand_info["notes"])

            # --- Step 5: Sender ↔ Brand cross-check ---
            text_for_sender = txt if not sender_domain_input else f"From: <noreply@{sender_domain_input}>\n" + txt
            sender_info = sender_brand_crosscheck(text_for_sender, all_hosts)
            if sender_info.get("notes"):
                # raise score if mismatch
                rules["score"] = min(10.0, rules["score"] + 2.5)
                rules["risk"] = "High" if rules["score"] >= 7.5 else ("Medium" if rules["score"] >= 4 else "Low")
                if p_conf is None or p_conf >= 15 or p_label == "Phishing":
                    p_label = "Phishing"
                extra = "; ".join(sender_info["notes"])
                brand_note = (extra if not brand_note else brand_note + "; " + extra)

            # --- Step 6: Whitelist check ---
            s_label, s_conf, p_label, p_conf, rules, wl_note = apply_strict_whitelist(
                txt, s_label, s_conf, p_label, p_conf, rules,
                parse_hosts, is_trusted, TRUSTED_DOMAINS
            )

            # --- Step 7: Final score combine ---
            phish_component = (p_conf or 0.0) / 10.0
            spam_component = ((s_conf if s_label == "Spam" else 0.0) / 10.0) * 0.7
            rule_component = float(rules["score"])
            final_risk = round(max(rule_component, phish_component, spam_component), 1)
            final_risk_label = "High" if final_risk >= 7.5 else ("Medium" if final_risk >= 4.0 else "Low")

            # --- Pack results for template ---
            result = {
                "spam_label": s_label,
                "spam_conf": s_conf,
                "phishing_label": p_label,
                "phishing_conf": p_conf,
                "phish_score": rules["score"],
                "phish_risk": rules["risk"],
                "final_risk": final_risk,
                "final_risk_label": final_risk_label,
                "phish_details": rules["details"],
                "whitelist_note": wl_note,
                "brand_note": brand_note,
                "sender_domain": sender_domain_input or (sender_info.get("sender_domain") if 'sender_info' in locals() else None),
            }
    return render_template("index.html", result=result, email_text=txt,
                           TRUSTED_DOMAINS=sorted(list(TRUSTED_DOMAINS)))

if __name__ == "__main__":
    app.run(debug=True)