from flask import Flask, render_template, request, jsonify
from scoring import phishing_score
from models import load_model
from brand_rules import sender_brand_check
from trusted import load_trusted

app = Flask(__name__)
# Load model once
try:
    pipe = load_model()
except Exception:
    pipe = None

TRUSTED = load_trusted()  # loads trusted_domains.txt if present

@app.route("/", methods=["GET","POST"])
def index():
    result = None
    text = ""
    if request.method == "POST":
        text = request.form.get("email_text","")
        rules = phishing_score(text)
        spam_pred = None
        if pipe:
            spam_pred = pipe.predict([text])[0]
        result = {
            "phish_rules": rules,
            "ml_pred": int(spam_pred) if spam_pred is not None else None
        }
    return render_template("index.html", result=result, email_text=text)

@app.route("/api/score", methods=["POST"])
def api_score():
    data = request.get_json() or {}
    text = data.get("text","")
    rules = phishing_score(text)
    ml = None
    if pipe:
        ml = int(pipe.predict([text])[0])
    return jsonify({"rules": rules, "ml": ml})

if __name__ == "__main__":
    app.run(debug=True)
