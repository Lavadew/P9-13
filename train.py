import argparse
from pathlib import Path
import pandas as pd
import numpy as np
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.compose import ColumnTransformer
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from heuristics import URLFeatures
from models import save_model

def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--csv", type=str, help="path to CSV file (columns: text,label)")
    p.add_argument("--text-col", default="text")
    p.add_argument("--label-col", default="label")
    return p.parse_args()

def normalize_labels(y):
    mapping = {"phishing":1,"spam":1,"1":1,"true":1,"yes":1,"phish":1,"legit":0,"ham":0,"0":0,"false":0,"no":0}
    def map_one(v):
        s = str(v).strip().lower()
        return mapping.get(s, None)
    y2 = y.map(map_one)
    if y2.isnull().any():
        # attempt numeric conversion
        try:
            yi = y.astype(int)
            return yi
        except:
            raise SystemExit("Cannot normalize labels; please supply 0/1 or phishing/legit labels")
    return y2.astype(int)

def main():
    args = parse_args()
    if not args.csv:
        raise SystemExit("Provide --csv path to training CSV")
    p = Path(args.csv)
    if not p.exists():
        raise SystemExit(f"CSV not found: {p}")
    df = pd.read_csv(p)
    if args.text_col not in df.columns or args.label_col not in df.columns:
        raise SystemExit(f"CSV must contain columns '{args.text_col}' and '{args.label_col}'")
    X_text = df[args.text_col].astype(str).fillna("")
    y = normalize_labels(df[args.label_col])
    X = pd.DataFrame({"text": X_text, "raw": X_text})
    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    ct = ColumnTransformer([
        ("tfidf", TfidfVectorizer(stop_words="english", max_features=20000), "text"),
        ("urlf", URLFeatures(), "raw")
    ])
    pipe = Pipeline([("features", ct), ("clf", LogisticRegression(max_iter=1000, class_weight="balanced"))])
    pipe.fit(Xtr, ytr)
    yp = pipe.predict(Xte)
    print(classification_report(yte, yp))
    save_model(pipe)
    print("[OK] Saved model to phishing_pipeline.joblib")

if __name__ == "__main__":
    main()