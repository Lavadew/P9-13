import re
from sklearn.base import BaseEstimator, TransformerMixin
import numpy as np

URL_REGEX = re.compile(r'((?:https?://|http://|www\.)[^\s<>"]+)', re.I)
IP_URL_REGEX = re.compile(r'https?://(?:\d{1,3}\.){3}\d{1,3}', re.I)
SUSPICIOUS_TLDS = {"ru","cn","tk","top","gq","ml","ga","zip","mov"}

def normalize_host(host: str) -> str:
    if not host:
        return ""
    h = host.lower()
    if h.startswith("www."):
        return h[4:]
    return h

class URLFeatures(TransformerMixin, BaseEstimator):
    #Extract simple numeric URL features for the model.
    def fit(self, X, y=None):
        return self

    def transform(self, X):
        # X is iterable of texts
        out = []
        for text in X:
            text = text or ""
            urls = URL_REGEX.findall(text)
            n_urls = len(urls)
            n_ip = len(IP_URL_REGEX.findall(text))
            n_susp_tld = 0
            for u in urls:
                try:
                    # get tld quickly
                    tld = u.lower().split('.')[-1].split('/')[0]
                    if tld in SUSPICIOUS_TLDS:
                        n_susp_tld += 1
                except Exception:
                    pass
            out.append([n_urls, n_ip, n_susp_tld, text.count('!')])
        return np.array(out)
