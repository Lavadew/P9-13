import joblib

def save_model(pipe, path="phishing_pipeline.joblib"):
    joblib.dump(pipe, path)

def load_model(path="phishing_pipeline.joblib"):
    return joblib.load(path)
