"""
Train a Random Forest threat classifier on the KDD Cup 99 dataset.
Saves the trained model + scaler to classifier/model_artifacts/

Usage:
    python classifier/train.py
"""
import os
import pickle
import pandas as pd
from sklearn.ensemble         import RandomForestClassifier
from sklearn.preprocessing    import StandardScaler, LabelEncoder
from sklearn.model_selection  import train_test_split
from sklearn.metrics          import classification_report

# ── KDD Cup 99 column names ───────────────────────────────────────────────────
KDD_COLUMNS = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in",
    "num_compromised", "root_shell", "su_attempted", "num_root", "num_file_creations",
    "num_shells", "num_access_files", "num_outbound_cmds", "is_host_login",
    "is_guest_login", "count", "srv_count", "serror_rate", "srv_serror_rate",
    "rerror_rate", "srv_rerror_rate", "same_srv_rate", "diff_srv_rate",
    "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate",
    "dst_host_rerror_rate", "dst_host_srv_rerror_rate", "label",
]

# Map KDD attack categories → our threat labels
LABEL_MAP = {
    "normal":      "normal",
    # DoS family
    "back":        "dos", "land": "dos", "neptune": "ddos", "pod": "dos",
    "smurf":       "ddos", "teardrop": "dos", "apache2": "dos",
    "udpstorm":    "ddos", "processtable": "dos", "mailbomb": "dos",
    # Probe / port scan family
    "ipsweep":     "port_scan", "nmap": "port_scan",
    "portsweep":   "port_scan", "satan": "port_scan",
    "mscan":       "port_scan", "saint": "port_scan",
    # R2L (remote to local — brute force / phishing)
    "ftp_write":   "brute_force", "guess_passwd": "brute_force",
    "imap":        "brute_force", "multihop": "phishing",
    "phf":         "phishing", "spy": "phishing", "warezclient": "phishing",
    "warezmaster":  "phishing", "snmpgetattack": "brute_force",
    "named":       "phishing", "sendmail": "phishing",
    # U2R (user to root — privilege escalation / exfiltration)
    "buffer_overflow": "data_exfiltration", "loadmodule": "data_exfiltration",
    "perl":            "data_exfiltration", "rootkit": "data_exfiltration",
    "httptunnel":      "data_exfiltration", "ps": "data_exfiltration",
    "sqlattack":       "data_exfiltration", "xterm": "data_exfiltration",
}

NUMERIC_FEATURES = [
    "duration", "src_bytes", "dst_bytes", "hot", "num_failed_logins",
    "logged_in", "count", "srv_count", "serror_rate", "rerror_rate",
    "same_srv_rate", "diff_srv_rate", "dst_host_count",
    "dst_host_srv_count", "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
]


def load_data(path="data/kddcup.data_10_percent.gz"):
    """
    Load KDD Cup 99 10% dataset.
    Download from: http://kdd.ics.uci.edu/databases/kddcup99/kddcup99.html
    """
    print(f"[Train] Loading dataset from {path}...")
    df = pd.read_csv(path, names=KDD_COLUMNS, compression="gzip")

    # Clean label (strip trailing dot)
    df["label"] = df["label"].str.rstrip(".")
    df["threat"] = df["label"].map(LABEL_MAP).fillna("unknown")

    print(f"[Train] Loaded {len(df):,} records.")
    print(f"[Train] Threat distribution:\n{df['threat'].value_counts()}\n")

    X = df[NUMERIC_FEATURES].fillna(0).values
    y = df["threat"].values
    return X, y


def train(data_path="data/kddcup.data_10_percent.gz"):
    X, y = load_data(data_path)

    # Encode labels
    le = LabelEncoder()
    y_enc = le.fit_transform(y)

    # Scale features
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # Train / test split
    X_train, X_test, y_train, y_test = train_test_split(
        X_scaled, y_enc, test_size=0.2, random_state=42, stratify=y_enc
    )

    print("[Train] Training Random Forest classifier...")
    clf = RandomForestClassifier(
        n_estimators=200,
        max_depth=20,
        min_samples_leaf=5,
        class_weight="balanced",
        n_jobs=-1,
        random_state=42,
    )
    clf.fit(X_train, y_train)

    # Evaluate
    y_pred = clf.predict(X_test)
    print("\n[Train] Classification Report:")
    print(classification_report(y_test, y_pred, target_names=le.classes_))

    # Save artifacts
    out_dir = "classifier/model_artifacts"
    os.makedirs(out_dir, exist_ok=True)

    with open(f"{out_dir}/model.pkl",   "wb") as f:
        pickle.dump(clf, f)
    with open(f"{out_dir}/scaler.pkl",  "wb") as f:
        pickle.dump(scaler, f)
    with open(f"{out_dir}/encoder.pkl", "wb") as f:
        pickle.dump(le, f)

    print(f"\n[Train] ✅ Artifacts saved to {out_dir}/")
    return clf, scaler, le


if __name__ == "__main__":
    train()
