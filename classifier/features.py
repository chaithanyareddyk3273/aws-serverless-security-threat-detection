"""
Feature extraction from raw network log events.
Maps JSON log entries to the numeric feature vector the ML model expects.

Expected raw event format (JSON):
{
    "src_ip":           "192.168.1.100",
    "dst_ip":           "10.0.0.5",
    "src_port":         54321,
    "dst_port":         22,
    "protocol":         "TCP",
    "duration_ms":      120,
    "bytes_sent":       4096,
    "bytes_received":   512,
    "packets_sent":     8,
    "packets_received": 4,
    "flags":            "SYN",
    "failed_logins":    3,
    "logged_in":        0,
    "num_connections":  150,
    "same_srv_rate":    0.95,
    "diff_srv_rate":    0.05,
    "dst_host_count":   255,
    "timestamp":        "2024-01-15T10:30:00Z"
}
"""

import numpy as np

PROTOCOL_MAP = {"TCP": 0, "UDP": 1, "ICMP": 2, "OTHER": 3}
FLAG_MAP     = {"SYN": 0, "ACK": 1, "FIN": 2, "RST": 3, "PSH": 4, "SF": 5, "OTHER": 6}

# Feature names in the order the model expects them
FEATURE_NAMES = [
    "duration_ms",
    "protocol",
    "flag",
    "bytes_sent",
    "bytes_received",
    "packets_sent",
    "packets_received",
    "failed_logins",
    "logged_in",
    "num_connections",
    "same_srv_rate",
    "diff_srv_rate",
    "dst_host_count",
    "dst_port_privileged",   # 1 if dst_port < 1024
    "bytes_ratio",           # bytes_sent / (bytes_received + 1)
    "packet_ratio",          # packets_sent / (packets_received + 1)
]


def extract_features(event: dict) -> np.ndarray:
    """
    Convert a raw log event dict into a numeric feature vector.

    Returns:
        np.ndarray of shape (1, len(FEATURE_NAMES)) ready for model.predict()
    """
    protocol = PROTOCOL_MAP.get(str(event.get("protocol", "OTHER")).upper(), 3)
    flag     = FLAG_MAP.get(str(event.get("flags", "OTHER")).upper(), 6)

    bytes_sent     = float(event.get("bytes_sent",     0))
    bytes_received = float(event.get("bytes_received", 0))
    pkts_sent      = float(event.get("packets_sent",   0))
    pkts_recv      = float(event.get("packets_received", 0))
    dst_port       = int(event.get("dst_port", 0))

    features = [
        float(event.get("duration_ms",       0)),
        float(protocol),
        float(flag),
        bytes_sent,
        bytes_received,
        pkts_sent,
        pkts_recv,
        float(event.get("failed_logins",     0)),
        float(event.get("logged_in",         0)),
        float(event.get("num_connections",   0)),
        float(event.get("same_srv_rate",     0.0)),
        float(event.get("diff_srv_rate",     0.0)),
        float(event.get("dst_host_count",    0)),
        1.0 if dst_port < 1024 else 0.0,
        bytes_sent / (bytes_received + 1.0),
        pkts_sent  / (pkts_recv + 1.0),
    ]

    return np.array(features, dtype=np.float32).reshape(1, -1)


def validate_event(event: dict) -> tuple[bool, str]:
    """
    Basic validation before feature extraction.
    Returns (is_valid, error_message).
    """
    required = ["src_ip", "dst_ip", "protocol", "bytes_sent", "timestamp"]
    for field in required:
        if field not in event:
            return False, f"Missing required field: {field}"
    return True, ""
