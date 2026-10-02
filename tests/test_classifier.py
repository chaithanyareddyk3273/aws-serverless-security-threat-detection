"""
Unit tests for the threat classifier pipeline.
Run: pytest tests/test_classifier.py -v
"""
import sys
import os

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from classifier.features     import extract_features, validate_event
from classifier.threat_types import get_severity, get_remediation, SEVERITY


# ── Sample events ─────────────────────────────────────────────────────────────
NORMAL_EVENT = {
    "src_ip": "192.168.1.10", "dst_ip": "10.0.0.1",
    "src_port": 54321, "dst_port": 443, "protocol": "TCP",
    "duration_ms": 50, "bytes_sent": 1024, "bytes_received": 2048,
    "packets_sent": 5, "packets_received": 8, "flags": "ACK",
    "failed_logins": 0, "logged_in": 1, "num_connections": 10,
    "same_srv_rate": 0.9, "diff_srv_rate": 0.1, "dst_host_count": 20,
    "timestamp": "2024-01-15T10:00:00Z",
}

DOS_EVENT = {
    **NORMAL_EVENT,
    "bytes_sent": 99999999, "packets_sent": 50000,
    "num_connections": 9999, "same_srv_rate": 1.0,
    "flags": "SYN", "duration_ms": 0,
}

BRUTE_FORCE_EVENT = {
    **NORMAL_EVENT,
    "dst_port": 22, "failed_logins": 200,
    "logged_in": 0, "num_connections": 500,
}

MISSING_FIELD_EVENT = {
    "src_port": 80, "dst_port": 443,
}


# ── Feature extraction tests ──────────────────────────────────────────────────
class TestFeatureExtraction:

    def test_normal_event_shape(self):
        feat = extract_features(NORMAL_EVENT)
        assert feat.shape == (1, 16), f"Expected (1, 16), got {feat.shape}"

    def test_dos_event_high_bytes(self):
        feat = extract_features(DOS_EVENT)
        # bytes_sent is index 3 (features are float32, so compare at that precision)
        assert feat[0, 3] == np.float32(DOS_EVENT["bytes_sent"])

    def test_privileged_port_flag(self):
        feat = extract_features(NORMAL_EVENT)   # dst_port=443, privileged
        assert feat[0, 13] == 1.0

        unprivileged = {**NORMAL_EVENT, "dst_port": 8080}
        feat2 = extract_features(unprivileged)
        assert feat2[0, 13] == 0.0

    def test_bytes_ratio(self):
        feat = extract_features(NORMAL_EVENT)
        expected = 1024 / (2048 + 1.0)
        assert abs(feat[0, 14] - expected) < 1e-5

    def test_unknown_protocol_defaults(self):
        evt = {**NORMAL_EVENT, "protocol": "UNKNOWN_PROTO"}
        feat = extract_features(evt)
        assert feat[0, 1] == 3.0   # OTHER = 3


# ── Validation tests ──────────────────────────────────────────────────────────
class TestValidation:

    def test_valid_event_passes(self):
        ok, err = validate_event(NORMAL_EVENT)
        assert ok is True
        assert err == ""

    def test_missing_src_ip_fails(self):
        ok, err = validate_event(MISSING_FIELD_EVENT)
        assert ok is False
        assert "src_ip" in err

    def test_missing_timestamp_fails(self):
        evt = {**NORMAL_EVENT}
        del evt["timestamp"]
        ok, err = validate_event(evt)
        assert ok is False


# ── Threat taxonomy tests ─────────────────────────────────────────────────────
class TestThreatTypes:

    def test_severity_mapping(self):
        assert get_severity("dos")               == "Critical"
        assert get_severity("ddos")              == "Critical"
        assert get_severity("data_exfiltration") == "Critical"
        assert get_severity("brute_force")       == "High"
        assert get_severity("phishing")          == "High"
        assert get_severity("port_scan")         == "Medium"
        assert get_severity("normal")            == "Info"

    def test_unknown_threat_defaults_medium(self):
        assert get_severity("some_new_threat") == "Medium"

    def test_remediation_has_steps(self):
        for threat in ["dos", "ddos", "brute_force", "phishing", "data_exfiltration", "port_scan"]:
            playbook = get_remediation(threat)
            assert "steps" in playbook
            assert len(playbook["steps"]) >= 3, f"{threat} should have at least 3 steps"
            assert "title" in playbook
            assert "description" in playbook

    def test_all_severity_levels_covered(self):
        expected = {"Info", "Medium", "High", "Critical"}
        actual   = set(SEVERITY.values())
        assert expected == actual
