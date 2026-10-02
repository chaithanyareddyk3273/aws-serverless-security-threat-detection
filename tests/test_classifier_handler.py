"""
Tests for the classifier Lambda's CloudWatch metrics and alerting.
AWS clients and the ML model are mocked, so no AWS account or trained model is needed.
Run: pytest tests/test_classifier_handler.py -v
"""
import importlib.util
import os
import sys
from unittest import mock

import pytest

ROOT = os.path.dirname(os.path.dirname(__file__))
sys.path.insert(0, ROOT)

from tests.test_classifier import NORMAL_EVENT  # noqa: E402


@pytest.fixture
def handler_module(monkeypatch):
    """Import lambda/classifier/handler.py with boto3 and the model mocked out."""
    monkeypatch.setenv("SNS_TOPIC_ARN", "arn:aws:sns:us-east-1:123456789012:alerts")
    fake_model = mock.MagicMock()
    with mock.patch("boto3.client"), mock.patch("classifier.model.ThreatClassifier", return_value=fake_model):
        spec = importlib.util.spec_from_file_location(
            "classifier_handler", os.path.join(ROOT, "lambda", "classifier", "handler.py")
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    module.cw = mock.MagicMock()
    module.sns = mock.MagicMock()
    return module


def _predict(module, threat, severity):
    module.classifier.predict.return_value = {
        "threat": threat, "severity": severity, "confidence": 0.9, "probabilities": {threat: 0.9},
    }


def _published_dimension_sets(module):
    metric_data = module.cw.put_metric_data.call_args.kwargs["MetricData"]
    return [{d["Name"]: d["Value"] for d in m["Dimensions"]} for m in metric_data]


def test_threat_publishes_all_dimension_sets_used_by_alarms(handler_module):
    _predict(handler_module, "ddos", "Critical")
    handler_module.handler({"raw_event": NORMAL_EVENT}, None)

    dims = _published_dimension_sets(handler_module)
    assert {"ThreatType": "ddos", "Severity": "Critical"} in dims  # dashboard widget
    assert {"Severity": "Critical"} in dims                        # critical_threat alarm
    assert {} in dims                                              # high_volume alarm + total widget


def test_critical_threat_sends_sns_alert(handler_module):
    _predict(handler_module, "ddos", "Critical")
    handler_module.handler({"raw_event": NORMAL_EVENT}, None)
    handler_module.sns.publish.assert_called_once()


def test_normal_traffic_publishes_no_threat_metric_or_alert(handler_module):
    _predict(handler_module, "normal", "Info")
    handler_module.handler({"raw_event": NORMAL_EVENT}, None)
    handler_module.cw.put_metric_data.assert_not_called()
    handler_module.sns.publish.assert_not_called()
