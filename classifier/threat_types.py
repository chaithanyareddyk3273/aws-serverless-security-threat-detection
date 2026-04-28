"""
Threat taxonomy, severity mapping, and human-readable remediation playbook.
Security analysts receive these steps in every alert — no prior technical
knowledge required to take initial action.
"""

# ── Threat label → severity ───────────────────────────────────────────────────
SEVERITY = {
    "normal":            "Info",
    "dos":               "Critical",
    "ddos":              "Critical",
    "port_scan":         "Medium",
    "brute_force":       "High",
    "phishing":          "High",
    "data_exfiltration": "Critical",
    "unknown":           "Medium",
}

# ── Severity → colour for CloudWatch / dashboard ─────────────────────────────
SEVERITY_COLOR = {
    "Info":     "#22c55e",
    "Medium":   "#f59e0b",
    "High":     "#ef4444",
    "Critical": "#7c3aed",
}

# ── Remediation playbook ──────────────────────────────────────────────────────
REMEDIATION = {
    "dos": {
        "title": "Denial of Service Attack Detected",
        "description": "High-volume traffic is flooding a resource, making it unavailable.",
        "steps": [
            "1. Immediately enable AWS Shield Advanced if not already active.",
            "2. Go to EC2 > Security Groups and block the source IP range.",
            "3. Enable rate limiting on your Application Load Balancer (ALB).",
            "4. Scale out the affected service if traffic is still growing.",
            "5. Notify the security team and open an incident ticket.",
            "6. Review CloudWatch metrics after 10 min to confirm traffic normalised.",
        ],
    },
    "ddos": {
        "title": "Distributed DoS (DDoS) Attack Detected",
        "description": "Multiple source IPs are co-ordinating to overwhelm your infrastructure.",
        "steps": [
            "1. Activate AWS Shield Advanced and enable DDoS response team (DRT) support.",
            "2. Enable AWS WAF on CloudFront / ALB with rate-based rules.",
            "3. Move traffic behind CloudFront to absorb the attack at the edge.",
            "4. Isolate the targeted EC2/Lambda function if impact is severe.",
            "5. Document source IPs, request time, and traffic pattern for post-incident review.",
        ],
    },
    "port_scan": {
        "title": "Port Scan Detected",
        "description": "A source is systematically probing your open ports — likely reconnaissance.",
        "steps": [
            "1. Identify the source IP in the alert and check it against threat intel (e.g. AbuseIPDB).",
            "2. Add the IP to your Security Group deny list.",
            "3. Review your Security Group rules — remove any open ports not in use.",
            "4. Enable VPC Flow Logs if not already active to capture further activity.",
            "5. Monitor for follow-up exploitation attempts over the next 24 hours.",
        ],
    },
    "brute_force": {
        "title": "Brute-Force Login Attack Detected",
        "description": "Repeated failed authentication attempts suggest a password-guessing attack.",
        "steps": [
            "1. Immediately lock the targeted account if possible.",
            "2. Enable MFA on the account and all admin accounts.",
            "3. Block the source IP in Security Groups / WAF.",
            "4. Check CloudTrail for any successful logins from this IP in the past 24 hours.",
            "5. Force password reset for the targeted user.",
            "6. Review IAM policies — ensure no overly-permissive roles are attached.",
        ],
    },
    "phishing": {
        "title": "Phishing Activity Detected",
        "description": "Suspicious DNS queries and payload patterns indicate a phishing attempt.",
        "steps": [
            "1. Block the suspicious domain in Route 53 Resolver DNS Firewall.",
            "2. Notify the user whose credentials may be targeted.",
            "3. Check SES / email logs for phishing emails sent from your domain.",
            "4. Scan the affected instance with Amazon Inspector.",
            "5. Reset credentials for any accounts that may have been exposed.",
        ],
    },
    "data_exfiltration": {
        "title": "Data Exfiltration Attempt Detected",
        "description": "Abnormally large outbound data transfer detected — potential data breach.",
        "steps": [
            "1. IMMEDIATELY isolate the source instance (remove from target group / stop EC2).",
            "2. Capture a memory dump and disk snapshot for forensics before stopping.",
            "3. Revoke all IAM credentials associated with the instance.",
            "4. Check S3 bucket access logs for unusual downloads.",
            "5. Notify your Data Protection Officer (DPO) — this may be a GDPR reportable event.",
            "6. Open a P1 incident and engage AWS Support.",
        ],
    },
    "unknown": {
        "title": "Anomalous Activity Detected",
        "description": "Unusual pattern detected that does not match known threat signatures.",
        "steps": [
            "1. Review VPC Flow Logs and CloudTrail for the source IP / resource.",
            "2. Determine if this is a known internal process or an external actor.",
            "3. If source is external, block the IP in Security Groups as a precaution.",
            "4. Escalate to the security team for manual investigation.",
        ],
    },
}


def get_remediation(threat_label):
    """Return the remediation playbook for a given threat label."""
    return REMEDIATION.get(threat_label.lower(), REMEDIATION["unknown"])


def get_severity(threat_label):
    return SEVERITY.get(threat_label.lower(), "Medium")
