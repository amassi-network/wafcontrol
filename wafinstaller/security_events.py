import os
import re
import socket
import syslog

WAFCONTROL_SYSLOG_SOCKET = os.environ.get(
    "WAFCONTROL_SYSLOG_SOCKET", "/run/wafcontrol/syslog.sock"
)


def _clean(value, maximum=500):
    text = re.sub(r"[\x00-\x1f\x7f]+", " ", str(value or ""))
    return re.sub(r"\s+", " ", text).strip()[:maximum]


def attack_priority(attack):
    if attack.status in {"Blocked", "Critical"} or attack.severity >= 3:
        return 1
    if attack.status == "High" or attack.severity == 2:
        return 2
    return 3


def attack_classification(attack):
    family = str(attack.rule_id)[:3]
    classifications = {
        "913": "Security Scanner Activity",
        "920": "HTTP Protocol Violation",
        "930": "Path Traversal or Local File Access",
        "931": "Remote File Inclusion",
        "932": "Remote Command Execution",
        "933": "PHP Injection",
        "934": "Generic Application Attack",
        "941": "Web Application Cross Site Scripting",
        "942": "Web Application SQL Injection",
        "949": "Inbound Anomaly Score Exceeded",
        "959": "Outbound Anomaly Score Exceeded",
        "980": "Web Application Correlation",
    }
    if family in classifications:
        return classifications[family]
    tags = {str(tag).lower() for tag in attack.rule_tags}
    message = attack.message.lower()
    if any("sqli" in tag for tag in tags) or "sql injection" in message:
        return "Web Application SQL Injection"
    if any("xss" in tag for tag in tags) or "cross-site scripting" in message:
        return "Web Application Cross Site Scripting"
    if attack.status == "Blocked":
        return "Attempted Web Application Attack"
    return "Potentially Bad Traffic"


def format_attack_syslog(attack):
    rule_id = attack.rule_id if str(attack.rule_id).isdigit() else "0"
    priority = attack_priority(attack)
    protocol = _clean(attack.protocol or "TCP", 8).upper()
    source_port = attack.source_port or 0
    destination_ip = attack.destination_ip or "-"
    destination_port = attack.destination_port or 0
    return (
        f"[1:{rule_id}:1] MODSEC {_clean(attack.message)} "
        f"[Classification: {attack_classification(attack)}] "
        f"[Priority: {priority}] "
        f"{{{protocol}}} {attack.ip}:{source_port} -> "
        f"{destination_ip}:{destination_port}"
    )


def _emit_to_dedicated_socket(message, syslog_priority):
    payload = (
        f"<{syslog.LOG_LOCAL5 | syslog_priority}>"
        f"wafcontrol[{os.getpid()}]: {message}"
    ).encode("utf-8", errors="replace")
    with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as transport:
        transport.connect(WAFCONTROL_SYSLOG_SOCKET)
        transport.sendall(payload)


def emit_attack_syslog(attack):
    priority = attack_priority(attack)
    syslog_priority = {
        1: syslog.LOG_ALERT,
        2: syslog.LOG_WARNING,
        3: syslog.LOG_NOTICE,
    }[priority]
    message = format_attack_syslog(attack)
    if os.path.exists(WAFCONTROL_SYSLOG_SOCKET):
        try:
            _emit_to_dedicated_socket(message, syslog_priority)
            return "dedicated"
        except OSError:
            pass
    syslog.openlog("wafcontrol", syslog.LOG_PID, syslog.LOG_LOCAL5)
    syslog.syslog(syslog_priority, message)
    return "system"
