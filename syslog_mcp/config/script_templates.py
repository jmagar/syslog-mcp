"""
Script templates and categorization rules for Elasticsearch queries.

This module provides configuration-driven Elasticsearch script generation
to improve maintainability and allow for easier updates to categorization rules.
"""

from typing import Any

# Authentication failure categorization patterns
AUTH_FAILURE_PATTERNS: dict[str, dict[str, Any]] = {
    "password_brute_force": {
        "patterns": ["Failed password"],
        "category": "Password Brute Force"
    },
    "user_enumeration": {
        "patterns": ["Invalid user"],
        "category": "Username Enumeration"
    },
    "auth_failure": {
        "patterns": ["authentication failure"],
        "category": "Authentication Failure"
    },
    "other": {
        "patterns": [],
        "category": "Other"
    }
}

# Suspicious activity categorization patterns (NON-AUTH ONLY)
# Note: Authentication-related patterns moved to auth analysis to eliminate overlap
SUSPICIOUS_ACTIVITY_PATTERNS: dict[str, dict[str, Any]] = {
    "privilege_escalation": {
        "patterns": ["sudo", "command"],
        "category": "Privilege Escalation",
        "severity": "HIGH"
    },
    "network_downloads": {
        "patterns": ["wget", "curl"],
        "category": "Network Downloads",
        "severity": "MEDIUM"
    },
    "network_tools": {
        "patterns": ["nc ", "netcat"],
        "category": "Network Tools",
        "severity": "HIGH"
    },
    "file_manipulation": {
        "patterns": ["/tmp/", "chmod", "base64"],
        "category": "File Manipulation",
        "severity": "MEDIUM"
    },
    "system_anomalies": {
        "patterns": ["systemd", "kernel"],
        "category": "System Anomalies",
        "severity": "LOW",
        "program_based": True
    },
    "process_monitoring": {
        "patterns": ["ps ", "top", "htop", "netstat"],
        "category": "Process Monitoring",
        "severity": "MEDIUM"
    },
    "other": {
        "patterns": [],
        "category": "Other Suspicious Activity",
        "severity": "LOW"
    }
}

# Attack method categorization patterns
ATTACK_METHOD_PATTERNS: dict[str, dict[str, Any]] = {
    "brute_force": {
        "patterns": ["Failed password"],
        "category": "Brute Force"
    },
    "user_scanning": {
        "patterns": ["Invalid user"],
        "category": "User Scanning"
    },
    "connection_probing": {
        "patterns": ["connection"],
        "category": "Connection Probing"
    },
    "other": {
        "patterns": [],
        "category": "Other"
    }
}

# Geographic distribution mapping (simplified IP geolocation)
GEOGRAPHIC_MAPPING = {
    "north_america_europe": {
        "octet_range": (1, 126),
        "region": "North America/Europe"
    },
    "asia_pacific": {
        "octet_range": (128, 191),
        "region": "Asia/Pacific"
    },
    "other_regions": {
        "octet_range": (192, 255),
        "region": "Other Regions"
    }
}

# Private IP ranges to filter out
PRIVATE_IP_RANGES: list[str] = ["10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31."]


def generate_auth_failure_categorization_script() -> str:
    """Generate Elasticsearch script for categorizing authentication failures."""

    conditions: list[str] = []
    for _pattern_key, pattern_data in AUTH_FAILURE_PATTERNS.items():
        pattern_data = pattern_data  # Type hint for mypy
        if pattern_data["patterns"]:  # Skip 'other' category
            pattern_checks: list[str] = []
            for pattern in pattern_data["patterns"]:
                pattern_checks.append(f"msg.indexOf('{pattern}') != -1")

            condition = f"if ({' && '.join(pattern_checks)}) {{ return '{pattern_data['category']}'; }}"
            conditions.append(condition)

    # Add fallback
    conditions.append(f"return '{AUTH_FAILURE_PATTERNS['other']['category']}';")

    return f"""
        String msg = doc['message.keyword'].size() > 0 ? doc['message.keyword'].value : '';
        {' else '.join(conditions)}
    """


def generate_suspicious_activity_categorization_script() -> str:
    """Generate Elasticsearch script for categorizing suspicious activities."""

    conditions: list[str] = []
    for _pattern_key, pattern_data in SUSPICIOUS_ACTIVITY_PATTERNS.items():
        pattern_data = pattern_data  # Type hint for mypy
        if pattern_data["patterns"]:  # Skip 'other' category
            if pattern_data.get("program_based"):
                # Special handling for program-based patterns
                program_checks: list[str] = []
                for pattern in pattern_data["patterns"]:
                    program_checks.append(f"prog.equals('{pattern}')")
                condition = f"if ({' || '.join(program_checks)}) {{ return '{pattern_data['category']}'; }}"
            else:
                # Regular message-based patterns
                pattern_checks: list[str] = []
                for pattern in pattern_data["patterns"]:
                    pattern_checks.append(f"msg.indexOf('{pattern}') != -1")
                condition = f"if ({' || '.join(pattern_checks)}) {{ return '{pattern_data['category']}'; }}"

            conditions.append(condition)

    # Add fallback
    conditions.append(f"return '{SUSPICIOUS_ACTIVITY_PATTERNS['other']['category']}';")

    return f"""
        String msg = doc['message.keyword'].size() > 0 ? doc['message.keyword'].value.toLowerCase() : '';
        String prog = doc['program.keyword'].size() > 0 ? doc['program.keyword'].value : '';

        {' else '.join(conditions)}
    """


def generate_attack_method_categorization_script() -> str:
    """Generate Elasticsearch script for categorizing attack methods."""

    conditions: list[str] = []
    for _pattern_key, pattern_data in ATTACK_METHOD_PATTERNS.items():
        pattern_data = pattern_data  # Type hint for mypy
        if pattern_data["patterns"]:  # Skip 'other' category
            pattern_checks: list[str] = []
            for pattern in pattern_data["patterns"]:
                pattern_checks.append(f"msg.indexOf('{pattern}') != -1")

            condition = f"if ({' || '.join(pattern_checks)}) {{ return '{pattern_data['category']}'; }}"
            conditions.append(condition)

    # Add fallback
    conditions.append(f"return '{ATTACK_METHOD_PATTERNS['other']['category']}';")

    return f"""
        String msg = doc['message.keyword'].size() > 0 ? doc['message.keyword'].value : '';
        {' else '.join(conditions)}
    """


def generate_ip_extraction_script() -> str:
    """Generate Elasticsearch script for extracting IP addresses using regex."""

    return """
        String msg = doc['message.keyword'].size() > 0 ? doc['message.keyword'].value : '';
        def matcher = /\\b(?:[0-9]{1,3}\\.){3}[0-9]{1,3}\\b/.matcher(msg);
        if (matcher.find()) {
            return matcher.group();
        }
        return 'unknown';
    """




def generate_user_extraction_script() -> str:
    """Generate Elasticsearch script for extracting usernames from auth failure messages."""

    return """
        String msg = doc['message.keyword'].size() > 0 ? doc['message.keyword'].value : '';
        if (msg.indexOf('Failed password for ') != -1) {
            int userStart = msg.indexOf('Failed password for ') + 20;
            int userEnd = msg.indexOf(' from', userStart);
            if (userEnd > userStart) {
                return msg.substring(userStart, userEnd);
            }
        } else if (msg.indexOf('Invalid user ') != -1) {
            int userStart = msg.indexOf('Invalid user ') + 13;
            int userEnd = msg.indexOf(' from', userStart);
            if (userEnd > userStart) {
                return msg.substring(userStart, userEnd);
            }
        }
        return 'unknown';
    """


__all__ = [
    "AUTH_FAILURE_PATTERNS",
    "SUSPICIOUS_ACTIVITY_PATTERNS",
    "ATTACK_METHOD_PATTERNS",
    "GEOGRAPHIC_MAPPING",
    "PRIVATE_IP_RANGES",
    "generate_auth_failure_categorization_script",
    "generate_suspicious_activity_categorization_script",
    "generate_attack_method_categorization_script",
    "generate_ip_extraction_script",
    "generate_user_extraction_script"
]
