"""
Security-focused Elasticsearch queries.

This module provides pure Elasticsearch query functions for security analysis,
including authentication failures, suspicious activities, and IP reputation analysis.
No business logic - just data access.
"""

from datetime import datetime, timedelta
from typing import Any

from ...config.script_templates import (
    generate_auth_failure_categorization_script,
    generate_ip_extraction_script,
    generate_user_extraction_script,
)
from ...services.elasticsearch_client import ElasticsearchClient
from ...utils.logging import get_logger

logger = get_logger(__name__)


async def query_failed_auth_attempts(
    es_client: ElasticsearchClient,
    device: str | None = None,
    hours: int = 24,
    top_ips: int = 10,
    limit: int = 1000
) -> dict[str, Any]:
    """Query failed authentication attempts from Elasticsearch."""

    # Calculate time range
    end_time = datetime.utcnow()
    start_time = end_time - timedelta(hours=hours)

    # Build base query
    base_query: dict[str, Any] = {
        "bool": {
            "must": [
                {
                    "range": {
                        "timestamp": {
                            "gte": start_time.isoformat(),
                            "lte": end_time.isoformat()
                        }
                    }
                },
                {
                    "bool": {
                        "should": [
                            {"match_phrase": {"message": "Failed password"}},
                            {"match_phrase": {"message": "Invalid user"}},
                            {"match_phrase": {"message": "authentication failure"}},
                            {"match_phrase": {"message": "failed login"}},
                            {"match_phrase": {"message": "login failed"}},
                            {"match_phrase": {"message": "pam_unix(sshd:auth): authentication failure"}},
                        ]
                    }
                }
            ],
            "filter": []
        }
    }

    # Add device filter if specified
    if device:
        base_query["bool"]["filter"].append({
            "term": {"device.keyword": device}
        })

    # Build comprehensive aggregation query
    search_query = {
        "query": base_query,
        "size": limit,
        "sort": [{"timestamp": {"order": "desc"}}],
        "_source": ["timestamp", "device", "message", "program", "severity"],
        "aggs": {
            "attacking_ips": {
                "terms": {
                    "script": {
                        "lang": "painless",
                        "source": generate_ip_extraction_script()
                    },
                    "size": top_ips
                }
            },
            "failed_users": {
                "terms": {
                    "script": {
                        "lang": "painless",
                        "source": generate_user_extraction_script()
                    },
                    "size": 30
                }
            },
            "targeted_devices": {
                "terms": {
                    "field": "device.keyword",
                    "size": 20
                }
            },
            "attack_methods": {
                "terms": {
                    "script": {
                        "lang": "painless",
                        "source": generate_auth_failure_categorization_script()
                    },
                    "size": 10
                }
            },
            "attack_timeline": {
                "date_histogram": {
                    "field": "timestamp",
                    "fixed_interval": "1h",
                    "min_doc_count": 0
                }
            }
        }
    }

    logger.debug(f"Executing failed auth query: {search_query}")
    response = await es_client.search_raw(
        query=search_query,
        index="syslog-ng",
        timeout="30s"
    )

    return response


async def query_suspicious_activity(
    es_client: ElasticsearchClient,
    device: str | None = None,
    hours: int = 24,
    sensitivity: str = "medium"
) -> dict[str, Any]:
    """Query suspicious activity patterns from Elasticsearch."""

    # Calculate time range
    end_time = datetime.utcnow()
    start_time = end_time - timedelta(hours=hours)

    # Sensitivity-based thresholds
    sensitivity_config = {
        "low": {"min_occurrences": 10, "time_window": "4h"},
        "medium": {"min_occurrences": 5, "time_window": "2h"},
        "high": {"min_occurrences": 2, "time_window": "1h"}
    }
    sensitivity_config.get(sensitivity, sensitivity_config["medium"])

    # Build suspicious activity query (NON-AUTH PATTERNS ONLY)
    base_query: dict[str, Any] = {
        "bool": {
            "must": [
                {
                    "range": {
                        "timestamp": {
                            "gte": start_time.isoformat(),
                            "lte": end_time.isoformat()
                        }
                    }
                },
                {
                    "bool": {
                        "should": [
                            # Privilege escalation (non-auth sudo commands)
                            {"bool": {"must": [
                                {"terms": {"program.keyword": ["sudo", "su"]}},
                                {"match": {"message": "COMMAND"}}
                            ]}},
                            # Network downloads
                            {"bool": {"should": [
                                {"match": {"message": "wget"}},
                                {"match": {"message": "curl"}}
                            ]}},
                            # Network tools usage
                            {"bool": {"should": [
                                {"match": {"message": "nc "}},
                                {"match": {"message": "netcat"}}
                            ]}},
                            # File manipulation
                            {"bool": {"should": [
                                {"match": {"message": "base64"}},
                                {"match": {"message": "/tmp/"}},
                                {"match": {"message": "chmod +x"}},
                                {"match": {"message": "chmod 777"}}
                            ]}},
                            # Process monitoring
                            {"bool": {"should": [
                                {"match": {"message": "ps "}},
                                {"match": {"message": "top"}},
                                {"match": {"message": "htop"}},
                                {"match": {"message": "netstat"}}
                            ]}},
                            # System anomalies (errors/critical)
                            {"bool": {"must": [
                                {"terms": {"severity.keyword": ["error", "critical"]}},
                                {"terms": {"program.keyword": ["systemd", "kernel"]}}
                            ]}}
                        ]
                    }
                }
            ],
            "filter": [
                # Explicitly exclude authentication-related messages to prevent overlap
                {
                    "bool": {
                        "must_not": [
                            {"match_phrase": {"message": "Failed password"}},
                            {"match_phrase": {"message": "Invalid user"}},
                            {"match_phrase": {"message": "Accepted password"}},
                            {"match_phrase": {"message": "Accepted publickey"}},
                            {"match_phrase": {"message": "authentication failure"}},
                            {"match_phrase": {"message": "session opened"}},
                            {"match_phrase": {"message": "session closed"}}
                        ]
                    }
                }
            ]
        }
    }

    # Add device filter if specified
    if device:
        base_query["bool"]["filter"].append({
            "term": {"device.keyword": device}
        })

    search_query = {
        "query": base_query,
        "size": 200,
        "sort": [{"timestamp": {"order": "desc"}}],
        "_source": ["timestamp", "device", "message", "program", "level"]
    }

    logger.debug(f"Executing suspicious activity query: {search_query}")
    response = await es_client.search_raw(
        query=search_query,
        index="syslog-ng",
        timeout="30s"
    )

    return response



async def query_authentication_timeline(
    es_client: ElasticsearchClient,
    device: str | None = None,
    hours: int = 24,
    interval: str = "1h"
) -> dict[str, Any]:
    """Query authentication timeline data from Elasticsearch."""

    # Build time range filter
    now = datetime.utcnow()
    start_time = now - timedelta(hours=hours)

    # Define precise authentication event patterns
    success_patterns = {
        "bool": {
            "should": [
                {"match_phrase": {"message": "Accepted password"}},
                {"match_phrase": {"message": "Accepted publickey"}},
                {"match_phrase": {"message": "session opened for user"}},
                {"match_phrase": {"message": "pam_unix(sshd:session): session opened"}},
                {"match_phrase": {"message": "New session"}},
                {"match_phrase": {"message": "User logged in"}},
                {"match_phrase": {"message": "Successful login"}},
                {"match_phrase": {"message": "authentication successful"}}
            ]
        }
    }

    failure_patterns = {
        "bool": {
            "should": [
                {"match_phrase": {"message": "Failed password"}},
                {"match_phrase": {"message": "Invalid user"}},
                {"match_phrase": {"message": "authentication failure"}},
                {"match_phrase": {"message": "failed login"}},
                {"match_phrase": {"message": "login failed"}},
                {"match_phrase": {"message": "pam_unix(sshd:auth): authentication failure"}},
                {"match_phrase": {"message": "Connection closed by authenticating user"}},
                {"match_phrase": {"message": "Disconnected from authenticating user"}}
            ]
        }
    }

    # Combine all authentication patterns
    auth_query = {
        "bool": {
            "must": [
                {
                    "range": {
                        "timestamp": {
                            "gte": start_time.isoformat(),
                            "lte": now.isoformat()
                        }
                    }
                },
                {
                    "bool": {
                        "should": [
                            success_patterns,
                            failure_patterns
                        ],
                        "minimum_should_match": 1
                    }
                }
            ]
        }
    }

    # Add device filter if specified
    if device:
        auth_query["bool"]["must"].append({
            "bool": {
                "should": [
                    {"term": {"hostname.keyword": device}},
                    {"term": {"host.keyword": device}},
                    {"term": {"hostname.keyword": device}}
                ]
            }
        })

    # Build aggregation with separate success/failure counts
    aggregation = {
        "auth_timeline": {
            "date_histogram": {
                "field": "timestamp",
                "fixed_interval": interval,
                "extended_bounds": {
                    "min": start_time.isoformat(),
                    "max": now.isoformat()
                },
                "min_doc_count": 0
            },
            "aggs": {
                "successful_auths": {
                    "filter": success_patterns
                },
                "failed_auths": {
                    "filter": failure_patterns
                }
            }
        }
    }

    # Execute search
    search_body = {
        "size": 0,
        "query": auth_query,
        "aggs": aggregation
    }

    try:
        response = await es_client.search_raw(
            query=search_body,
            index="syslog-ng",
            timeout="30s"
        )
        return response
    except Exception as e:
        logger.error(f"Authentication timeline query failed: {e}")
        return {"hits": {"total": {"value": 0}}, "aggregations": {}}


__all__ = [
    "query_failed_auth_attempts",
    "query_suspicious_activity",
    "query_authentication_timeline"
]
