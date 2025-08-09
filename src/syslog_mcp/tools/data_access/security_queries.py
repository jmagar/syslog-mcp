"""
Security-focused Elasticsearch queries.

This module provides pure Elasticsearch query functions for security analysis,
including authentication failures, suspicious activities, and IP reputation analysis.
No business logic - just data access.
"""

from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from ...services.elasticsearch_client import ElasticsearchClient
from ...exceptions import ElasticsearchConnectionError, ElasticsearchQueryError
from ...utils.logging import get_logger
from ...config.script_templates import (
    generate_ip_extraction_script,
    generate_public_ip_extraction_script,
    generate_geographic_distribution_script,
    generate_user_extraction_script,
    generate_auth_failure_categorization_script,
    generate_suspicious_activity_categorization_script,
    generate_attack_method_categorization_script
)

logger = get_logger(__name__)


async def query_failed_auth_attempts(
    es_client: ElasticsearchClient,
    device: Optional[str] = None,
    hours: int = 24,
    top_ips: int = 10,
    limit: int = 1000
) -> Dict[str, Any]:
    """Query failed authentication attempts from Elasticsearch."""
    
    # Calculate time range
    end_time = datetime.utcnow()
    start_time = end_time - timedelta(hours=hours)
    
    # Build base query
    base_query = {
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
        "_source": ["timestamp", "device", "message", "program", "level"],
        "aggs": {
            "attacking_ips": {
                "terms": {
                    "script": {
                        "source": generate_ip_extraction_script()
                    },
                    "size": top_ips
                }
            },
            "failed_users": {
                "terms": {
                    "script": {
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
    device: Optional[str] = None,
    hours: int = 24,
    sensitivity: str = "medium"
) -> Dict[str, Any]:
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
    config = sensitivity_config.get(sensitivity, sensitivity_config["medium"])
    
    # Build suspicious activity query
    base_query = {
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
                            # Off-hours activity  
                            {"bool": {"must": [
                                {"terms": {"program.keyword": ["sudo", "su", "ssh", "sshd"]}}
                            ]}},
                            # Privilege escalation
                            {"bool": {"must": [
                                {"terms": {"program.keyword": ["sudo", "su"]}},
                                {"match": {"message": "COMMAND"}}
                            ]}},
                            # Unusual command patterns
                            {"bool": {"should": [
                                {"match": {"message": "wget"}},
                                {"match": {"message": "curl"}},
                                {"match": {"message": "nc "}},
                                {"match": {"message": "netcat"}},
                                {"match": {"message": "base64"}},
                                {"match": {"message": "/tmp/"}},
                                {"match": {"message": "chmod +x"}}
                            ]}},
                            # Service anomalies
                            {"bool": {"must": [
                                {"terms": {"level.keyword": ["error", "critical"]}},
                                {"terms": {"program.keyword": ["systemd", "kernel"]}}
                            ]}}
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
    
    search_query = {
        "query": base_query,
        "size": 200,
        "sort": [{"timestamp": {"order": "desc"}}],
        "_source": ["timestamp", "device", "message", "program", "level"],
        "aggs": {
            "suspicious_patterns": {
                "terms": {
                    "script": {
                        "source": generate_suspicious_activity_categorization_script()
                    },
                    "size": 10
                }
            },
            "off_hours_activity": {
                "filter": {
                    "script": {
                        "source": "doc['timestamp'].value.getHour() >= 0 && doc['timestamp'].value.getHour() <= 6"
                    }
                },
                "aggs": {
                    "by_hour": {
                        "date_histogram": {
                            "field": "timestamp",
                            "fixed_interval": "1h"
                        }
                    }
                }
            },
            "devices_with_activity": {
                "terms": {
                    "field": "device.keyword",
                    "size": 20
                }
            },
            "timeline": {
                "date_histogram": {
                    "field": "timestamp",
                    "fixed_interval": config["time_window"],
                    "min_doc_count": 1
                }
            }
        }
    }
    
    logger.debug(f"Executing suspicious activity query: {search_query}")
    response = await es_client.search_raw(
        query=search_query,
        index="syslog-ng",
        timeout="30s"
    )
    
    return response


async def query_ip_reputation_data(
    es_client: ElasticsearchClient,
    ip_address: Optional[str] = None,
    hours: int = 24,
    min_attempts: int = 5,
    top_ips: int = 20
) -> Dict[str, Any]:
    """Query IP reputation and activity data from Elasticsearch."""
    
    # Calculate time range
    end_time = datetime.utcnow()
    start_time = end_time - timedelta(hours=hours)
    
    # Build base query - focus on network-related logs
    base_query = {
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
                            {"match_phrase": {"message": "connection"}},
                            {"match_phrase": {"message": "from"}},
                            {"terms": {"program.keyword": ["sshd", "nginx", "apache", "fail2ban"]}}
                        ]
                    }
                }
            ],
            "filter": []
        }
    }
    
    # If specific IP provided, filter for it
    if ip_address:
        base_query["bool"]["filter"].append({
            "wildcard": {"message": f"*{ip_address}*"}
        })
    
    search_query = {
        "query": base_query,
        "size": 0,  # We only want aggregations
        "aggs": {
            "ip_analysis": {
                "terms": {
                    "script": {
                        "source": generate_public_ip_extraction_script()
                    },
                    "size": top_ips,
                    "min_doc_count": min_attempts
                },
                "aggs": {
                    "attack_patterns": {
                        "terms": {
                            "script": {
                                "source": generate_attack_method_categorization_script()
                            },
                            "size": 10
                        }
                    },
                    "targeted_services": {
                        "terms": {
                            "field": "program.keyword",
                            "size": 10
                        }
                    },
                    "activity_timeline": {
                        "date_histogram": {
                            "field": "timestamp",
                            "fixed_interval": "1h",
                            "min_doc_count": 1
                        }
                    },
                    "sample_logs": {
                        "top_hits": {
                            "sort": [{"timestamp": {"order": "desc"}}],
                            "size": 5,
                            "_source": ["timestamp", "device", "message", "program"]
                        }
                    }
                }
            },
            "geographic_distribution": {
                "terms": {
                    "script": {
                        "source": generate_geographic_distribution_script()
                    },
                    "size": 10
                }
            }
        }
    }
    
    logger.debug(f"Executing IP reputation query: {search_query}")
    response = await es_client.search_raw(
        query=search_query,
        index="syslog-ng",
        timeout="30s"
    )
    
    return response


async def query_authentication_timeline(
    es_client: ElasticsearchClient,
    device: Optional[str] = None,
    hours: int = 24,
    interval: str = "1h"
) -> Dict[str, Any]:
    """Query authentication timeline data from Elasticsearch."""
    
    # Build time range filter
    now = datetime.utcnow()
    start_time = now - timedelta(hours=hours)
    
    # Base query for authentication events
    query = {
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
                            {"wildcard": {"message": "*authentication*"}},
                            {"wildcard": {"message": "*login*"}},
                            {"wildcard": {"message": "*auth*"}},
                            {"wildcard": {"message": "*ssh*"}},
                            {"term": {"program": "sshd"}},
                            {"term": {"program": "login"}},
                            {"term": {"program": "su"}}
                        ],
                        "minimum_should_match": 1
                    }
                }
            ]
        }
    }
    
    # Add device filter if specified
    if device:
        query["bool"]["must"].append({
            "bool": {
                "should": [
                    {"term": {"hostname": device}},
                    {"term": {"host": device}},
                    {"term": {"device": device}}
                ]
            }
        })
    
    # Build aggregation for timeline
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
                "auth_status": {
                    "terms": {
                        "field": "level.keyword",
                        "size": 10
                    }
                }
            }
        }
    }
    
    # Execute search
    search_body = {
        "size": 0,
        "query": query,
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
    "query_ip_reputation_data",
    "query_authentication_timeline"
]