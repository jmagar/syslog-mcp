"""
Device-focused Elasticsearch queries.

This module provides pure Elasticsearch query functions for device health analysis,
error analysis, and device activity patterns. No business logic - just data access.
"""

from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from ...services.elasticsearch_client import ElasticsearchClient
from ...exceptions import ElasticsearchConnectionError, ElasticsearchQueryError
from ...utils.logging import get_logger

logger = get_logger(__name__)


async def query_device_health_summary(
    es_client: ElasticsearchClient,
    device_name: str,
    hours: int = 24
) -> Dict[str, Any]:
    """Query comprehensive device health data from Elasticsearch."""
    
    # Calculate time range
    end_time = datetime.utcnow()
    start_time = end_time - timedelta(hours=hours)
    
    # Build comprehensive device query
    device_query = {
        "query": {
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
                        "term": {
                            "device.keyword": device_name
                        }
                    }
                ]
            }
        },
        "size": 50,
        "sort": [{"timestamp": {"order": "desc"}}],
        "_source": ["timestamp", "device", "message", "program", "level", "facility"],
        "aggs": {
            "severity_distribution": {
                "terms": {
                    "field": "level.keyword",
                    "size": 10
                }
            },
            "facility_distribution": {
                "terms": {
                    "field": "facility.keyword",
                    "size": 20
                }
            },
            "top_programs": {
                "terms": {
                    "field": "program.keyword",
                    "size": 20
                }
            },
            "recent_errors": {
                "filter": {
                    "terms": {"level.keyword": ["error", "critical", "alert", "emergency"]}
                },
                "aggs": {
                    "latest_errors": {
                        "top_hits": {
                            "sort": [{"timestamp": {"order": "desc"}}],
                            "size": 20,
                            "_source": ["timestamp", "message", "program", "level"]
                        }
                    }
                }
            },
            "recent_warnings": {
                "filter": {
                    "terms": {"level.keyword": ["warning", "warn"]}
                },
                "aggs": {
                    "latest_warnings": {
                        "top_hits": {
                            "sort": [{"timestamp": {"order": "desc"}}],
                            "size": 10,
                            "_source": ["timestamp", "message", "program", "level"]
                        }
                    }
                }
            },
            "activity_timeline": {
                "date_histogram": {
                    "field": "timestamp",
                    "fixed_interval": "1h",
                    "min_doc_count": 0,
                    "extended_bounds": {
                        "min": start_time.isoformat(),
                        "max": end_time.isoformat()
                    }
                }
            },
            "last_activity": {
                "top_hits": {
                    "sort": [{"timestamp": {"order": "desc"}}],
                    "size": 1,
                    "_source": ["timestamp"]
                }
            }
        }
    }
    
    logger.debug(f"Executing device health query for {device_name}: {device_query}")
    response = await es_client.search_raw(
        query=device_query,
        index="syslog-ng",
        timeout="30s"
    )
    
    return response


async def query_error_analysis(
    es_client: ElasticsearchClient,
    device: Optional[str] = None,
    hours: int = 24,
    severity: Optional[str] = None,
    top_errors: int = 15
) -> Dict[str, Any]:
    """Query error patterns and analysis data from Elasticsearch."""
    
    # Calculate time range
    end_time = datetime.utcnow()
    start_time = end_time - timedelta(hours=hours)
    
    # Build base query for errors
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
                }
            ],
            "filter": []
        }
    }
    
    # Add severity filter
    if severity:
        base_query["bool"]["must"].append({
            "term": {"level.keyword": severity.lower()}
        })
    else:
        # Default to error-level logs
        base_query["bool"]["must"].append({
            "terms": {"level.keyword": ["error", "critical", "alert", "emergency", "warning"]}
        })
    
    # Add device filter if specified
    if device:
        base_query["bool"]["filter"].append({
            "term": {"device.keyword": device}
        })
    
    search_query = {
        "query": base_query,
        "size": 0,  # Only want aggregations for analysis
        "aggs": {
            "error_patterns": {
                "terms": {
                    "script": {
                        "source": r"""
                            String msg = doc['message.keyword'].value.toLowerCase();
                            String prog = doc['program.keyword'].value;
                            
                            // Hardware issues
                            if (msg.contains('usb') || msg.contains('hardware') || msg.contains('device')) {
                                return 'Hardware Issues (' + prog + ')';
                            }
                            // Network issues
                            else if (msg.contains('network') || msg.contains('connection') || msg.contains('timeout')) {
                                return 'Network Issues (' + prog + ')';
                            }
                            // Authentication/Security
                            else if (msg.contains('auth') || msg.contains('permission') || msg.contains('denied')) {
                                return 'Authentication Issues (' + prog + ')';
                            }
                            // File system issues
                            else if (msg.contains('disk') || msg.contains('filesystem') || msg.contains('mount')) {
                                return 'Filesystem Issues (' + prog + ')';
                            }
                            // Service issues
                            else if (msg.contains('service') || msg.contains('daemon') || msg.contains('failed to start')) {
                                return 'Service Issues (' + prog + ')';
                            }
                            // Memory/CPU issues
                            else if (msg.contains('memory') || msg.contains('cpu') || msg.contains('resource')) {
                                return 'Resource Issues (' + prog + ')';
                            }
                            else {
                                return 'Other Issues (' + prog + ')';
                            }
                        """
                    },
                    "size": top_errors
                }
            },
            "affected_services": {
                "terms": {
                    "field": "program.keyword",
                    "size": 20
                }
            },
            "affected_devices": {
                "terms": {
                    "field": "device.keyword",
                    "size": 20
                }
            },
            "severity_breakdown": {
                "terms": {
                    "field": "level.keyword",
                    "size": 10
                }
            },
            "error_timeline": {
                "date_histogram": {
                    "field": "timestamp",
                    "fixed_interval": "1h",
                    "min_doc_count": 1
                }
            },
            "peak_error_periods": {
                "date_histogram": {
                    "field": "timestamp",
                    "fixed_interval": "1h"
                },
                "aggs": {
                    "error_bucket_sort": {
                        "bucket_sort": {
                            "sort": [{"_count": {"order": "desc"}}],
                            "size": 5
                        }
                    }
                }
            },
            "sample_errors": {
                "terms": {
                    "field": "program.keyword",
                    "size": 10
                },
                "aggs": {
                    "sample_messages": {
                        "top_hits": {
                            "sort": [{"timestamp": {"order": "desc"}}],
                            "size": 2,
                            "_source": ["timestamp", "device", "message", "level"]
                        }
                    }
                }
            }
        }
    }
    
    logger.debug(f"Executing error analysis query: {search_query}")
    response = await es_client.search_raw(
        query=search_query,
        index="syslog-ng",
        timeout="30s"
    )
    
    return response


async def query_device_activity_timeline(
    es_client: ElasticsearchClient,
    device: Optional[str] = None,
    hours: int = 24,
    interval: str = "1h"
) -> Dict[str, Any]:
    """Query device activity timeline data from Elasticsearch."""
    
    # Calculate time range
    end_time = datetime.utcnow()
    start_time = end_time - timedelta(hours=hours)
    
    # Build timeline query
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
        "size": 0,
        "aggs": {
            "activity_timeline": {
                "date_histogram": {
                    "field": "timestamp",
                    "fixed_interval": interval,
                    "min_doc_count": 0,
                    "extended_bounds": {
                        "min": start_time.isoformat(),
                        "max": end_time.isoformat()
                    }
                },
                "aggs": {
                    "severity_breakdown": {
                        "terms": {
                            "field": "level.keyword",
                            "size": 10
                        }
                    },
                    "top_programs": {
                        "terms": {
                            "field": "program.keyword",
                            "size": 5
                        }
                    }
                }
            },
            "overall_activity": {
                "terms": {
                    "field": "device.keyword",
                    "size": 50
                },
                "aggs": {
                    "last_activity": {
                        "top_hits": {
                            "sort": [{"timestamp": {"order": "desc"}}],
                            "size": 1,
                            "_source": ["timestamp"]
                        }
                    }
                }
            },
            "authentication_timeline": {
                "filter": {
                    "terms": {"facility.keyword": ["auth", "authpriv"]}
                },
                "aggs": {
                    "auth_over_time": {
                        "date_histogram": {
                            "field": "timestamp",
                            "fixed_interval": interval,
                            "min_doc_count": 0
                        },
                        "aggs": {
                            "success_vs_failure": {
                                "terms": {
                                    "script": {
                                        "source": r"""
                                            String msg = doc['message.keyword'].value.toLowerCase();
                                            if (msg.contains('failed') || msg.contains('invalid') || msg.contains('authentication failure')) {
                                                return 'Failed';
                                            } else if (msg.contains('accepted') || msg.contains('session opened')) {
                                                return 'Successful';
                                            } else {
                                                return 'Other';
                                            }
                                        """
                                    },
                                    "size": 5
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    
    logger.debug(f"Executing activity timeline query: {search_query}")
    response = await es_client.search_raw(
        query=search_query,
        index="syslog-ng",
        timeout="30s"
    )
    
    return response