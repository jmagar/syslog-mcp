"""
Search-focused Elasticsearch queries.

This module provides pure Elasticsearch query functions for general log searching,
time-range searches, and full-text search capabilities. No business logic - just data access.
"""

from datetime import datetime, timedelta
from typing import Any

from ...services.elasticsearch_client import ElasticsearchClient
from ...utils.logging import get_logger

logger = get_logger(__name__)


async def query_logs_by_timerange(
    es_client: ElasticsearchClient,
    start_time: str,
    end_time: str,
    device: str | None = None,
    query: str | None = None,
    limit: int = 100
) -> dict[str, Any]:
    """Query logs within a specific time range from Elasticsearch."""

    # Build base time range query
    base_query: dict[str, Any] = {
        "bool": {
            "must": [
                {
                    "range": {
                        "timestamp": {
                            "gte": start_time,
                            "lte": end_time,
                            "time_zone": "+00:00"
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

    # Add text search if specified
    if query:
        base_query["bool"]["must"].append({
            "multi_match": {
                "query": query,
                "fields": ["message", "program", "severity"],
                "type": "best_fields",
                "fuzziness": "AUTO"
            }
        })

    search_query = {
        "query": base_query,
        "size": limit,
        "sort": [{"timestamp": {"order": "desc"}}],
        "_source": ["timestamp", "device", "message", "program", "severity", "facility"],
        "aggs": {
            "device_breakdown": {
                "terms": {
                    "field": "device.keyword",
                    "size": 20
                }
            },
            "program_breakdown": {
                "terms": {
                    "field": "program.keyword",
                    "size": 20
                }
            },
            "level_breakdown": {
                "terms": {
                    "field": "severity.keyword",
                    "size": 10
                }
            },
            "activity_distribution": {
                "date_histogram": {
                    "field": "timestamp",
                    "fixed_interval": "1h",
                    "min_doc_count": 1
                }
            },
            "search_relevance": {
                "significant_text": {
                    "field": "message",
                    "size": 10
                }
            }
        }
    }

    logger.debug(f"Executing timerange query from {start_time} to {end_time}: {search_query}")
    response = await es_client.search_raw(
        query=search_query,
        index="syslog-ng",
        timeout="30s"
    )

    return response


async def query_full_text_search(
    es_client: ElasticsearchClient,
    search_query: str,
    device: str | None = None,
    hours: int = 24,
    limit: int = 50,
    search_type: str = "phrase"
) -> dict[str, Any]:
    """Query logs using full-text search from Elasticsearch."""

    # Input validation
    if not search_query or not search_query.strip():
        raise ValueError("Search query cannot be empty")

    if search_type not in ["phrase", "fuzzy", "wildcard", "regex"]:
        raise ValueError(f"Invalid search_type: {search_type}. Must be one of: phrase, fuzzy, wildcard, regex")

    # Simple, reliable time range calculation using EXACT pattern from correlation search
    end_time_dt = datetime.utcnow()
    start_time_dt = end_time_dt - timedelta(hours=hours)

    # Simplified search configuration using proven patterns from working correlation search
    search_config: dict[str, dict[str, Any]] = {
        "phrase": {
            "type": "phrase",
            "slop": 2
        },
        "fuzzy": {
            "fuzziness": "AUTO",
            "operator": "and"
        },
        "wildcard": {
            "operator": "and"
        },
        "regex": {
            "operator": "and"
        }
    }

    config: dict[str, Any] = search_config.get(search_type, search_config["phrase"])

    # Build base query using EXACT pattern from working correlation search
    base_query: dict[str, Any] = {
        "bool": {
            "must": [
                {
                    "range": {
                        "timestamp": {
                            "gte": start_time_dt.isoformat(),
                            "lte": end_time_dt.isoformat(),
                            "time_zone": "+00:00"
                        }
                    }
                }
            ],
            "filter": []
        }
    }

    # Add text search
    if search_type == "regex":
        base_query["bool"]["must"].append({
            "regexp": {
                "message": {
                    "value": search_query,
                    "flags": "ALL",
                    "case_insensitive": True
                }
            }
        })
    elif search_type == "wildcard":
        base_query["bool"]["must"].append({
            "wildcard": {
                "message.keyword": {
                    "value": f"*{search_query}*",
                    "case_insensitive": True
                }
            }
        })
    else:
        # Build multi_match query using exact pattern from working correlation search
        multi_match_query = {
            "query": search_query,
            "fields": ["message^2", "program", "severity"]  # Exact alignment with working correlation search
        }

        # Add parameters based on search type, keeping it simple
        if search_type == "phrase" and "slop" in config:
            multi_match_query["type"] = "phrase"
            multi_match_query["slop"] = config["slop"]
        elif search_type == "fuzzy":
            # Use basic fuzzy search with proven parameters
            if "fuzziness" in config:
                multi_match_query["fuzziness"] = config["fuzziness"]
            if "operator" in config:
                multi_match_query["operator"] = config["operator"]
        else:
            # Default pattern - use exact correlation search configuration
            multi_match_query["operator"] = "and"

        base_query["bool"]["must"].append({
            "multi_match": multi_match_query
        })

    # Add device filter if specified
    if device:
        base_query["bool"]["filter"].append({
            "term": {"device.keyword": device}
        })

    es_query = {
        "query": base_query,
        "size": limit,
        "sort": [
            {"_score": {"order": "desc"}},
            {"timestamp": {"order": "desc"}}
        ],
        "_source": ["timestamp", "device", "message", "program", "severity", "facility"],
        "highlight": {
            "fields": {
                "message": {
                    "fragment_size": 150,
                    "number_of_fragments": 3,
                    "pre_tags": ["<mark>"],
                    "post_tags": ["</mark>"]
                }
            }
        },
        "aggs": {
            "match_distribution": {
                "date_histogram": {
                    "field": "timestamp",
                    "fixed_interval": "1h",
                    "min_doc_count": 1
                }
            },
            "matching_devices": {
                "terms": {
                    "field": "device.keyword",
                    "size": 20
                }
            },
            "matching_programs": {
                "terms": {
                    "field": "program.keyword",
                    "size": 15
                }
            },
            "matching_levels": {
                "terms": {
                    "field": "severity.keyword",
                    "size": 10
                }
            },
            "related_terms": {
                "significant_text": {
                    "field": "message",
                    "size": 15,
                    "filter_duplicate_text": True
                }
            },
            "context_analysis": {
                "terms": {
                    "script": {
                        "lang": "painless",
                        "source": r"""
                            String msg = doc['message.keyword'].value.toLowerCase();
                            String prog = doc['program.keyword'].value;

                            if (msg.indexOf('error') != -1 || msg.indexOf('failed') != -1 || msg.indexOf('critical') != -1) {
                                return 'Error Context';
                            } else if (msg.indexOf('warning') != -1 || msg.indexOf('warn') != -1) {
                                return 'Warning Context';
                            } else if (msg.indexOf('auth') != -1 || msg.indexOf('login') != -1 || msg.indexOf('user') != -1) {
                                return 'Authentication Context';
                            } else if (msg.indexOf('network') != -1 || msg.indexOf('connection') != -1 || msg.indexOf('tcp') != -1) {
                                return 'Network Context';
                            } else if (msg.indexOf('service') != -1 || msg.indexOf('daemon') != -1 || msg.indexOf('start') != -1) {
                                return 'Service Context';
                            } else {
                                return 'General Context';
                            }
                        """
                    },
                    "size": 10
                }
            }
        }
    }

    logger.debug(f"Executing full text search query '{search_query}': {es_query}")

    try:
        response = await es_client.search_raw(
            query=es_query,
            index="syslog-ng",
            timeout="30s"
        )
        return response
    except Exception as e:
        logger.error(f"Full text search query failed: {e}")
        logger.error(f"Query that failed: {es_query}")
        raise


async def query_general_log_search(
    es_client: ElasticsearchClient,
    query: str | None = None,
    device: str | None = None,
    level: str | None = None,
    start_time: str | None = None,
    end_time: str | None = None,
    hours: int = 24,
    limit: int = 100,
    offset: int = 0,
    sort_field: str = "timestamp",
    sort_order: str = "desc"
) -> dict[str, Any]:
    """Query general log search with comprehensive filtering from Elasticsearch."""

    # DEBUG: Log what we're receiving to identify the issue
    logger.debug(f"query_general_log_search: query='{query}', level='{level}', device='{device}'")

    # Simple, reliable time range calculation using EXACT pattern from correlation search
    if not start_time and not end_time:
        end_time_dt = datetime.utcnow()
        start_time_dt = end_time_dt - timedelta(hours=hours)
        logger.debug(f"Using automatic time range: {start_time_dt} to {end_time_dt}")
    else:
        # Parse string times to datetime objects for consistency
        if isinstance(start_time, str):
            start_time_dt = datetime.fromisoformat(start_time.replace('Z', '+00:00'))
        if isinstance(end_time, str):
            end_time_dt = datetime.fromisoformat(end_time.replace('Z', '+00:00'))

    # Simple basic search - just find logs with the text
    must_clauses = []
    filter_clauses = []

    # Add time range
    filter_clauses.append({
        "range": {
            "timestamp": {
                "gte": start_time_dt.isoformat(),
                "lte": end_time_dt.isoformat()
            }
        }
    })

    # Add text search if provided
    if query:
        must_clauses.append({
            "multi_match": {
                "query": query,
                "fields": ["message", "program"]
            }
        })

    base_query: dict[str, Any] = {
        "bool": {
            "must": must_clauses,
            "filter": filter_clauses
        }
    }

    # Add device filter if specified (keeping this since it works in correlation)
    if device:
        base_query["bool"]["filter"].append({
            "term": {"device.keyword": device}
        })

    # SIMPLE search query matching correlation pattern exactly
    search_query = {
        "query": base_query,
        "size": limit,
        "sort": [{"timestamp": {"order": "desc"}}],
        "_source": ["timestamp", "device", "message", "program", "severity", "facility"]
    }

    logger.debug(f"Full query: {search_query}")
    logger.debug(f"Executing general search query: {search_query}")
    response = await es_client.search_raw(
        query=search_query,
        index="syslog-ng",
        timeout="30s"
    )
    logger.debug(f"Response hits: {response.get('hits', {}).get('total', {})}")

    return response


async def query_search_correlate(
    es_client: ElasticsearchClient,
    primary_query: str,
    correlation_fields: list[str],
    time_window: int = 60,
    device: str | None = None,
    hours: int = 24,
    limit: int = 100
) -> dict[str, Any]:
    """Query logs for correlation analysis from Elasticsearch."""

    # Input validation
    if not primary_query or not primary_query.strip():
        raise ValueError("Primary query cannot be empty")

    if not correlation_fields or len(correlation_fields) == 0:
        raise ValueError("At least one correlation field must be provided")

    # Validate correlation fields and map to actual index fields
    valid_fields = ["device", "program", "level", "severity", "facility"]
    field_mapping = {
        "device": "device",
        "level": "severity"
    }

    mapped_fields = []
    for field in correlation_fields:
        if field not in valid_fields:
            raise ValueError(f"Invalid correlation field: {field}. Must be one of: {valid_fields}")
        # Map common field names to actual index fields
        mapped_field = field_mapping.get(field, field)
        mapped_fields.append(mapped_field)

    # Use mapped fields for the rest of the function
    correlation_fields = mapped_fields

    # Calculate time range
    end_time = datetime.utcnow()
    start_time = end_time - timedelta(hours=hours)

    # Build base query for primary events
    base_query: dict[str, Any] = {
        "bool": {
            "must": [
                {
                    "range": {
                        "timestamp": {
                            "gte": start_time.isoformat(),
                            "lte": end_time.isoformat(),
                            "time_zone": "+00:00"
                        }
                    }
                },
                {
                    "multi_match": {
                        "query": primary_query,
                        "fields": ["message^2", "program", "severity"],
                        "type": "best_fields",
                        "operator": "and"
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

    # Build aggregations for correlation analysis
    correlation_aggs = {}
    for field in correlation_fields:
        field_key = field.replace(".", "_")
        correlation_aggs[f"correlation_by_{field_key}"] = {
            "terms": {
                "field": f"{field}.keyword" if not field.endswith(".keyword") else field,
                "size": 20
            },
            "aggs": {
                "timeline": {
                    "date_histogram": {
                        "field": "timestamp",
                        "fixed_interval": f"{time_window}s",
                        "min_doc_count": 1
                    }
                },
                "sample_events": {
                    "top_hits": {
                        "sort": [{"timestamp": {"order": "desc"}}],
                        "size": 3,
                        "_source": ["timestamp", "device", "message", "program", "severity"]
                    }
                }
            }
        }

    search_query = {
        "query": base_query,
        "size": limit,
        "sort": [{"timestamp": {"order": "desc"}}],
        "_source": ["timestamp", "device", "message", "program", "severity", "facility"],
        "aggs": {
            **correlation_aggs,
            "event_timeline": {
                "date_histogram": {
                    "field": "timestamp",
                    "fixed_interval": f"{time_window}s",
                    "min_doc_count": 1
                }
            },
            "device_program_correlation": {
                "terms": {
                    "field": "device.keyword",
                    "size": 20
                },
                "aggs": {
                    "programs": {
                        "terms": {
                            "field": "program.keyword",
                            "size": 10
                        }
                    }
                }
            }
        }
    }

    logger.debug(f"Correlation full query: {search_query}")
    logger.debug(f"Executing correlation search query: {search_query}")

    try:
        response = await es_client.search_raw(
            query=search_query,
            index="syslog-ng",
            timeout="30s"
        )
        logger.debug(f"Correlation response hits: {response.get('hits', {}).get('total', {})}")
        return response
    except Exception as e:
        logger.error(f"Correlation search query failed: {e}")
        logger.error(f"Query that failed: {search_query}")
        raise
