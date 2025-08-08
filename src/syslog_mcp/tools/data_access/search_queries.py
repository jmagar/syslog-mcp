"""
Search-focused Elasticsearch queries.

This module provides pure Elasticsearch query functions for general log searching,
time-range searches, and full-text search capabilities. No business logic - just data access.
"""

from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from ...services.elasticsearch_client import ElasticsearchClient
from ...exceptions import ElasticsearchConnectionError, ElasticsearchQueryError
from ...utils.logging import get_logger

logger = get_logger(__name__)


async def query_logs_by_timerange(
    es_client: ElasticsearchClient,
    start_time: str,
    end_time: str,
    device: Optional[str] = None,
    query: Optional[str] = None,
    limit: int = 100
) -> Dict[str, Any]:
    """Query logs within a specific time range from Elasticsearch."""
    
    # Build base time range query
    base_query = {
        "bool": {
            "must": [
                {
                    "range": {
                        "timestamp": {
                            "gte": start_time,
                            "lte": end_time
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
                "fields": ["message", "program", "level"],
                "type": "best_fields",
                "fuzziness": "AUTO"
            }
        })
    
    search_query = {
        "query": base_query,
        "size": limit,
        "sort": [{"timestamp": {"order": "desc"}}],
        "_source": ["timestamp", "device", "message", "program", "level", "facility"],
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
                    "field": "level.keyword",
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
    response = await es_client._client.search(
        index="syslog-ng",
        body=search_query,
        timeout="30s"
    )
    
    return response


async def query_full_text_search(
    es_client: ElasticsearchClient,
    search_query: str,
    device: Optional[str] = None,
    hours: int = 24,
    limit: int = 50,
    search_type: str = "phrase"
) -> Dict[str, Any]:
    """Query logs using full-text search from Elasticsearch."""
    
    # Calculate time range
    end_time = datetime.utcnow()
    start_time = end_time - timedelta(hours=hours)
    
    # Build search query based on type
    search_config = {
        "phrase": {
            "type": "phrase",
            "slop": 2
        },
        "fuzzy": {
            "type": "best_fields", 
            "fuzziness": "AUTO",
            "operator": "or"
        },
        "wildcard": {
            "type": "phrase_prefix"
        },
        "regex": {
            "type": "best_fields",
            "operator": "and"
        }
    }
    
    config = search_config.get(search_type, search_config["phrase"])
    
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
        multi_match_query = {
            "query": search_query,
            "fields": ["message^3", "program^2", "level", "facility"],
            "type": config["type"],
            "operator": config.get("operator", "or")
        }
        
        # Only add fuzziness if it's not None
        if config.get("fuzziness") is not None:
            multi_match_query["fuzziness"] = config["fuzziness"]
            
        # Only add slop if it's not None
        if config.get("slop") is not None:
            multi_match_query["slop"] = config["slop"]
            
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
        "_source": ["timestamp", "device", "message", "program", "level", "facility"],
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
                    "field": "level.keyword",
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
    response = await es_client._client.search(
        index="syslog-ng",
        body=es_query,
        timeout="30s"
    )
    
    return response


async def query_general_log_search(
    es_client: ElasticsearchClient,
    query: Optional[str] = None,
    device: Optional[str] = None,
    level: Optional[str] = None,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
    sort_field: str = "timestamp",
    sort_order: str = "desc"
) -> Dict[str, Any]:
    """Query general log search with comprehensive filtering from Elasticsearch."""
    
    # Build base query
    base_query = {
        "bool": {
            "must": [],
            "filter": []
        }
    }
    
    # Add time range if specified
    if start_time and end_time:
        base_query["bool"]["must"].append({
            "range": {
                "timestamp": {
                    "gte": start_time,
                    "lte": end_time
                }
            }
        })
    elif start_time:
        base_query["bool"]["must"].append({
            "range": {
                "timestamp": {
                    "gte": start_time
                }
            }
        })
    elif end_time:
        base_query["bool"]["must"].append({
            "range": {
                "timestamp": {
                    "lte": end_time
                }
            }
        })
    
    # Add text search if specified
    if query:
        base_query["bool"]["must"].append({
            "multi_match": {
                "query": query,
                "fields": ["message^2", "program", "level"],
                "type": "cross_fields",
                "operator": "and"
            }
        })
    
    # Add device filter if specified
    if device:
        # Support wildcards in device names
        if "*" in device or "?" in device:
            base_query["bool"]["filter"].append({
                "wildcard": {"device.keyword": device}
            })
        else:
            base_query["bool"]["filter"].append({
                "term": {"device.keyword": device}
            })
    
    # Add level filter if specified
    if level:
        # Support multiple levels separated by commas
        levels = [l.strip().upper() for l in level.split(",")]
        base_query["bool"]["filter"].append({
            "terms": {"level.keyword": levels}
        })
    
    # Build sort configuration
    sort_config = []
    if sort_field == "timestamp":
        sort_config.append({"timestamp": {"order": sort_order}})
    elif sort_field == "_score":
        sort_config.append({"_score": {"order": sort_order}})
        sort_config.append({"timestamp": {"order": "desc"}})  # Secondary sort
    else:
        sort_config.append({sort_field: {"order": sort_order}})
        sort_config.append({"timestamp": {"order": "desc"}})  # Secondary sort
    
    search_query = {
        "query": base_query,
        "size": limit,
        "from": offset,
        "sort": sort_config,
        "_source": ["timestamp", "device", "message", "program", "level", "facility"],
        "aggs": {
            "total_by_device": {
                "terms": {
                    "field": "device.keyword",
                    "size": 50
                }
            },
            "total_by_level": {
                "terms": {
                    "field": "level.keyword",
                    "size": 10
                }
            },
            "total_by_program": {
                "terms": {
                    "field": "program.keyword",
                    "size": 30
                }
            },
            "total_by_facility": {
                "terms": {
                    "field": "facility.keyword",
                    "size": 20
                }
            },
            "logs_over_time": {
                "date_histogram": {
                    "field": "timestamp",
                    "fixed_interval": "1h",
                    "min_doc_count": 1
                }
            }
        }
    }
    
    # Only include aggregations if we're not just doing pagination
    if offset == 0:
        search_query["aggs"]["sample_recent"] = {
            "top_hits": {
                "sort": [{"timestamp": {"order": "desc"}}],
                "size": 5,
                "_source": ["timestamp", "device", "message", "program", "level"]
            }
        }
    
    logger.debug(f"Executing general search query: {search_query}")
    response = await es_client._client.search(
        index="syslog-ng",
        body=search_query,
        timeout="30s"
    )
    
    return response


async def query_search_correlate(
    es_client: ElasticsearchClient,
    primary_query: str,
    correlation_fields: List[str],
    time_window: int = 60,
    device: Optional[str] = None,
    hours: int = 24,
    limit: int = 100
) -> Dict[str, Any]:
    """Query logs for correlation analysis from Elasticsearch."""
    
    # Calculate time range
    end_time = datetime.utcnow()
    start_time = end_time - timedelta(hours=hours)
    
    # Build base query for primary events
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
                    "multi_match": {
                        "query": primary_query,
                        "fields": ["message^2", "program", "level"],
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
                        "_source": ["timestamp", "device", "message", "program", "level"]
                    }
                }
            }
        }
    
    search_query = {
        "query": base_query,
        "size": limit,
        "sort": [{"timestamp": {"order": "desc"}}],
        "_source": ["timestamp", "device", "message", "program", "level", "facility"],
        "aggs": {
            **correlation_aggs,
            "event_timeline": {
                "date_histogram": {
                    "field": "timestamp",
                    "fixed_interval": f"{time_window}s",
                    "min_doc_count": 1
                }
            },
            "correlation_matrix": {
                "terms": {
                    "script": {
                        "source": """
                            String device = doc['device.keyword'].size() > 0 ? doc['device.keyword'].value : '';
                            String program = doc['program.keyword'].size() > 0 ? doc['program.keyword'].value : '';
                            String level = doc['level.keyword'].size() > 0 ? doc['level.keyword'].value : '';
                            return device + '|' + program + '|' + level;
                        """
                    },
                    "size": 30
                }
            }
        }
    }
    
    logger.debug(f"Executing correlation search query: {search_query}")
    response = await es_client._client.search(
        index="syslog-ng",
        body=search_query,
        timeout="30s"
    )
    
    return response