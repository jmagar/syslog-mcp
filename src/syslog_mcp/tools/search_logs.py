"""
Log search tool for querying Elasticsearch with comprehensive filtering and pagination.

This tool provides the primary interface for searching syslog data with support for
text search, device filtering, log level filtering, time range queries, and pagination.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional

from fastmcp import FastMCP
from pydantic import BaseModel, Field, field_validator

from ..models.log_entry import LogEntry, LogLevel
from ..models.query import LogSearchQuery, TimeRange, SearchFilter, SortOrder
from ..models.response import LogSearchResult, ResponseStatus, ExecutionMetrics
from ..services.elasticsearch_client import ElasticsearchClient
from ..utils.logging import get_logger, log_mcp_request, log_mcp_response
from ..exceptions import (
    ElasticsearchConnectionError, 
    ElasticsearchQueryError,
    ElasticsearchTimeoutError
)

logger = get_logger(__name__)


class SearchLogsParameters(BaseModel):
    """Parameters for the search_logs MCP tool."""
    
    query: Optional[str] = Field(
        None,
        description="Text search query to match against log messages"
    )
    
    device: Optional[str] = Field(
        None,
        description="Filter logs by device/hostname (supports wildcards)"
    )
    
    level: Optional[LogLevel] = Field(
        None,
        description="Filter logs by severity level"
    )
    
    start_time: Optional[datetime] = Field(
        None,
        description="Start of time range (ISO 8601 format)"
    )
    
    end_time: Optional[datetime] = Field(
        None,
        description="End of time range (ISO 8601 format)"
    )
    
    limit: int = Field(
        100,
        ge=1,
        le=1000,
        description="Maximum number of results to return"
    )
    
    offset: int = Field(
        0,
        ge=0,
        description="Number of results to skip for pagination"
    )
    
    sort_field: str = Field(
        "timestamp",
        description="Field to sort results by"
    )
    
    sort_order: SortOrder = Field(
        SortOrder.DESC,
        description="Sort order (ASC or DESC)"
    )
    
    @field_validator('end_time')
    @classmethod
    def validate_time_range(cls, v, info):
        """Validate that end_time is after start_time."""
        if info.data:
            start_time = info.data.get('start_time')
            if start_time and v and v <= start_time:
                raise ValueError("end_time must be after start_time")
        return v


def register_search_tools(mcp: FastMCP) -> None:
    """Register all search-related MCP tools."""
    
    @mcp.tool()
    async def search_logs(
        query: Optional[str] = None,
        device: Optional[str] = None,
        level: Optional[LogLevel] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 100,
        offset: int = 0,
        sort_field: str = "timestamp",
        sort_order: SortOrder = SortOrder.DESC
    ) -> Dict[str, Any]:
        """
        Search syslog entries with comprehensive filtering and pagination.
        
        This tool provides the primary interface for querying syslog data stored in
        Elasticsearch with support for text search, filtering, and time range queries.
        
        Args:
            query: Text search query to match against log messages
            device: Filter logs by device/hostname (supports wildcards)
            level: Filter logs by severity level (DEBUG, INFO, WARN, ERROR, CRITICAL)
            start_time: Start of time range (ISO 8601 format)
            end_time: End of time range (ISO 8601 format)
            limit: Maximum number of results to return (1-1000, default 100)
            offset: Number of results to skip for pagination (default 0)
            sort_field: Field to sort results by (default "timestamp")
            sort_order: Sort order - "ASC" or "DESC" (default "DESC")
            
        Returns:
            Dictionary containing:
            - status: Operation status (success/error/timeout)
            - total_hits: Total number of matching logs
            - logs: Array of matching log entries
            - offset: Current pagination offset
            - limit: Current page size
            - has_more: Boolean indicating if more results are available
            - execution_metrics: Query performance information
            
        Raises:
            ElasticsearchConnectionError: If cannot connect to Elasticsearch
            ElasticsearchQueryError: If query is malformed or invalid
            ElasticsearchTimeoutError: If query times out
        """
        # Log the incoming request
        request_args = {
            "query": query,
            "device": device, 
            "level": level.value if level else None,
            "start_time": start_time.isoformat() if start_time else None,
            "end_time": end_time.isoformat() if end_time else None,
            "limit": limit,
            "offset": offset,
            "sort_field": sort_field,
            "sort_order": sort_order.value
        }
        log_mcp_request("search_logs", request_args)
        
        try:
            # Validate parameters using Pydantic model
            params = SearchLogsParameters(
                query=query,
                device=device,
                level=level,
                start_time=start_time,
                end_time=end_time,
                limit=limit,
                offset=offset,
                sort_field=sort_field,
                sort_order=sort_order
            )
            
            # Build time range filter if provided
            time_range = None
            if params.start_time or params.end_time:
                time_range = TimeRange(
                    start=params.start_time,
                    end=params.end_time
                )
            
            # Build search filters
            filters = []
            if params.device:
                # Search both hostname and host fields since logs use different field names
                device_operator = "wildcard" if "*" in params.device or "?" in params.device else "eq"
                filters.append(SearchFilter(
                    field="hostname",  # Primary field used by most logs
                    value=params.device,
                    operator=device_operator
                ))
                
            if params.level:
                filters.append(SearchFilter(
                    field="level",
                    value=params.level.value,
                    operator="eq"
                ))
            
            # Create search query model
            search_query = LogSearchQuery(
                query_string=params.query,
                time_range=time_range,
                filters=filters,
                limit=params.limit,
                offset=params.offset,
                sort_field=params.sort_field,
                sort_order=params.sort_order
            )
            
            # Get Elasticsearch client
            es_client = ElasticsearchClient()
            
            try:
                # Connect to Elasticsearch
                await es_client.connect()
                
                # Execute the search
                result = await es_client.search_logs(search_query)
                
                # Log successful response
                response_data = {
                    "status": result.status.value,
                    "total_hits": result.total_hits,
                    "result_count": len(result.logs),
                    "took_ms": result.metrics.execution_time_ms if result.metrics else None
                }
                log_mcp_response("search_logs", True, response_data)
                
                # Return the search result as dictionary
                return result.model_dump(by_alias=True, exclude_none=True)
            finally:
                # Ensure proper cleanup
                await es_client.disconnect()
            
        except ElasticsearchConnectionError as e:
            error_msg = f"Failed to connect to Elasticsearch: {e.message}"
            log_mcp_response("search_logs", False, error=error_msg)
            
            # Return error response in expected format
            return {
                "status": "error",
                "error_type": "connection_error",
                "error_message": error_msg,
                "total_hits": 0,
                "logs": [],
                "has_more": False,
                "execution_metrics": {
                    "execution_time_ms": 0,
                    "query_time_ms": 0,
                    "documents_examined": 0,
                    "documents_returned": 0
                }
            }
            
        except ElasticsearchQueryError as e:
            error_msg = f"Invalid search query: {e.message}"
            log_mcp_response("search_logs", False, error=error_msg)
            
            return {
                "status": "error",
                "error_type": "query_error", 
                "error_message": error_msg,
                "total_hits": 0,
                "logs": [],
                "has_more": False,
                "execution_metrics": {
                    "execution_time_ms": 0,
                    "query_time_ms": 0,
                    "documents_examined": 0,
                    "documents_returned": 0
                }
            }
            
        except ElasticsearchTimeoutError as e:
            error_msg = f"Search query timed out: {e.message}"
            log_mcp_response("search_logs", False, error=error_msg)
            
            return {
                "status": "timeout",
                "error_type": "timeout_error",
                "error_message": error_msg,
                "total_hits": 0,
                "logs": [],
                "has_more": False,
                "execution_metrics": {
                    "execution_time_ms": e.context.get("timeout_ms", 30000) if e.context else 30000,
                    "query_time_ms": 0,
                    "documents_examined": 0,
                    "documents_returned": 0,
                    "timed_out": True
                }
            }
            
        except Exception as e:
            error_msg = f"Unexpected error during search: {str(e)}"
            logger.error("Unexpected error in search_logs", extra={
                "error": str(e),
                "error_type": type(e).__name__,
                "parameters": request_args
            }, exc_info=True)
            log_mcp_response("search_logs", False, error=error_msg)
            
            return {
                "status": "error",
                "error_type": "internal_error",
                "error_message": error_msg,
                "total_hits": 0,
                "logs": [],
                "has_more": False,
                "execution_metrics": {
                    "execution_time_ms": 0,
                    "query_time_ms": 0,
                    "documents_examined": 0,
                    "documents_returned": 0
                }
            }