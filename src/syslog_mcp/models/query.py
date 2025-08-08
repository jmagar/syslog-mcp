"""
Query and search models for MCP tool parameters and responses.

Provides structured models for search queries, filters, aggregations,
and search parameters used by the MCP server tools.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional, Any, Union
from ipaddress import IPv4Address, IPv6Address

from pydantic import BaseModel, Field, field_validator, computed_field
from pydantic.types import constr, confloat, conint

from .log_entry import LogLevel
from .device import DeviceType


class SortOrder(str, Enum):
    """Sort order for query results."""
    
    ASC = "asc"
    DESC = "desc"


class TimeRange(BaseModel):
    """
    Time range specification for log queries.
    """
    
    start: Optional[datetime] = Field(
        None,
        description="Start time for the range (inclusive)"
    )
    
    end: Optional[datetime] = Field(
        None,
        description="End time for the range (inclusive)"
    )
    
    last_hours: Optional[confloat(gt=0.0)] = Field(
        None,
        description="Query logs from the last N hours"
    )
    
    last_days: Optional[confloat(gt=0.0)] = Field(
        None,
        description="Query logs from the last N days"
    )
    
    @computed_field
    @property
    def effective_start(self) -> Optional[datetime]:
        """Calculate effective start time from relative time specs."""
        if self.start:
            return self.start
        
        now = datetime.now(timezone.utc)
        
        if self.last_hours:
            from datetime import timedelta
            return now - timedelta(hours=self.last_hours)
        
        if self.last_days:
            from datetime import timedelta
            return now - timedelta(days=self.last_days)
        
        return None
    
    @computed_field
    @property
    def effective_end(self) -> Optional[datetime]:
        """Calculate effective end time."""
        return self.end or datetime.now(timezone.utc)
    
    @field_validator('end')
    @classmethod
    def validate_time_range(cls, v: Optional[datetime], info) -> Optional[datetime]:
        """Validate that end time is after start time."""
        if v and hasattr(info, 'data') and info.data.get('start'):
            start = info.data['start']
            if v <= start:
                raise ValueError("End time must be after start time")
        return v


class SearchFilter(BaseModel):
    """
    Individual search filter for log queries.
    """
    
    field: constr(min_length=1) = Field(
        ...,
        description="Field name to filter on",
        examples=["device", "level", "message", "facility"]
    )
    
    operator: str = Field(
        "eq",
        description="Filter operator (eq, ne, in, contains, regex, range)",
        examples=["eq", "contains", "regex"]
    )
    
    value: Any = Field(
        ...,
        description="Filter value or values for the field",
        examples=["web-server", "ERROR", ["auth", "daemon"]]
    )
    
    case_sensitive: bool = Field(
        False,
        description="Whether string matching should be case sensitive"
    )
    
    @field_validator('operator')
    @classmethod
    def validate_operator(cls, v: str) -> str:
        """Validate filter operator."""
        valid_operators = {
            'eq', 'ne', 'in', 'not_in', 'contains', 'not_contains',
            'regex', 'range', 'exists', 'missing', 'prefix', 'wildcard'
        }
        
        if v not in valid_operators:
            raise ValueError(f"Invalid operator: {v}. Valid operators: {valid_operators}")
        
        return v


class AggregationRequest(BaseModel):
    """
    Aggregation specification for analytics queries.
    """
    
    name: constr(min_length=1) = Field(
        ...,
        description="Name for this aggregation"
    )
    
    type: str = Field(
        ...,
        description="Aggregation type (terms, date_histogram, stats, etc.)",
        examples=["terms", "date_histogram", "stats", "cardinality"]
    )
    
    field: constr(min_length=1) = Field(
        ...,
        description="Field to aggregate on"
    )
    
    size: conint(ge=1, le=10000) = Field(
        10,
        description="Maximum number of buckets/results"
    )
    
    interval: Optional[str] = Field(
        None,
        description="Interval for date/histogram aggregations",
        examples=["1h", "1d", "1w"]
    )
    
    min_doc_count: conint(ge=0) = Field(
        1,
        description="Minimum document count for buckets"
    )
    
    @field_validator('type')
    @classmethod
    def validate_aggregation_type(cls, v: str) -> str:
        """Validate aggregation type."""
        valid_types = {
            'terms', 'date_histogram', 'histogram', 'range', 'stats',
            'extended_stats', 'cardinality', 'percentiles', 'significant_terms'
        }
        
        if v not in valid_types:
            raise ValueError(f"Invalid aggregation type: {v}. Valid types: {valid_types}")
        
        return v


class LogSearchQuery(BaseModel):
    """
    Comprehensive log search query with filters, sorting, and pagination.
    """
    
    # Text search
    query_string: Optional[constr(max_length=1024)] = Field(
        None,
        description="Full-text search query string",
        examples=["authentication failed", "error AND database"]
    )
    
    # Time filtering
    time_range: Optional[TimeRange] = Field(
        None,
        description="Time range for the search"
    )
    
    # Field filters
    filters: List[SearchFilter] = Field(
        default_factory=list,
        description="List of field-based filters"
    )
    
    # Device filtering
    devices: Optional[List[str]] = Field(
        None,
        description="Filter by specific device names",
        max_length=100
    )
    
    levels: Optional[List[LogLevel]] = Field(
        None,
        description="Filter by log levels",
        examples=[["ERROR", "CRITICAL"]]
    )
    
    facilities: Optional[List[str]] = Field(
        None,
        description="Filter by syslog facilities",
        examples=[["auth", "daemon"]]
    )
    
    # Pagination and sorting
    limit: conint(ge=1, le=10000) = Field(
        100,
        description="Maximum number of results to return"
    )
    
    offset: conint(ge=0) = Field(
        0,
        description="Number of results to skip"
    )
    
    sort_field: str = Field(
        "timestamp",
        description="Field to sort results by"
    )
    
    sort_order: SortOrder = Field(
        SortOrder.DESC,
        description="Sort order for results"
    )
    
    # Aggregations
    aggregations: List[AggregationRequest] = Field(
        default_factory=list,
        description="List of aggregations to compute"
    )
    
    # Advanced options
    include_metadata: bool = Field(
        True,
        description="Whether to include metadata fields in results"
    )
    
    highlight: bool = Field(
        False,
        description="Whether to highlight matching terms in results"
    )
    
    scroll_id: Optional[str] = Field(
        None,
        description="Scroll ID for pagination of large result sets"
    )
    
    @field_validator('filters')
    @classmethod
    def validate_filters(cls, v: List[SearchFilter]) -> List[SearchFilter]:
        """Validate search filters."""
        if len(v) > 50:
            raise ValueError("Too many filters (maximum 50)")
        
        # Check for duplicate field filters
        field_counts = {}
        for filter_item in v:
            field_counts[filter_item.field] = field_counts.get(filter_item.field, 0) + 1
            if field_counts[filter_item.field] > 5:
                raise ValueError(f"Too many filters on field '{filter_item.field}' (maximum 5)")
        
        return v
    
    @computed_field
    @property
    def has_time_filter(self) -> bool:
        """Check if query has any time-based filtering."""
        return self.time_range is not None
    
    @computed_field
    @property
    def estimated_result_size(self) -> str:
        """Estimate result size category for resource planning."""
        if self.limit <= 100:
            return "small"
        elif self.limit <= 1000:
            return "medium"
        elif self.limit <= 5000:
            return "large"
        else:
            return "very_large"


class DeviceSearchQuery(BaseModel):
    """
    Search query for device information and statistics.
    """
    
    # Device filtering
    name_pattern: Optional[str] = Field(
        None,
        description="Pattern to match device names (supports wildcards)",
        examples=["web-*", "*-prod"]
    )
    
    device_types: Optional[List[DeviceType]] = Field(
        None,
        description="Filter by device types"
    )
    
    environments: Optional[List[str]] = Field(
        None,
        description="Filter by environments",
        examples=[["production", "staging"]]
    )
    
    locations: Optional[List[str]] = Field(
        None,
        description="Filter by device locations"
    )
    
    # Health filtering
    min_health_score: confloat(ge=0.0, le=1.0) = Field(
        0.0,
        description="Minimum health score threshold"
    )
    
    max_health_score: confloat(ge=0.0, le=1.0) = Field(
        1.0,
        description="Maximum health score threshold"
    )
    
    statuses: Optional[List[str]] = Field(
        None,
        description="Filter by device statuses",
        examples=[["healthy", "warning"]]
    )
    
    # Activity filtering
    active_within_hours: Optional[confloat(gt=0.0)] = Field(
        None,
        description="Include only devices active within N hours"
    )
    
    min_log_count: conint(ge=0) = Field(
        0,
        description="Minimum total log count"
    )
    
    # Tag filtering
    tags: Dict[str, str] = Field(
        default_factory=dict,
        description="Filter by device tags (key-value pairs)"
    )
    
    # Sorting and pagination
    limit: conint(ge=1, le=1000) = Field(
        50,
        description="Maximum number of devices to return"
    )
    
    offset: conint(ge=0) = Field(
        0,
        description="Number of devices to skip"
    )
    
    sort_by: str = Field(
        "health_score",
        description="Field to sort devices by",
        examples=["health_score", "name", "last_updated", "criticality"]
    )
    
    sort_order: SortOrder = Field(
        SortOrder.DESC,
        description="Sort order for devices"
    )
    
    # Statistics options
    include_statistics: bool = Field(
        True,
        description="Whether to include health statistics summary"
    )


class AggregationQuery(BaseModel):
    """
    Specialized query for analytics and aggregation operations.
    """
    
    # Base query to filter data before aggregation
    base_query: Optional[LogSearchQuery] = Field(
        None,
        description="Base query to filter logs before aggregation"
    )
    
    # Time-based aggregation settings
    time_interval: Optional[str] = Field(
        None,
        description="Time interval for time-based aggregations",
        examples=["1h", "1d", "1w", "1M"]
    )
    
    # Aggregation specifications
    aggregations: List[AggregationRequest] = Field(
        ...,
        min_length=1,
        max_length=10,
        description="List of aggregations to compute"
    )
    
    # Output options
    include_raw_data: bool = Field(
        False,
        description="Whether to include raw log data with aggregations"
    )
    
    format_results: bool = Field(
        True,
        description="Whether to format aggregation results for display"
    )


class SearchContext(BaseModel):
    """
    Context information for search operations and caching.
    """
    
    user_id: Optional[str] = Field(
        None,
        description="User identifier for personalized results"
    )
    
    session_id: Optional[str] = Field(
        None,
        description="Session identifier for result caching"
    )
    
    query_id: Optional[str] = Field(
        None,
        description="Unique query identifier for tracking"
    )
    
    cache_ttl: conint(ge=0, le=3600) = Field(
        300,
        description="Cache time-to-live in seconds"
    )
    
    priority: str = Field(
        "normal",
        description="Query priority level",
        examples=["low", "normal", "high", "urgent"]
    )
    
    explain: bool = Field(
        False,
        description="Whether to include query execution plan"
    )
    
    @field_validator('priority')
    @classmethod
    def validate_priority(cls, v: str) -> str:
        """Validate query priority."""
        valid_priorities = {"low", "normal", "high", "urgent"}
        if v not in valid_priorities:
            raise ValueError(f"Invalid priority: {v}. Valid priorities: {valid_priorities}")
        return v