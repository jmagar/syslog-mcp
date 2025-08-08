"""
Response models for MCP tool outputs and API responses.

Provides structured models for search results, aggregation outputs,
health information, and error responses from MCP server tools.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional, Any, Union

from pydantic import BaseModel, Field, computed_field
from pydantic.types import constr, confloat, conint

from .log_entry import LogEntry, LogLevel
from .device import DeviceInfo, DeviceStatus
from .query import AggregationRequest


class ResponseStatus(str, Enum):
    """Response status for MCP operations."""
    
    SUCCESS = "success"
    PARTIAL_SUCCESS = "partial_success" 
    ERROR = "error"
    TIMEOUT = "timeout"


class ExecutionMetrics(BaseModel):
    """
    Execution metrics for search and aggregation operations.
    """
    
    execution_time_ms: conint(ge=0) = Field(
        ...,
        description="Total execution time in milliseconds"
    )
    
    query_time_ms: conint(ge=0) = Field(
        ...,
        description="Time spent on query execution"
    )
    
    documents_examined: conint(ge=0) = Field(
        ...,
        description="Number of documents examined"
    )
    
    documents_returned: conint(ge=0) = Field(
        ...,
        description="Number of documents in results"
    )
    
    shards_total: conint(ge=0) = Field(
        1,
        description="Total number of shards queried"
    )
    
    shards_successful: conint(ge=0) = Field(
        1,
        description="Number of successful shard queries"
    )
    
    shards_failed: conint(ge=0) = Field(
        0,
        description="Number of failed shard queries"
    )
    
    timed_out: bool = Field(
        False,
        description="Whether the query timed out"
    )
    
    @computed_field
    @property
    def shard_success_rate(self) -> float:
        """Calculate shard success rate as percentage."""
        if self.shards_total == 0:
            return 100.0
        return (self.shards_successful / self.shards_total) * 100.0
    
    @computed_field
    @property
    def performance_category(self) -> str:
        """Categorize query performance."""
        if self.execution_time_ms < 100:
            return "fast"
        elif self.execution_time_ms < 1000:
            return "medium"
        elif self.execution_time_ms < 5000:
            return "slow"
        else:
            return "very_slow"


class HighlightMatch(BaseModel):
    """
    Text highlighting information for search results.
    """
    
    field: str = Field(
        ...,
        description="Field name containing the match"
    )
    
    fragments: List[str] = Field(
        ...,
        description="Text fragments with highlighted terms",
        max_length=10
    )
    
    score: confloat(ge=0.0) = Field(
        0.0,
        description="Relevance score for this highlight"
    )


class AggregationBucket(BaseModel):
    """
    Individual bucket result from aggregation operations.
    """
    
    key: Union[str, int, float] = Field(
        ...,
        description="Bucket key value"
    )
    
    doc_count: conint(ge=0) = Field(
        ...,
        description="Number of documents in this bucket"
    )
    
    key_as_string: Optional[str] = Field(
        None,
        description="String representation of key for display"
    )
    
    percentage: Optional[confloat(ge=0.0, le=100.0)] = Field(
        None,
        description="Percentage of total documents"
    )
    
    sub_aggregations: Dict[str, Any] = Field(
        default_factory=dict,
        description="Nested aggregation results"
    )


class AggregationResult(BaseModel):
    """
    Results from an aggregation operation.
    """
    
    name: str = Field(
        ...,
        description="Name of the aggregation"
    )
    
    type: str = Field(
        ...,
        description="Type of aggregation performed"
    )
    
    buckets: List[AggregationBucket] = Field(
        default_factory=list,
        description="Bucket results for bucketed aggregations"
    )
    
    value: Optional[Union[int, float, Dict[str, Any]]] = Field(
        None,
        description="Single value result for metric aggregations"
    )
    
    doc_count: conint(ge=0) = Field(
        0,
        description="Total document count for this aggregation"
    )
    
    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Additional aggregation metadata"
    )
    
    @computed_field
    @property
    def has_buckets(self) -> bool:
        """Check if aggregation has bucket results."""
        return len(self.buckets) > 0
    
    @computed_field
    @property
    def bucket_count(self) -> int:
        """Get number of buckets in result."""
        return len(self.buckets)


class LogSearchResult(BaseModel):
    """
    Results from log search operations with metadata and aggregations.
    """
    
    # Search metadata
    status: ResponseStatus = Field(
        ...,
        description="Overall status of the search operation"
    )
    
    total_hits: conint(ge=0) = Field(
        ...,
        description="Total number of matching documents"
    )
    
    max_score: Optional[confloat(ge=0.0)] = Field(
        None,
        description="Maximum relevance score in results"
    )
    
    # Results data
    logs: List[LogEntry] = Field(
        default_factory=list,
        description="List of log entries matching the query",
        max_length=10000
    )
    
    # Aggregation results
    aggregations: List[AggregationResult] = Field(
        default_factory=list,
        description="Aggregation results if requested"
    )
    
    # Highlighting
    highlights: Dict[str, List[HighlightMatch]] = Field(
        default_factory=dict,
        description="Text highlighting information keyed by document ID"
    )
    
    # Pagination
    offset: conint(ge=0) = Field(
        0,
        description="Starting offset for these results"
    )
    
    limit: conint(ge=1) = Field(
        100,
        description="Maximum results requested"
    )
    
    has_more: bool = Field(
        False,
        description="Whether more results are available"
    )
    
    next_offset: Optional[conint(ge=0)] = Field(
        None,
        description="Offset for next page of results"
    )
    
    scroll_id: Optional[str] = Field(
        None,
        description="Scroll ID for continued pagination"
    )
    
    # Performance and diagnostics
    metrics: ExecutionMetrics = Field(
        ...,
        description="Query execution metrics"
    )
    
    warnings: List[str] = Field(
        default_factory=list,
        description="Any warnings generated during search"
    )
    
    query_explanation: Optional[Dict[str, Any]] = Field(
        None,
        description="Query execution plan if explain was requested"
    )
    
    # Metadata
    generated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="When these results were generated"
    )
    
    @computed_field
    @property
    def result_count(self) -> int:
        """Get actual number of results returned."""
        return len(self.logs)
    
    @computed_field
    @property
    def has_aggregations(self) -> bool:
        """Check if results include aggregation data."""
        return len(self.aggregations) > 0
    
    @computed_field
    @property
    def has_highlights(self) -> bool:
        """Check if results include highlighting."""
        return len(self.highlights) > 0
    
    @computed_field
    @property
    def completion_percentage(self) -> float:
        """Calculate query completion percentage."""
        if self.total_hits == 0:
            return 100.0
        
        returned = self.offset + self.result_count
        return min((returned / self.total_hits) * 100.0, 100.0)


class DeviceSearchResult(BaseModel):
    """
    Results from device search operations.
    """
    
    status: ResponseStatus = Field(
        ...,
        description="Overall status of the search operation"
    )
    
    total_count: conint(ge=0) = Field(
        ...,
        description="Total number of devices matching criteria"
    )
    
    devices: List[DeviceInfo] = Field(
        default_factory=list,
        description="List of devices matching the query",
        max_length=1000
    )
    
    # Pagination
    offset: conint(ge=0) = Field(
        0,
        description="Starting offset for these results"
    )
    
    limit: conint(ge=1) = Field(
        50,
        description="Maximum results requested"
    )
    
    has_more: bool = Field(
        False,
        description="Whether more results are available"
    )
    
    # Statistics
    health_statistics: Optional[Dict[str, float]] = Field(
        None,
        description="Health score statistics across all matched devices"
    )
    
    status_summary: Optional[Dict[str, int]] = Field(
        None,
        description="Count of devices by status"
    )
    
    type_summary: Optional[Dict[str, int]] = Field(
        None,
        description="Count of devices by type"
    )
    
    # Performance
    metrics: ExecutionMetrics = Field(
        ...,
        description="Search execution metrics"
    )
    
    warnings: List[str] = Field(
        default_factory=list,
        description="Any warnings generated during search"
    )
    
    generated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="When these results were generated"
    )
    
    @computed_field
    @property
    def result_count(self) -> int:
        """Get actual number of devices returned."""
        return len(self.devices)
    
    @computed_field
    @property
    def average_health_score(self) -> float:
        """Calculate average health score of returned devices."""
        if not self.devices:
            return 0.0
        
        total = sum(device.health_score for device in self.devices)
        return total / len(self.devices)


class HealthCheckResult(BaseModel):
    """
    Results from health check operations.
    """
    
    status: ResponseStatus = Field(
        ...,
        description="Overall health status"
    )
    
    # Service health
    elasticsearch_status: str = Field(
        ...,
        description="Elasticsearch cluster health status",
        examples=["green", "yellow", "red"]
    )
    
    elasticsearch_nodes: conint(ge=0) = Field(
        ...,
        description="Number of active Elasticsearch nodes"
    )
    
    cluster_name: Optional[str] = Field(
        None,
        description="Elasticsearch cluster name"
    )
    
    # Index health
    total_indices: conint(ge=0) = Field(
        0,
        description="Total number of indices"
    )
    
    active_shards: conint(ge=0) = Field(
        0,
        description="Number of active shards"
    )
    
    relocating_shards: conint(ge=0) = Field(
        0,
        description="Number of relocating shards"
    )
    
    initializing_shards: conint(ge=0) = Field(
        0,
        description="Number of initializing shards"
    )
    
    unassigned_shards: conint(ge=0) = Field(
        0,
        description="Number of unassigned shards"
    )
    
    # Performance metrics
    response_time_ms: conint(ge=0) = Field(
        ...,
        description="Health check response time in milliseconds"
    )
    
    # Data statistics
    total_documents: conint(ge=0) = Field(
        0,
        description="Total number of documents across all indices"
    )
    
    total_size_bytes: conint(ge=0) = Field(
        0,
        description="Total size of all indices in bytes"
    )
    
    # Issues and warnings
    warnings: List[str] = Field(
        default_factory=list,
        description="Health warnings or issues detected"
    )
    
    recommendations: List[str] = Field(
        default_factory=list,
        description="Recommended actions based on health status"
    )
    
    # Metadata
    checked_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="When this health check was performed"
    )
    
    version_info: Dict[str, str] = Field(
        default_factory=dict,
        description="Version information for system components"
    )
    
    @computed_field
    @property
    def is_healthy(self) -> bool:
        """Determine if overall system is healthy."""
        return (
            self.status == ResponseStatus.SUCCESS and
            self.elasticsearch_status in ["green", "yellow"] and
            self.unassigned_shards == 0 and
            self.response_time_ms < 5000
        )
    
    @computed_field
    @property
    def shard_health_percentage(self) -> float:
        """Calculate percentage of healthy shards."""
        total_shards = (
            self.active_shards + self.relocating_shards + 
            self.initializing_shards + self.unassigned_shards
        )
        
        if total_shards == 0:
            return 100.0
        
        healthy_shards = self.active_shards
        return (healthy_shards / total_shards) * 100.0
    
    @computed_field
    @property
    def performance_category(self) -> str:
        """Categorize system performance."""
        if self.response_time_ms < 100:
            return "excellent"
        elif self.response_time_ms < 500:
            return "good"
        elif self.response_time_ms < 2000:
            return "fair"
        else:
            return "poor"


class ErrorDetail(BaseModel):
    """
    Detailed error information for failed operations.
    """
    
    code: str = Field(
        ...,
        description="Error code identifier"
    )
    
    message: str = Field(
        ...,
        description="Human-readable error message"
    )
    
    details: Optional[str] = Field(
        None,
        description="Additional error details or context"
    )
    
    field: Optional[str] = Field(
        None,
        description="Field name if error is field-specific"
    )
    
    suggestion: Optional[str] = Field(
        None,
        description="Suggested action to resolve the error"
    )


class ErrorResponse(BaseModel):
    """
    Structured error response for failed MCP operations.
    """
    
    status: ResponseStatus = Field(
        ResponseStatus.ERROR,
        description="Response status (always 'error')"
    )
    
    error_type: str = Field(
        ...,
        description="Category of error",
        examples=["validation", "connection", "timeout", "authentication"]
    )
    
    primary_error: ErrorDetail = Field(
        ...,
        description="Primary error information"
    )
    
    additional_errors: List[ErrorDetail] = Field(
        default_factory=list,
        description="Additional related errors"
    )
    
    # Context information
    operation: Optional[str] = Field(
        None,
        description="Operation that failed"
    )
    
    request_id: Optional[str] = Field(
        None,
        description="Unique request identifier for debugging"
    )
    
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="When the error occurred"
    )
    
    # Recovery information
    retry_after: Optional[conint(ge=0)] = Field(
        None,
        description="Seconds to wait before retrying"
    )
    
    recoverable: bool = Field(
        True,
        description="Whether this error might be recoverable"
    )
    
    @computed_field
    @property
    def error_count(self) -> int:
        """Get total number of errors."""
        return 1 + len(self.additional_errors)
    
    @computed_field
    @property
    def has_suggestions(self) -> bool:
        """Check if any errors have suggestions."""
        if self.primary_error.suggestion:
            return True
        
        return any(
            error.suggestion for error in self.additional_errors
        )


class OperationSummary(BaseModel):
    """
    Summary information for completed operations.
    """
    
    operation: str = Field(
        ...,
        description="Type of operation performed"
    )
    
    status: ResponseStatus = Field(
        ...,
        description="Overall operation status"
    )
    
    items_processed: conint(ge=0) = Field(
        0,
        description="Number of items processed"
    )
    
    items_successful: conint(ge=0) = Field(
        0,
        description="Number of items processed successfully"
    )
    
    items_failed: conint(ge=0) = Field(
        0,
        description="Number of items that failed processing"
    )
    
    execution_time_ms: conint(ge=0) = Field(
        ...,
        description="Total execution time in milliseconds"
    )
    
    warnings: List[str] = Field(
        default_factory=list,
        description="Warnings generated during operation"
    )
    
    completed_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="When the operation completed"
    )
    
    @computed_field
    @property
    def success_rate(self) -> float:
        """Calculate success rate as percentage."""
        if self.items_processed == 0:
            return 100.0
        
        return (self.items_successful / self.items_processed) * 100.0
    
    @computed_field
    @property
    def has_failures(self) -> bool:
        """Check if operation had any failures."""
        return self.items_failed > 0