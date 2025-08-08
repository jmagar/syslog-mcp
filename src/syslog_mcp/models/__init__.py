"""
Data models for the Syslog MCP server.

This module contains Pydantic models for log entries, search queries, device information,
and API responses with validation.
"""

from .log_entry import LogEntry, LogLevel
from .device import DeviceInfo, DeviceStatus, DeviceType, DeviceList, LogActivitySummary
from .query import (
    TimeRange, SearchFilter, AggregationRequest, LogSearchQuery,
    DeviceSearchQuery, AggregationQuery, SearchContext, SortOrder
)
from .response import (
    ResponseStatus, ExecutionMetrics, HighlightMatch, AggregationBucket,
    AggregationResult, LogSearchResult, DeviceSearchResult, HealthCheckResult,
    ErrorDetail, ErrorResponse, OperationSummary
)
from .serialization import (
    SerializationConfig, ModelSerializer, ModelDeserializer,
    ValidationErrorReporter, DeserializationError,
    serialize_model, deserialize_model, validate_and_report_errors
)

__all__ = [
    # Log entry models
    "LogEntry",
    "LogLevel",
    # Device models
    "DeviceInfo",
    "DeviceStatus", 
    "DeviceType",
    "DeviceList",
    "LogActivitySummary",
    # Query models
    "TimeRange",
    "SearchFilter",
    "AggregationRequest",
    "LogSearchQuery",
    "DeviceSearchQuery",
    "AggregationQuery",
    "SearchContext",
    "SortOrder",
    # Response models
    "ResponseStatus",
    "ExecutionMetrics",
    "HighlightMatch",
    "AggregationBucket",
    "AggregationResult",
    "LogSearchResult",
    "DeviceSearchResult",
    "HealthCheckResult",
    "ErrorDetail",
    "ErrorResponse",
    "OperationSummary",
    # Serialization utilities
    "SerializationConfig",
    "ModelSerializer",
    "ModelDeserializer",
    "ValidationErrorReporter",
    "DeserializationError",
    "serialize_model",
    "deserialize_model",
    "validate_and_report_errors",
]
