"""
Data models for the Syslog MCP server.

This module contains Pydantic models for log entries, search queries, device information,
and API responses with validation.
"""

from .device import DeviceInfo, DeviceList, DeviceStatus, DeviceType, LogActivitySummary
from .log_entry import LogEntry, LogLevel
from .query import (
    AggregationQuery,
    AggregationRequest,
    DeviceSearchQuery,
    LogSearchQuery,
    SearchContext,
    SearchFilter,
    SortOrder,
    TimeRange,
)
from .response import (
    AggregationBucket,
    AggregationResult,
    DeviceSearchResult,
    ErrorDetail,
    ErrorResponse,
    ExecutionMetrics,
    HealthCheckResult,
    HighlightMatch,
    LogSearchResult,
    OperationSummary,
    ResponseStatus,
)
from .serialization import (
    DeserializationError,
    ModelDeserializer,
    ModelSerializer,
    SerializationConfig,
    ValidationErrorReporter,
    deserialize_model,
    serialize_model,
    validate_and_report_errors,
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
