"""
Tests for response models used by MCP tools.
"""

import pytest
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List

from pydantic import ValidationError

from syslog_mcp.models.response import (
    ResponseStatus, ExecutionMetrics, HighlightMatch, AggregationBucket,
    AggregationResult, LogSearchResult, DeviceSearchResult, HealthCheckResult,
    ErrorDetail, ErrorResponse, OperationSummary
)
from syslog_mcp.models.log_entry import LogEntry, LogLevel
from syslog_mcp.models.device import DeviceInfo, DeviceStatus


class TestResponseStatus:
    """Test ResponseStatus enum."""
    
    def test_response_status_values(self):
        """Test response status enum values."""
        assert ResponseStatus.SUCCESS == "success"
        assert ResponseStatus.PARTIAL_SUCCESS == "partial_success"
        assert ResponseStatus.ERROR == "error"
        assert ResponseStatus.TIMEOUT == "timeout"


class TestExecutionMetrics:
    """Test ExecutionMetrics model for performance tracking."""
    
    def test_basic_metrics(self):
        """Test basic execution metrics."""
        metrics = ExecutionMetrics(
            execution_time_ms=150,
            query_time_ms=120,
            documents_examined=1000,
            documents_returned=50,
            shards_total=3,
            shards_successful=3,
            shards_failed=0
        )
        
        assert metrics.execution_time_ms == 150
        assert metrics.query_time_ms == 120
        assert metrics.documents_examined == 1000
        assert metrics.documents_returned == 50
        assert metrics.shard_success_rate == 100.0
        assert metrics.performance_category == "medium"
    
    def test_performance_categories(self):
        """Test performance categorization."""
        fast_metrics = ExecutionMetrics(
            execution_time_ms=50,
            query_time_ms=40,
            documents_examined=100,
            documents_returned=10
        )
        
        slow_metrics = ExecutionMetrics(
            execution_time_ms=3000,
            query_time_ms=2800,
            documents_examined=50000,
            documents_returned=100
        )
        
        very_slow_metrics = ExecutionMetrics(
            execution_time_ms=8000,
            query_time_ms=7500,
            documents_examined=100000,
            documents_returned=1000
        )
        
        assert fast_metrics.performance_category == "fast"
        assert slow_metrics.performance_category == "slow"
        assert very_slow_metrics.performance_category == "very_slow"
    
    def test_shard_failure_rate(self):
        """Test shard failure rate calculation."""
        failed_metrics = ExecutionMetrics(
            execution_time_ms=500,
            query_time_ms=400,
            documents_examined=1000,
            documents_returned=800,
            shards_total=5,
            shards_successful=3,
            shards_failed=2
        )
        
        assert failed_metrics.shard_success_rate == 60.0
    
    def test_timeout_metrics(self):
        """Test timeout indication."""
        timeout_metrics = ExecutionMetrics(
            execution_time_ms=10000,
            query_time_ms=9800,
            documents_examined=50000,
            documents_returned=0,
            timed_out=True
        )
        
        assert timeout_metrics.timed_out is True
        assert timeout_metrics.performance_category == "very_slow"


class TestHighlightMatch:
    """Test HighlightMatch model for search highlighting."""
    
    def test_basic_highlight(self):
        """Test basic highlight match."""
        highlight = HighlightMatch(
            field="message",
            fragments=["User <em>authentication</em> failed", "Login <em>failed</em>"],
            score=1.2
        )
        
        assert highlight.field == "message"
        assert len(highlight.fragments) == 2
        assert highlight.score == 1.2
    
    def test_highlight_limits(self):
        """Test highlight fragment limits."""
        # Too many fragments
        many_fragments = [f"Fragment {i}" for i in range(11)]
        
        with pytest.raises(ValidationError):
            HighlightMatch(
                field="message",
                fragments=many_fragments,
                score=1.0
            )


class TestAggregationBucket:
    """Test AggregationBucket model for aggregation results."""
    
    def test_string_key_bucket(self):
        """Test bucket with string key."""
        bucket = AggregationBucket(
            key="web-server",
            doc_count=150,
            percentage=25.5
        )
        
        assert bucket.key == "web-server"
        assert bucket.doc_count == 150
        assert bucket.percentage == 25.5
    
    def test_numeric_key_bucket(self):
        """Test bucket with numeric key."""
        bucket = AggregationBucket(
            key=404,
            doc_count=50,
            key_as_string="404 - Not Found"
        )
        
        assert bucket.key == 404
        assert bucket.key_as_string == "404 - Not Found"
    
    def test_nested_aggregations(self):
        """Test bucket with sub-aggregations."""
        bucket = AggregationBucket(
            key="ERROR",
            doc_count=100,
            sub_aggregations={
                "by_device": {
                    "buckets": [
                        {"key": "server-1", "doc_count": 60},
                        {"key": "server-2", "doc_count": 40}
                    ]
                }
            }
        )
        
        assert len(bucket.sub_aggregations) == 1
        assert "by_device" in bucket.sub_aggregations


class TestAggregationResult:
    """Test AggregationResult model for aggregation outputs."""
    
    def test_bucket_aggregation(self):
        """Test aggregation with buckets."""
        buckets = [
            AggregationBucket(key="ERROR", doc_count=50),
            AggregationBucket(key="WARN", doc_count=30),
            AggregationBucket(key="INFO", doc_count=20)
        ]
        
        result = AggregationResult(
            name="by_level",
            type="terms",
            buckets=buckets,
            doc_count=100
        )
        
        assert result.name == "by_level"
        assert result.type == "terms"
        assert result.bucket_count == 3
        assert result.has_buckets is True
        assert result.doc_count == 100
    
    def test_metric_aggregation(self):
        """Test metric aggregation with single value."""
        result = AggregationResult(
            name="avg_health_score",
            type="avg",
            value=0.75,
            doc_count=200
        )
        
        assert result.name == "avg_health_score"
        assert result.type == "avg"
        assert result.value == 0.75
        assert result.has_buckets is False
        assert result.bucket_count == 0
    
    def test_stats_aggregation(self):
        """Test stats aggregation with complex value."""
        stats_value = {
            "count": 100,
            "min": 0.1,
            "max": 1.0,
            "avg": 0.75,
            "sum": 75.0
        }
        
        result = AggregationResult(
            name="health_stats",
            type="stats",
            value=stats_value,
            metadata={"field": "health_score"}
        )
        
        assert result.type == "stats"
        assert isinstance(result.value, dict)
        assert result.value["avg"] == 0.75
        assert result.metadata["field"] == "health_score"


class TestLogSearchResult:
    """Test LogSearchResult model for search responses."""
    
    def create_sample_logs(self, count: int) -> List[LogEntry]:
        """Create sample log entries for testing."""
        logs = []
        for i in range(count):
            log = LogEntry(
                timestamp=datetime.now(timezone.utc) - timedelta(hours=i),
                device=f"server-{i:02d}",
                level=LogLevel.INFO,
                message=f"Test message {i}"
            )
            logs.append(log)
        return logs
    
    def test_successful_search_result(self):
        """Test successful search result."""
        metrics = ExecutionMetrics(
            execution_time_ms=200,
            query_time_ms=180,
            documents_examined=1000,
            documents_returned=50
        )
        
        logs = self.create_sample_logs(50)
        
        result = LogSearchResult(
            status=ResponseStatus.SUCCESS,
            total_hits=150,
            max_score=2.5,
            logs=logs,
            metrics=metrics,
            offset=0,
            limit=50,
            has_more=True,
            next_offset=50
        )
        
        assert result.status == ResponseStatus.SUCCESS
        assert result.total_hits == 150
        assert result.result_count == 50
        assert result.has_more is True
        assert abs(result.completion_percentage - 33.333333333333336) < 0.001  # (0+50)/150 * 100
    
    def test_search_with_aggregations(self):
        """Test search result with aggregations."""
        metrics = ExecutionMetrics(
            execution_time_ms=300,
            query_time_ms=250,
            documents_examined=2000,
            documents_returned=100
        )
        
        aggregations = [
            AggregationResult(
                name="by_device",
                type="terms",
                buckets=[
                    AggregationBucket(key="server-01", doc_count=60),
                    AggregationBucket(key="server-02", doc_count=40)
                ]
            )
        ]
        
        result = LogSearchResult(
            status=ResponseStatus.SUCCESS,
            total_hits=100,
            logs=self.create_sample_logs(100),
            aggregations=aggregations,
            metrics=metrics
        )
        
        assert result.has_aggregations is True
        assert len(result.aggregations) == 1
        assert result.aggregations[0].bucket_count == 2
    
    def test_search_with_highlights(self):
        """Test search result with highlighting."""
        metrics = ExecutionMetrics(
            execution_time_ms=150,
            query_time_ms=130,
            documents_examined=500,
            documents_returned=25
        )
        
        highlights = {
            "doc_1": [
                HighlightMatch(
                    field="message",
                    fragments=["User <em>authentication</em> failed"],
                    score=1.5
                )
            ]
        }
        
        result = LogSearchResult(
            status=ResponseStatus.SUCCESS,
            total_hits=25,
            logs=self.create_sample_logs(25),
            highlights=highlights,
            metrics=metrics
        )
        
        assert result.has_highlights is True
        assert "doc_1" in result.highlights
        assert len(result.highlights["doc_1"]) == 1
    
    def test_search_with_warnings(self):
        """Test search result with warnings."""
        metrics = ExecutionMetrics(
            execution_time_ms=5000,
            query_time_ms=4800,
            documents_examined=100000,
            documents_returned=1000,
            shards_total=5,
            shards_successful=4,
            shards_failed=1
        )
        
        result = LogSearchResult(
            status=ResponseStatus.PARTIAL_SUCCESS,
            total_hits=1000,
            logs=self.create_sample_logs(1000),
            metrics=metrics,
            warnings=["Query took longer than expected", "One shard failed"]
        )
        
        assert result.status == ResponseStatus.PARTIAL_SUCCESS
        assert len(result.warnings) == 2
        assert metrics.shard_success_rate == 80.0
    
    def test_pagination_calculations(self):
        """Test pagination and completion calculations."""
        metrics = ExecutionMetrics(
            execution_time_ms=100,
            query_time_ms=90,
            documents_examined=200,
            documents_returned=50
        )
        
        # Second page of results
        result = LogSearchResult(
            status=ResponseStatus.SUCCESS,
            total_hits=200,
            logs=self.create_sample_logs(50),
            metrics=metrics,
            offset=50,
            limit=50,
            has_more=True,
            next_offset=100
        )
        
        # Completion: (50 offset + 50 results) / 200 total = 50%
        assert result.completion_percentage == 50.0
        assert result.result_count == 50
    
    def test_scroll_search(self):
        """Test scroll-based search result."""
        metrics = ExecutionMetrics(
            execution_time_ms=1000,
            query_time_ms=950,
            documents_examined=10000,
            documents_returned=1000
        )
        
        result = LogSearchResult(
            status=ResponseStatus.SUCCESS,
            total_hits=50000,
            logs=self.create_sample_logs(1000),
            metrics=metrics,
            scroll_id="scroll_12345",
            limit=1000
        )
        
        assert result.scroll_id == "scroll_12345"
        assert result.completion_percentage == 2.0  # 1000/50000 * 100


class TestDeviceSearchResult:
    """Test DeviceSearchResult model for device search responses."""
    
    def create_sample_devices(self, count: int) -> List[DeviceInfo]:
        """Create sample devices for testing."""
        devices = []
        for i in range(count):
            device = DeviceInfo(name=f"device-{i:02d}")
            devices.append(device)
        return devices
    
    def test_basic_device_search(self):
        """Test basic device search result."""
        metrics = ExecutionMetrics(
            execution_time_ms=50,
            query_time_ms=40,
            documents_examined=100,
            documents_returned=20
        )
        
        devices = self.create_sample_devices(20)
        
        result = DeviceSearchResult(
            status=ResponseStatus.SUCCESS,
            total_count=50,
            devices=devices,
            metrics=metrics,
            offset=0,
            limit=20,
            has_more=True
        )
        
        assert result.status == ResponseStatus.SUCCESS
        assert result.total_count == 50
        assert result.result_count == 20
        assert result.has_more is True
        assert result.average_health_score >= 0.0
    
    def test_device_search_with_statistics(self):
        """Test device search with health statistics."""
        metrics = ExecutionMetrics(
            execution_time_ms=75,
            query_time_ms=65,
            documents_examined=200,
            documents_returned=30
        )
        
        result = DeviceSearchResult(
            status=ResponseStatus.SUCCESS,
            total_count=30,
            devices=self.create_sample_devices(30),
            metrics=metrics,
            health_statistics={
                "min": 0.2,
                "max": 1.0,
                "mean": 0.75,
                "median": 0.8
            },
            status_summary={
                "healthy": 20,
                "warning": 8,
                "critical": 2
            },
            type_summary={
                "server": 15,
                "workstation": 10,
                "unknown": 5
            }
        )
        
        assert result.health_statistics["mean"] == 0.75
        assert result.status_summary["healthy"] == 20
        assert result.type_summary["server"] == 15
    
    def test_empty_device_search(self):
        """Test empty device search result."""
        metrics = ExecutionMetrics(
            execution_time_ms=25,
            query_time_ms=20,
            documents_examined=0,
            documents_returned=0
        )
        
        result = DeviceSearchResult(
            status=ResponseStatus.SUCCESS,
            total_count=0,
            devices=[],
            metrics=metrics
        )
        
        assert result.result_count == 0
        assert result.average_health_score == 0.0
        assert result.has_more is False


class TestHealthCheckResult:
    """Test HealthCheckResult model for system health."""
    
    def test_healthy_system(self):
        """Test healthy system status."""
        health = HealthCheckResult(
            status=ResponseStatus.SUCCESS,
            elasticsearch_status="green",
            elasticsearch_nodes=3,
            cluster_name="production",
            total_indices=50,
            active_shards=150,
            relocating_shards=0,
            initializing_shards=0,
            unassigned_shards=0,
            response_time_ms=150,
            total_documents=1000000,
            total_size_bytes=5368709120  # 5GB
        )
        
        assert health.is_healthy is True
        assert health.shard_health_percentage == 100.0
        assert health.performance_category == "good"
    
    def test_degraded_system(self):
        """Test degraded system with issues."""
        health = HealthCheckResult(
            status=ResponseStatus.PARTIAL_SUCCESS,
            elasticsearch_status="yellow",
            elasticsearch_nodes=2,  # Node failure
            total_indices=50,
            active_shards=120,
            relocating_shards=10,
            initializing_shards=5,
            unassigned_shards=15,  # Some shards unassigned
            response_time_ms=3000,  # Slow response
            warnings=[
                "One Elasticsearch node is down",
                "15 shards are unassigned"
            ],
            recommendations=[
                "Check failed node status",
                "Consider adding more nodes"
            ]
        )
        
        assert health.is_healthy is False  # Has unassigned shards
        assert health.shard_health_percentage == 80.0  # 120/(120+10+5+15) * 100
        assert health.performance_category == "poor"
        assert len(health.warnings) == 2
        assert len(health.recommendations) == 2
    
    def test_critical_system(self):
        """Test critical system status."""
        health = HealthCheckResult(
            status=ResponseStatus.ERROR,
            elasticsearch_status="red",
            elasticsearch_nodes=1,
            active_shards=50,
            unassigned_shards=100,
            response_time_ms=10000,
            warnings=["Cluster is in red state", "Many shards unavailable"],
            recommendations=["Immediate attention required"]
        )
        
        assert health.is_healthy is False
        assert abs(health.shard_health_percentage - 33.333333333333336) < 0.001  # 50/150
        assert health.performance_category == "poor"
    
    def test_performance_categories(self):
        """Test different performance categories."""
        excellent = HealthCheckResult(
            status=ResponseStatus.SUCCESS,
            elasticsearch_status="green",
            elasticsearch_nodes=3,
            response_time_ms=50
        )
        
        fair = HealthCheckResult(
            status=ResponseStatus.SUCCESS,
            elasticsearch_status="green", 
            elasticsearch_nodes=3,
            response_time_ms=1500
        )
        
        assert excellent.performance_category == "excellent"
        assert fair.performance_category == "fair"


class TestErrorResponse:
    """Test ErrorResponse model for error handling."""
    
    def test_basic_error(self):
        """Test basic error response."""
        primary_error = ErrorDetail(
            code="VALIDATION_ERROR",
            message="Invalid query parameter",
            field="timestamp",
            suggestion="Use ISO 8601 format for timestamps"
        )
        
        error_response = ErrorResponse(
            error_type="validation",
            primary_error=primary_error,
            operation="search_logs",
            recoverable=True
        )
        
        assert error_response.status == ResponseStatus.ERROR
        assert error_response.error_type == "validation"
        assert error_response.error_count == 1
        assert error_response.has_suggestions is True
        assert error_response.recoverable is True
    
    def test_multiple_errors(self):
        """Test error response with multiple errors."""
        primary_error = ErrorDetail(
            code="CONNECTION_ERROR",
            message="Failed to connect to Elasticsearch"
        )
        
        additional_errors = [
            ErrorDetail(
                code="TIMEOUT_ERROR",
                message="Query timed out after 30 seconds"
            ),
            ErrorDetail(
                code="AUTHENTICATION_ERROR",
                message="Invalid credentials provided",
                suggestion="Check API key configuration"
            )
        ]
        
        error_response = ErrorResponse(
            error_type="connection",
            primary_error=primary_error,
            additional_errors=additional_errors,
            retry_after=60,
            recoverable=False
        )
        
        assert error_response.error_count == 3
        assert error_response.has_suggestions is True
        assert error_response.retry_after == 60
        assert error_response.recoverable is False
    
    def test_error_without_suggestions(self):
        """Test error response without suggestions."""
        primary_error = ErrorDetail(
            code="INTERNAL_ERROR",
            message="An unexpected error occurred"
        )
        
        error_response = ErrorResponse(
            error_type="internal",
            primary_error=primary_error
        )
        
        assert error_response.has_suggestions is False


class TestOperationSummary:
    """Test OperationSummary model for operation results."""
    
    def test_successful_operation(self):
        """Test completely successful operation."""
        summary = OperationSummary(
            operation="bulk_index",
            status=ResponseStatus.SUCCESS,
            items_processed=1000,
            items_successful=1000,
            items_failed=0,
            execution_time_ms=5000
        )
        
        assert summary.success_rate == 100.0
        assert summary.has_failures is False
        assert summary.status == ResponseStatus.SUCCESS
    
    def test_partially_successful_operation(self):
        """Test partially successful operation."""
        summary = OperationSummary(
            operation="device_update",
            status=ResponseStatus.PARTIAL_SUCCESS,
            items_processed=100,
            items_successful=85,
            items_failed=15,
            execution_time_ms=2000,
            warnings=["Some devices were offline", "Timeout on 3 devices"]
        )
        
        assert summary.success_rate == 85.0
        assert summary.has_failures is True
        assert len(summary.warnings) == 2
    
    def test_empty_operation(self):
        """Test operation with no items."""
        summary = OperationSummary(
            operation="maintenance",
            status=ResponseStatus.SUCCESS,
            execution_time_ms=100
        )
        
        assert summary.success_rate == 100.0  # No items = 100% success
        assert summary.has_failures is False


class TestResponseModelIntegration:
    """Test integration between different response models."""
    
    def test_search_result_with_all_components(self):
        """Test complete search result with all features."""
        # Create execution metrics
        metrics = ExecutionMetrics(
            execution_time_ms=500,
            query_time_ms=450,
            documents_examined=5000,
            documents_returned=100,
            shards_total=3,
            shards_successful=3
        )
        
        # Create sample logs
        logs = [
            LogEntry(
                timestamp=datetime.now(timezone.utc),
                device="web-server-01",
                level=LogLevel.ERROR,
                message="Database connection failed"
            )
        ]
        
        # Create aggregation results
        aggregations = [
            AggregationResult(
                name="by_level",
                type="terms",
                buckets=[
                    AggregationBucket(key="ERROR", doc_count=60),
                    AggregationBucket(key="WARN", doc_count=40)
                ]
            )
        ]
        
        # Create highlights
        highlights = {
            "log_1": [
                HighlightMatch(
                    field="message",
                    fragments=["<em>Database</em> connection failed"],
                    score=2.0
                )
            ]
        }
        
        # Create complete search result
        result = LogSearchResult(
            status=ResponseStatus.SUCCESS,
            total_hits=100,
            max_score=2.5,
            logs=logs,
            aggregations=aggregations,
            highlights=highlights,
            metrics=metrics,
            offset=0,
            limit=100,
            warnings=["Query was complex and took longer than usual"]
        )
        
        # Verify all components integrated correctly
        assert result.result_count == 1
        assert result.has_aggregations is True
        assert result.has_highlights is True
        assert result.completion_percentage == 1.0  # 1/100 * 100
        assert len(result.warnings) == 1
        assert result.metrics.performance_category == "medium"