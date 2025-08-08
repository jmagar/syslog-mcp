"""
Tests for query and search models.
"""

import pytest
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List

from pydantic import ValidationError

from syslog_mcp.models.query import (
    TimeRange, SearchFilter, AggregationRequest, LogSearchQuery,
    DeviceSearchQuery, AggregationQuery, SearchContext, SortOrder
)
from syslog_mcp.models.log_entry import LogLevel
from syslog_mcp.models.device import DeviceType


class TestSortOrder:
    """Test SortOrder enum."""
    
    def test_sort_order_values(self):
        """Test sort order enum values."""
        assert SortOrder.ASC == "asc"
        assert SortOrder.DESC == "desc"


class TestTimeRange:
    """Test TimeRange model for time-based filtering."""
    
    def test_explicit_time_range(self):
        """Test explicit start/end time range."""
        start = datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        end = datetime(2024, 1, 2, 0, 0, 0, tzinfo=timezone.utc)
        
        time_range = TimeRange(start=start, end=end)
        
        assert time_range.start == start
        assert time_range.end == end
        assert time_range.effective_start == start
        assert time_range.effective_end == end
    
    def test_last_hours_range(self):
        """Test relative time range using last_hours."""
        time_range = TimeRange(last_hours=24)
        
        assert time_range.last_hours == 24
        assert time_range.effective_start is not None
        assert time_range.effective_end is not None
        
        # Should be approximately 24 hours ago
        expected_start = datetime.now(timezone.utc) - timedelta(hours=24)
        actual_start = time_range.effective_start
        
        # Allow 1 minute tolerance for test execution time
        assert abs((actual_start - expected_start).total_seconds()) < 60
    
    def test_last_days_range(self):
        """Test relative time range using last_days."""
        time_range = TimeRange(last_days=7)
        
        assert time_range.last_days == 7
        assert time_range.effective_start is not None
        
        expected_start = datetime.now(timezone.utc) - timedelta(days=7)
        actual_start = time_range.effective_start
        
        # Allow 1 minute tolerance
        assert abs((actual_start - expected_start).total_seconds()) < 60
    
    def test_invalid_time_range(self):
        """Test validation of invalid time ranges."""
        start = datetime(2024, 1, 2, 0, 0, 0, tzinfo=timezone.utc)
        end = datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc)  # Before start
        
        with pytest.raises(ValidationError, match="End time must be after start time"):
            TimeRange(start=start, end=end)
    
    def test_no_time_specification(self):
        """Test time range with no time specification."""
        time_range = TimeRange()
        
        assert time_range.effective_start is None
        assert time_range.effective_end is not None  # Defaults to now


class TestSearchFilter:
    """Test SearchFilter model for field-based filtering."""
    
    def test_basic_filter(self):
        """Test basic search filter creation."""
        filter_obj = SearchFilter(
            field="device",
            operator="eq",
            value="web-server-01"
        )
        
        assert filter_obj.field == "device"
        assert filter_obj.operator == "eq"
        assert filter_obj.value == "web-server-01"
        assert filter_obj.case_sensitive is False
    
    def test_list_value_filter(self):
        """Test filter with list value."""
        filter_obj = SearchFilter(
            field="level",
            operator="in",
            value=["ERROR", "CRITICAL"]
        )
        
        assert filter_obj.operator == "in"
        assert filter_obj.value == ["ERROR", "CRITICAL"]
    
    def test_case_sensitive_filter(self):
        """Test case sensitive filter."""
        filter_obj = SearchFilter(
            field="message",
            operator="contains",
            value="Failed",
            case_sensitive=True
        )
        
        assert filter_obj.case_sensitive is True
    
    def test_invalid_operator(self):
        """Test validation of invalid operators."""
        with pytest.raises(ValidationError, match="Invalid operator"):
            SearchFilter(
                field="device",
                operator="invalid_op",
                value="test"
            )
    
    def test_regex_filter(self):
        """Test regex filter."""
        filter_obj = SearchFilter(
            field="device",
            operator="regex",
            value=r"web-.*\d+"
        )
        
        assert filter_obj.operator == "regex"
        assert filter_obj.value == r"web-.*\d+"


class TestAggregationRequest:
    """Test AggregationRequest model for analytics."""
    
    def test_terms_aggregation(self):
        """Test terms aggregation request."""
        agg = AggregationRequest(
            name="devices_by_type",
            type="terms",
            field="device_type",
            size=20
        )
        
        assert agg.name == "devices_by_type"
        assert agg.type == "terms"
        assert agg.field == "device_type"
        assert agg.size == 20
    
    def test_date_histogram_aggregation(self):
        """Test date histogram aggregation."""
        agg = AggregationRequest(
            name="logs_over_time",
            type="date_histogram",
            field="timestamp",
            interval="1h",
            min_doc_count=0
        )
        
        assert agg.type == "date_histogram"
        assert agg.interval == "1h"
        assert agg.min_doc_count == 0
    
    def test_stats_aggregation(self):
        """Test stats aggregation."""
        agg = AggregationRequest(
            name="health_stats",
            type="stats",
            field="health_score"
        )
        
        assert agg.type == "stats"
        assert agg.field == "health_score"
    
    def test_invalid_aggregation_type(self):
        """Test validation of invalid aggregation types."""
        with pytest.raises(ValidationError, match="Invalid aggregation type"):
            AggregationRequest(
                name="test",
                type="invalid_type",
                field="test_field"
            )


class TestLogSearchQuery:
    """Test LogSearchQuery model for comprehensive log searching."""
    
    def test_minimal_search_query(self):
        """Test creation with minimal parameters."""
        query = LogSearchQuery()
        
        assert query.limit == 100
        assert query.offset == 0
        assert query.sort_field == "timestamp"
        assert query.sort_order == SortOrder.DESC
        assert query.filters == []
        assert query.aggregations == []
    
    def test_full_text_search(self):
        """Test full-text search query."""
        query = LogSearchQuery(
            query_string="authentication failed",
            limit=50
        )
        
        assert query.query_string == "authentication failed"
        assert query.limit == 50
    
    def test_time_filtered_query(self):
        """Test query with time filtering."""
        time_range = TimeRange(last_hours=24)
        query = LogSearchQuery(
            time_range=time_range,
            devices=["web-server-01", "web-server-02"],
            levels=[LogLevel.ERROR, LogLevel.CRITICAL]
        )
        
        assert query.time_range == time_range
        assert query.has_time_filter is True
        assert len(query.devices) == 2
        assert len(query.levels) == 2
    
    def test_filtered_search(self):
        """Test search with field filters."""
        filters = [
            SearchFilter(field="facility", operator="eq", value="auth"),
            SearchFilter(field="message", operator="contains", value="failed")
        ]
        
        query = LogSearchQuery(
            filters=filters,
            facilities=["auth", "daemon"],
            sort_field="level",
            sort_order=SortOrder.ASC
        )
        
        assert len(query.filters) == 2
        assert query.facilities == ["auth", "daemon"]
        assert query.sort_field == "level"
        assert query.sort_order == SortOrder.ASC
    
    def test_aggregated_search(self):
        """Test search with aggregations."""
        aggregations = [
            AggregationRequest(
                name="by_device",
                type="terms",
                field="device",
                size=10
            ),
            AggregationRequest(
                name="by_hour",
                type="date_histogram",
                field="timestamp",
                interval="1h"
            )
        ]
        
        query = LogSearchQuery(
            aggregations=aggregations,
            include_metadata=False,
            highlight=True
        )
        
        assert len(query.aggregations) == 2
        assert query.include_metadata is False
        assert query.highlight is True
    
    def test_result_size_estimation(self):
        """Test result size estimation."""
        small_query = LogSearchQuery(limit=50)
        medium_query = LogSearchQuery(limit=500)
        large_query = LogSearchQuery(limit=2000)
        very_large_query = LogSearchQuery(limit=8000)
        
        assert small_query.estimated_result_size == "small"
        assert medium_query.estimated_result_size == "medium"
        assert large_query.estimated_result_size == "large"
        assert very_large_query.estimated_result_size == "very_large"
    
    def test_too_many_filters(self):
        """Test validation of too many filters."""
        # Create 51 filters (over the limit)
        filters = [
            SearchFilter(field=f"field_{i}", operator="eq", value=f"value_{i}")
            for i in range(51)
        ]
        
        with pytest.raises(ValidationError, match="Too many filters"):
            LogSearchQuery(filters=filters)
    
    def test_too_many_filters_per_field(self):
        """Test validation of too many filters on single field."""
        # Create 6 filters on the same field (over the limit)
        filters = [
            SearchFilter(field="device", operator="eq", value=f"server-{i}")
            for i in range(6)
        ]
        
        with pytest.raises(ValidationError, match="Too many filters on field"):
            LogSearchQuery(filters=filters)
    
    def test_scroll_pagination(self):
        """Test scroll-based pagination."""
        query = LogSearchQuery(
            scroll_id="scroll123456789",
            limit=1000
        )
        
        assert query.scroll_id == "scroll123456789"
        assert query.estimated_result_size == "medium"


class TestDeviceSearchQuery:
    """Test DeviceSearchQuery model for device searches."""
    
    def test_basic_device_query(self):
        """Test basic device search query."""
        query = DeviceSearchQuery()
        
        assert query.limit == 50
        assert query.offset == 0
        assert query.sort_by == "health_score"
        assert query.sort_order == SortOrder.DESC
        assert query.min_health_score == 0.0
        assert query.max_health_score == 1.0
    
    def test_name_pattern_search(self):
        """Test device search with name patterns."""
        query = DeviceSearchQuery(
            name_pattern="web-*",
            device_types=[DeviceType.SERVER, DeviceType.VIRTUAL_MACHINE],
            environments=["production", "staging"]
        )
        
        assert query.name_pattern == "web-*"
        assert len(query.device_types) == 2
        assert len(query.environments) == 2
    
    def test_health_filtered_search(self):
        """Test device search with health filtering."""
        query = DeviceSearchQuery(
            min_health_score=0.7,
            max_health_score=1.0,
            statuses=["healthy", "warning"],
            active_within_hours=24.0
        )
        
        assert query.min_health_score == 0.7
        assert query.max_health_score == 1.0
        assert query.active_within_hours == 24.0
        assert len(query.statuses) == 2
    
    def test_location_and_tag_search(self):
        """Test device search with location and tag filtering."""
        query = DeviceSearchQuery(
            locations=["datacenter-a", "datacenter-b"],
            tags={"team": "platform", "env": "prod"},
            min_log_count=1000,
            sort_by="name",
            sort_order=SortOrder.ASC
        )
        
        assert len(query.locations) == 2
        assert query.tags["team"] == "platform"
        assert query.min_log_count == 1000
        assert query.sort_by == "name"
        assert query.sort_order == SortOrder.ASC
    
    def test_statistics_inclusion(self):
        """Test statistics inclusion option."""
        with_stats = DeviceSearchQuery(include_statistics=True)
        without_stats = DeviceSearchQuery(include_statistics=False)
        
        assert with_stats.include_statistics is True
        assert without_stats.include_statistics is False


class TestAggregationQuery:
    """Test AggregationQuery model for analytics operations."""
    
    def test_simple_aggregation_query(self):
        """Test simple aggregation query."""
        aggregations = [
            AggregationRequest(
                name="device_counts",
                type="terms",
                field="device"
            )
        ]
        
        query = AggregationQuery(aggregations=aggregations)
        
        assert len(query.aggregations) == 1
        assert query.include_raw_data is False
        assert query.format_results is True
    
    def test_time_based_aggregation(self):
        """Test time-based aggregation query."""
        base_query = LogSearchQuery(
            time_range=TimeRange(last_days=7),
            levels=[LogLevel.ERROR]
        )
        
        aggregations = [
            AggregationRequest(
                name="errors_by_hour",
                type="date_histogram",
                field="timestamp",
                interval="1h"
            )
        ]
        
        query = AggregationQuery(
            base_query=base_query,
            time_interval="1h",
            aggregations=aggregations,
            include_raw_data=True
        )
        
        assert query.base_query == base_query
        assert query.time_interval == "1h"
        assert query.include_raw_data is True
    
    def test_multiple_aggregations(self):
        """Test query with multiple aggregations."""
        aggregations = [
            AggregationRequest(name="by_device", type="terms", field="device"),
            AggregationRequest(name="by_level", type="terms", field="level"),
            AggregationRequest(name="level_stats", type="stats", field="level")
        ]
        
        query = AggregationQuery(
            aggregations=aggregations,
            format_results=False
        )
        
        assert len(query.aggregations) == 3
        assert query.format_results is False
    
    def test_aggregation_limits(self):
        """Test aggregation count limits."""
        # Too many aggregations
        aggregations = [
            AggregationRequest(name=f"agg_{i}", type="terms", field="device")
            for i in range(11)  # Over the limit of 10
        ]
        
        with pytest.raises(ValidationError):
            AggregationQuery(aggregations=aggregations)
        
        # No aggregations
        with pytest.raises(ValidationError):
            AggregationQuery(aggregations=[])


class TestSearchContext:
    """Test SearchContext model for search metadata."""
    
    def test_basic_context(self):
        """Test basic search context."""
        context = SearchContext()
        
        assert context.cache_ttl == 300
        assert context.priority == "normal"
        assert context.explain is False
    
    def test_user_context(self):
        """Test search context with user information."""
        context = SearchContext(
            user_id="user123",
            session_id="session456",
            query_id="query789",
            priority="high"
        )
        
        assert context.user_id == "user123"
        assert context.session_id == "session456"
        assert context.query_id == "query789"
        assert context.priority == "high"
    
    def test_cache_and_explain(self):
        """Test cache and explain options."""
        context = SearchContext(
            cache_ttl=600,
            explain=True,
            priority="urgent"
        )
        
        assert context.cache_ttl == 600
        assert context.explain is True
        assert context.priority == "urgent"
    
    def test_invalid_priority(self):
        """Test validation of invalid priorities."""
        with pytest.raises(ValidationError, match="Invalid priority"):
            SearchContext(priority="invalid")
    
    def test_cache_ttl_limits(self):
        """Test cache TTL validation."""
        # Valid TTL
        context = SearchContext(cache_ttl=1800)
        assert context.cache_ttl == 1800
        
        # Invalid TTL (too high)
        with pytest.raises(ValidationError):
            SearchContext(cache_ttl=3601)
        
        # Invalid TTL (negative)
        with pytest.raises(ValidationError):
            SearchContext(cache_ttl=-1)


class TestQueryModelIntegration:
    """Test integration between different query models."""
    
    def test_complete_search_scenario(self):
        """Test a complete search scenario with all components."""
        # Create time range
        time_range = TimeRange(last_hours=6)
        
        # Create filters
        filters = [
            SearchFilter(field="facility", operator="eq", value="auth"),
            SearchFilter(field="message", operator="contains", value="failed")
        ]
        
        # Create aggregations
        aggregations = [
            AggregationRequest(
                name="devices",
                type="terms",
                field="device",
                size=20
            )
        ]
        
        # Create main search query
        search_query = LogSearchQuery(
            query_string="authentication error",
            time_range=time_range,
            filters=filters,
            levels=[LogLevel.ERROR, LogLevel.WARN],
            aggregations=aggregations,
            limit=500,
            highlight=True
        )
        
        # Create search context
        context = SearchContext(
            user_id="analyst_001",
            priority="high",
            explain=True
        )
        
        # Verify all components work together
        assert search_query.has_time_filter is True
        assert search_query.estimated_result_size == "medium"
        assert len(search_query.filters) == 2
        assert len(search_query.aggregations) == 1
        assert context.priority == "high"
    
    def test_device_and_log_search_consistency(self):
        """Test consistency between device and log search models."""
        # Both should support similar sorting and pagination
        device_query = DeviceSearchQuery(
            limit=100,
            offset=50,
            sort_order=SortOrder.ASC
        )
        
        log_query = LogSearchQuery(
            limit=100,
            offset=50,
            sort_order=SortOrder.ASC
        )
        
        assert device_query.limit == log_query.limit
        assert device_query.offset == log_query.offset
        assert device_query.sort_order == log_query.sort_order