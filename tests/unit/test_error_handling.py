"""
Tests for comprehensive error handling framework.
"""

import pytest
import asyncio
from unittest.mock import Mock, patch
from elasticsearch.exceptions import (
    ConnectionError as ESConnectionError,
    AuthenticationException,
    RequestError,
    ConnectionTimeout as ESTimeoutError,
)
from elastic_transport import ApiResponseMeta

from syslog_mcp.exceptions import (
    SyslogMCPError,
    ElasticsearchConnectionError,
    ElasticsearchAuthenticationError,
    ElasticsearchTimeoutError,
    ElasticsearchRateLimitError,
    ElasticsearchQueryError,
    ElasticsearchValidationError,
    ErrorSeverity,
    ErrorCategory,
)

from syslog_mcp.utils.error_handling import (
    ErrorClassifier,
    ErrorMiddleware,
    ErrorRecoveryManager,
    GracefulDegradationManager,
    error_handler,
    create_error_context,
)


class TestErrorClassification:
    """Test error classification functionality."""
    
    def test_classify_connection_error(self):
        """Test classification of Elasticsearch connection errors."""
        es_error = ESConnectionError("Connection failed")
        context = {"host": "localhost:9200"}
        
        classified = ErrorClassifier.classify_elasticsearch_error(es_error, context)
        
        assert isinstance(classified, ElasticsearchConnectionError)
        assert classified.severity == ErrorSeverity.HIGH
        assert classified.category == ErrorCategory.CONNECTION
        assert classified.recoverable is True
        assert "localhost:9200" in str(classified.context)
        assert classified.original_error == es_error
    
    def test_classify_authentication_error(self):
        """Test classification of authentication errors."""
        # Create a proper ApiResponseMeta for the exception
        meta = ApiResponseMeta(status=401, headers={}, http_version="1.1", duration=1.0, node=None)
        es_error = AuthenticationException("Invalid credentials", meta, {})
        context = {"auth_method": "api_key"}
        
        classified = ErrorClassifier.classify_elasticsearch_error(es_error, context)
        
        assert isinstance(classified, ElasticsearchAuthenticationError)
        assert classified.severity == ErrorSeverity.HIGH
        assert classified.category == ErrorCategory.AUTHENTICATION
        assert classified.recoverable is False
        assert "api_key" in str(classified.context)
    
    def test_classify_timeout_error(self):
        """Test classification of timeout errors."""
        es_error = ESTimeoutError("Operation timed out")
        context = {"operation": "search", "timeout_seconds": 30.0}
        
        classified = ErrorClassifier.classify_elasticsearch_error(es_error, context)
        
        assert isinstance(classified, ElasticsearchTimeoutError)
        assert classified.severity == ErrorSeverity.MEDIUM
        assert classified.category == ErrorCategory.TIMEOUT
        assert classified.recoverable is True
        assert classified.context["timeout_seconds"] == 30.0
    
    def test_classify_rate_limit_error(self):
        """Test classification of rate limit errors."""
        # Create a proper ApiResponseMeta for rate limit error
        meta = ApiResponseMeta(status=429, headers={}, http_version="1.1", duration=1.0, node=None)
        es_error = RequestError("Too Many Requests", meta, {"retry_after": "5"})
        
        classified = ErrorClassifier.classify_elasticsearch_error(es_error)
        
        assert isinstance(classified, ElasticsearchRateLimitError)
        assert classified.severity == ErrorSeverity.MEDIUM
        assert classified.category == ErrorCategory.RATE_LIMIT
        assert classified.recoverable is True
    
    def test_classify_query_error(self):
        """Test classification of query errors."""
        # Create a proper ApiResponseMeta for query error
        meta = ApiResponseMeta(status=400, headers={}, http_version="1.1", duration=1.0, node=None)
        es_error = RequestError("Bad Request", meta, {})
        context = {"query": {"match": {"field": "value"}}, "index": "test-index"}
        
        classified = ErrorClassifier.classify_elasticsearch_error(es_error, context)
        
        assert isinstance(classified, ElasticsearchQueryError)
        assert classified.severity == ErrorSeverity.MEDIUM
        assert classified.category == ErrorCategory.QUERY
        assert classified.recoverable is False
        assert "test-index" in str(classified.context)
    
    def test_classify_validation_error(self):
        """Test classification of validation errors."""
        es_error = ValueError("Invalid parameter")
        context = {"field": "size", "value": -1}
        
        classified = ErrorClassifier.classify_elasticsearch_error(es_error, context)
        
        assert isinstance(classified, ElasticsearchValidationError)
        assert classified.severity == ErrorSeverity.LOW
        assert classified.category == ErrorCategory.VALIDATION
        assert classified.recoverable is False


class TestErrorMiddleware:
    """Test error handling middleware functionality."""
    
    @pytest.mark.asyncio
    async def test_error_middleware_handles_error(self):
        """Test that error middleware properly handles and transforms errors."""
        middleware = ErrorMiddleware(
            include_traceback=False,
            transform_errors=True,
            enable_recovery=True,
        )
        
        es_error = ESConnectionError("Connection failed")
        context = {"host": "localhost:9200"}
        
        structured_error = await middleware.handle_error(
            es_error, "test_operation", context
        )
        
        assert isinstance(structured_error, ElasticsearchConnectionError)
        assert structured_error.context["operation"] == "test_operation"
        assert "timestamp" in structured_error.context
    
    @pytest.mark.asyncio
    async def test_error_middleware_tracks_statistics(self):
        """Test that error middleware tracks error statistics."""
        middleware = ErrorMiddleware()
        
        es_error = ESConnectionError("Connection failed")
        
        await middleware.handle_error(es_error, "test_operation")
        await middleware.handle_error(es_error, "test_operation")
        
        stats = middleware.get_error_stats()
        assert "ElasticsearchConnectionError:test_operation" in stats
        assert stats["ElasticsearchConnectionError:test_operation"] == 2
    
    def test_error_middleware_reset_stats(self):
        """Test error statistics reset functionality."""
        middleware = ErrorMiddleware()
        middleware.error_stats["test"] = 5
        
        middleware.reset_error_stats()
        
        assert middleware.get_error_stats() == {}


class TestErrorRecoveryManager:
    """Test error recovery functionality."""
    
    @pytest.mark.asyncio
    async def test_recovery_for_connection_error(self):
        """Test recovery strategy for connection errors."""
        manager = ErrorRecoveryManager()
        
        error = ElasticsearchConnectionError("Connection failed")
        context = {"attempt": 1}
        
        recovery_info = await manager.attempt_recovery(error, context)
        
        assert recovery_info is not None
        assert recovery_info["strategy"] == "reconnect"
        assert recovery_info["wait_seconds"] == 2  # 2^1
        assert recovery_info["fallback_available"] is True
    
    @pytest.mark.asyncio
    async def test_recovery_for_timeout_error(self):
        """Test recovery strategy for timeout errors."""
        manager = ErrorRecoveryManager()
        
        error = ElasticsearchTimeoutError("Operation timed out", timeout_seconds=30.0)
        context = {"timeout": 30}
        
        recovery_info = await manager.attempt_recovery(error, context)
        
        assert recovery_info is not None
        assert recovery_info["strategy"] == "increase_timeout"
        assert recovery_info["new_timeout"] == 45.0  # 30 * 1.5
        assert recovery_info["reduce_query_size"] is True
    
    @pytest.mark.asyncio
    async def test_recovery_for_rate_limit_error(self):
        """Test recovery strategy for rate limit errors."""
        manager = ErrorRecoveryManager()
        
        error = ElasticsearchRateLimitError(
            "Rate limit exceeded", 
            retry_after=10
        )
        error.context = {"retry_after_seconds": 10}
        
        recovery_info = await manager.attempt_recovery(error)
        
        assert recovery_info is not None
        assert recovery_info["strategy"] == "backoff_and_retry"
        assert recovery_info["wait_seconds"] == 10
        assert recovery_info["reduce_rate"] is True
    
    @pytest.mark.asyncio
    async def test_no_recovery_for_non_recoverable_error(self):
        """Test that non-recoverable errors return None."""
        manager = ErrorRecoveryManager()
        
        error = ElasticsearchAuthenticationError("Invalid credentials")
        
        recovery_info = await manager.attempt_recovery(error)
        
        assert recovery_info is None


class TestGracefulDegradationManager:
    """Test graceful degradation functionality."""
    
    def test_enter_degradation_mode(self):
        """Test entering graceful degradation mode."""
        manager = GracefulDegradationManager()
        
        assert manager.degradation_mode is False
        
        manager.enter_degradation_mode("Elasticsearch unavailable")
        
        assert manager.degradation_mode is True
        assert manager.degradation_start_time is not None
    
    def test_exit_degradation_mode(self):
        """Test exiting graceful degradation mode."""
        manager = GracefulDegradationManager()
        manager.enter_degradation_mode("Test")
        
        manager.exit_degradation_mode()
        
        assert manager.degradation_mode is False
        assert manager.degradation_start_time is None
    
    def test_get_fallback_response_when_not_degraded(self):
        """Test that fallback responses are None when not in degradation mode."""
        manager = GracefulDegradationManager()
        
        response = manager.get_fallback_response("cluster_health")
        
        assert response is None
    
    def test_get_fallback_response_when_degraded(self):
        """Test fallback responses in degradation mode."""
        manager = GracefulDegradationManager()
        manager.enter_degradation_mode("Test")
        
        response = manager.get_fallback_response("cluster_health")
        
        assert response is not None
        assert response["status"] == "degraded"
        assert "Elasticsearch temporarily unavailable" in response["message"]
    
    def test_cache_and_retrieve_response(self):
        """Test caching and retrieving responses."""
        manager = GracefulDegradationManager()
        manager.enter_degradation_mode("Test")
        
        # Cache a response
        test_data = {"result": "success"}
        manager.cache_response("test_operation", test_data)
        
        # Retrieve cached response
        cached = manager.get_fallback_response("test_operation")
        
        assert cached == test_data


class TestErrorHandlerDecorator:
    """Test error handler decorator functionality."""
    
    @pytest.mark.asyncio
    async def test_error_handler_decorator_catches_exceptions(self):
        """Test that error handler decorator catches and transforms exceptions."""
        
        @error_handler("test_operation")
        async def failing_function():
            raise ESConnectionError("Connection failed")
        
        with pytest.raises(ElasticsearchConnectionError) as exc_info:
            await failing_function()
        
        error = exc_info.value
        assert isinstance(error, ElasticsearchConnectionError)
        assert error.severity == ErrorSeverity.HIGH
        assert error.category == ErrorCategory.CONNECTION
    
    @pytest.mark.asyncio
    async def test_error_handler_decorator_passes_success(self):
        """Test that error handler decorator passes through successful results."""
        
        @error_handler("test_operation")
        async def successful_function():
            return {"status": "success"}
        
        result = await successful_function()
        
        assert result == {"status": "success"}


class TestErrorContext:
    """Test error context creation functionality."""
    
    def test_create_error_context_basic(self):
        """Test basic error context creation."""
        context = create_error_context("test_operation")
        
        assert context["operation"] == "test_operation"
        assert "timestamp" in context
    
    def test_create_error_context_with_parameters(self):
        """Test error context creation with parameters."""
        context = create_error_context(
            operation="search",
            index="test-index",
            query={"match": {"field": "value"}},
            host="localhost:9200",
            custom_field="custom_value"
        )
        
        assert context["operation"] == "search"
        assert context["index"] == "test-index"
        assert context["query"] == {"match": {"field": "value"}}
        assert context["host"] == "localhost:9200"
        assert context["custom_field"] == "custom_value"
        assert "timestamp" in context


class TestSyslogMCPErrorBase:
    """Test base SyslogMCPError functionality."""
    
    def test_error_to_dict(self):
        """Test error dictionary conversion."""
        error = SyslogMCPError(
            "Test error",
            severity=ErrorSeverity.HIGH,
            category=ErrorCategory.CONNECTION,
            context={"host": "localhost"},
            recoverable=True,
            recovery_hint="Retry connection",
            original_error=ValueError("Original"),
        )
        
        error_dict = error.to_dict()
        
        assert error_dict["error_type"] == "SyslogMCPError"
        assert error_dict["message"] == "Test error"
        assert error_dict["severity"] == "high"
        assert error_dict["category"] == "connection"
        assert error_dict["recoverable"] is True
        assert error_dict["recovery_hint"] == "Retry connection"
        assert error_dict["context"] == {"host": "localhost"}
        assert "Original" in error_dict["original_error"]
    
    def test_error_inheritance(self):
        """Test that custom errors inherit properly."""
        error = ElasticsearchConnectionError("Connection failed")
        
        assert isinstance(error, SyslogMCPError)
        assert error.severity == ErrorSeverity.HIGH
        assert error.category == ErrorCategory.CONNECTION
        assert error.recoverable is True