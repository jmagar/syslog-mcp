"""
Comprehensive error handling framework for the Syslog MCP server.

Provides error classification, recovery strategies, structured logging,
and graceful degradation patterns inspired by FastMCP middleware.
"""

import time
import traceback
from collections.abc import Callable
from datetime import datetime
from functools import wraps
from typing import Any

from elasticsearch.exceptions import (
    AuthenticationException,
    AuthorizationException,
    NotFoundError,
    RequestError,
    SSLError,
    TransportError,
)
from elasticsearch.exceptions import (
    ConnectionError as ESConnectionError,
)
from elasticsearch.exceptions import (
    ConnectionTimeout as ESTimeoutError,
)

from ..exceptions import (
    CircuitBreakerOpenError,
    ElasticsearchAuthenticationError,
    ElasticsearchAuthorizationError,
    ElasticsearchConnectionError,
    ElasticsearchIndexError,
    ElasticsearchQueryError,
    ElasticsearchRateLimitError,
    ElasticsearchSystemError,
    ElasticsearchTimeoutError,
    ElasticsearchValidationError,
    ErrorCategory,
    RetryableElasticsearchError,
    SyslogMCPError,
)
from ..utils.logging import get_logger

logger = get_logger(__name__)


class ErrorClassifier:
    """
    Classifies and transforms Elasticsearch exceptions into structured MCP errors.

    Similar to FastMCP's error handling middleware, provides consistent
    error responses and classification.
    """

    @staticmethod
    def classify_elasticsearch_error(error: Exception, context: dict[str, Any] | None = None) -> SyslogMCPError:
        """
        Classify an Elasticsearch exception into a structured MCP error.

        Args:
            error: The original Elasticsearch exception
            context: Additional context information

        Returns:
            Appropriate SyslogMCPError subclass
        """
        context = context or {}

        # Timeout errors (check first since ConnectionTimeout inherits from ConnectionError)
        if isinstance(error, ESTimeoutError):
            return ElasticsearchTimeoutError(
                f"Operation timed out: {str(error)}",
                original_error=error,
                operation=context.get("operation"),
                timeout_seconds=context.get("timeout_seconds"),
            )

        # Connection errors
        if isinstance(error, ESConnectionError | TransportError):
            return ElasticsearchConnectionError(
                f"Connection failed: {str(error)}",
                original_error=error,
                host=context.get("host"),
                context=context,
            )

        # Authentication errors
        if isinstance(error, AuthenticationException):
            return ElasticsearchAuthenticationError(
                f"Authentication failed: {str(error)}",
                original_error=error,
                auth_method=context.get("auth_method"),
            )

        # Authorization errors
        if isinstance(error, AuthorizationException):
            return ElasticsearchAuthorizationError(
                f"Authorization failed: {str(error)}",
                original_error=error,
                required_privilege=context.get("required_privilege"),
            )


        # SSL errors - not recoverable
        if isinstance(error, SSLError):
            return ElasticsearchConnectionError(
                f"SSL connection failed: {str(error)}",
                original_error=error,
                recoverable=False,
                recovery_hint="Check SSL configuration and certificates",
            )

        # Request errors - analyze status code
        if isinstance(error, RequestError):
            status_code = getattr(error, 'status_code', None)
            if status_code is None and hasattr(error, 'meta'):
                status_code = getattr(error.meta, 'status', None)

            # Rate limiting
            if status_code == 429:
                retry_after = None
                if hasattr(error, 'body') and error.body:
                    # Try to extract retry-after from error body
                    retry_after = error.body.get('retry_after', None)

                return ElasticsearchRateLimitError(
                    f"Rate limit exceeded: {str(error)}",
                    original_error=error,
                    retry_after=retry_after,
                )

            # Query errors (400 Bad Request)
            if status_code == 400:
                return ElasticsearchQueryError(
                    f"Invalid query: {str(error)}",
                    original_error=error,
                    query=context.get("query"),
                    index=context.get("index"),
                )

            # Not found errors
            if status_code == 404:
                return ElasticsearchIndexError(
                    f"Index not found: {str(error)}",
                    original_error=error,
                    index_name=context.get("index"),
                    operation="read",
                )

            # Service unavailable - recoverable
            if status_code in [503, 502, 504]:
                return RetryableElasticsearchError(
                    f"Service temporarily unavailable: {str(error)}",
                    original_error=error,
                )

        # Not found errors
        if isinstance(error, NotFoundError):
            return ElasticsearchIndexError(
                f"Resource not found: {str(error)}",
                original_error=error,
                index_name=context.get("index"),
            )

        # ValidationError for data validation issues
        if isinstance(error, ValueError | TypeError):
            return ElasticsearchValidationError(
                f"Validation error: {str(error)}",
                original_error=error,
                field=context.get("field"),
                value=context.get("value"),
            )

        # Circuit breaker specific
        if isinstance(error, CircuitBreakerOpenError):
            return error  # Already properly structured

        # Default to system error for unknown exceptions
        return ElasticsearchSystemError(
            f"Unexpected error: {str(error)}",
            original_error=error,
            component=context.get("component", "elasticsearch_client"),
        )


class ErrorRecoveryManager:
    """
    Manages error recovery strategies and graceful degradation.

    Provides recovery mechanisms for different error types and contexts.
    """

    def __init__(self) -> None:
        self.recovery_attempts: dict[str, int] = {}
        self.recovery_strategies: dict[ErrorCategory, Callable[..., dict[str, Any] | None]] = {
            ErrorCategory.CONNECTION: self._recover_connection_error,
            ErrorCategory.TIMEOUT: self._recover_timeout_error,
            ErrorCategory.RATE_LIMIT: self._recover_rate_limit_error,
            ErrorCategory.QUERY: self._recover_query_error,
        }

    async def attempt_recovery(
        self,
        error: SyslogMCPError,
        context: dict[str, Any] | None = None
    ) -> dict[str, Any] | None:
        """
        Attempt to recover from an error.

        Args:
            error: The structured error to recover from
            context: Recovery context information

        Returns:
            Recovery suggestions or None if not recoverable
        """
        if not error.recoverable:
            logger.warning(
                "Error is not recoverable",
                extra={
                    "error_type": type(error).__name__,
                    "category": error.category.value,
                    "recovery_hint": error.recovery_hint,
                }
            )
            return None

        recovery_strategy = self.recovery_strategies.get(error.category)
        if not recovery_strategy:
            logger.debug(f"No recovery strategy for category: {error.category.value}")
            return None

        try:
            result = await recovery_strategy(error, context or {})
            return result
        except Exception as e:
            logger.error(
                "Recovery attempt failed",
                extra={
                    "error_type": type(error).__name__,
                    "recovery_error": str(e),
                    "traceback": traceback.format_exc(),
                }
            )
            return None

    async def _recover_connection_error(
        self,
        error: SyslogMCPError,
        context: dict[str, Any]
    ) -> dict[str, Any]:
        """Recovery strategy for connection errors."""
        return {
            "strategy": "reconnect",
            "wait_seconds": min(2 ** context.get("attempt", 1), 30),  # Exponential backoff
            "max_attempts": 3,
            "fallback_available": True,
        }

    async def _recover_timeout_error(
        self,
        error: SyslogMCPError,
        context: dict[str, Any]
    ) -> dict[str, Any]:
        """Recovery strategy for timeout errors."""
        return {
            "strategy": "increase_timeout",
            "new_timeout": context.get("timeout", 30) * 1.5,
            "reduce_query_size": True,
            "max_attempts": 2,
        }

    async def _recover_rate_limit_error(
        self,
        error: SyslogMCPError,
        context: dict[str, Any]
    ) -> dict[str, Any]:
        """Recovery strategy for rate limit errors."""
        retry_after = error.context.get("retry_after_seconds", 1)
        return {
            "strategy": "backoff_and_retry",
            "wait_seconds": retry_after,
            "reduce_rate": True,
            "max_attempts": 5,
        }

    async def _recover_query_error(
        self,
        error: SyslogMCPError,
        context: dict[str, Any]
    ) -> dict[str, Any]:
        """Recovery strategy for query errors."""
        return {
            "strategy": "simplify_query",
            "fallback_to_basic": True,
            "validate_parameters": True,
            "max_attempts": 1,  # Don't retry query errors multiple times
        }


class ErrorMiddleware:
    """
    Error handling middleware inspired by FastMCP patterns.

    Provides consistent error handling, logging, and recovery across
    all Elasticsearch operations.
    """

    def __init__(
        self,
        include_traceback: bool = False,
        transform_errors: bool = True,
        enable_recovery: bool = True,
        log_level: str = "ERROR",
    ):
        self.include_traceback = include_traceback
        self.transform_errors = transform_errors
        self.enable_recovery = enable_recovery
        self.log_level = log_level
        self.classifier = ErrorClassifier()
        self.recovery_manager = ErrorRecoveryManager()
        self.error_stats: dict[str, int] = {}

    async def handle_error(
        self,
        error: Exception,
        operation: str,
        context: dict[str, Any] | None = None,
    ) -> SyslogMCPError:
        """
        Handle and transform an error with comprehensive logging and recovery.

        Args:
            error: The original exception
            operation: Name of the operation that failed
            context: Additional context information

        Returns:
            Structured MCP error
        """
        context = context or {}
        context["operation"] = operation
        context["timestamp"] = datetime.utcnow().isoformat()

        # Classify the error
        if isinstance(error, SyslogMCPError):
            structured_error = error
            # Ensure context includes operation info
            structured_error.context.update(context)
        else:
            structured_error = self.classifier.classify_elasticsearch_error(error, context)

        # Track error statistics
        error_key = f"{type(structured_error).__name__}:{operation}"
        self.error_stats[error_key] = self.error_stats.get(error_key, 0) + 1

        # Prepare logging data
        log_data = {
            "operation": operation,
            "error_info": structured_error.to_dict(),
            "context": context,
            "error_count": self.error_stats[error_key],
        }

        if self.include_traceback and structured_error.original_error:
            log_data["traceback"] = traceback.format_exception(
                type(structured_error.original_error),
                structured_error.original_error,
                structured_error.original_error.__traceback__
            )

        # Log the error
        log_method = getattr(logger, self.log_level.lower(), logger.error)
        log_method(
            f"Error in {operation}: {structured_error.message}",
            extra=log_data
        )

        # Attempt recovery if enabled
        if self.enable_recovery and structured_error.recoverable:
            recovery_info = await self.recovery_manager.attempt_recovery(
                structured_error, context
            )
            if recovery_info:
                logger.info(
                    f"Recovery strategy available for {operation}",
                    extra={"recovery_info": recovery_info}
                )
                # Add recovery info to error context
                structured_error.context["recovery_info"] = recovery_info

        return structured_error

    def get_error_stats(self) -> dict[str, int]:
        """Get error statistics for monitoring."""
        return self.error_stats.copy()

    def reset_error_stats(self) -> None:
        """Reset error statistics."""
        self.error_stats.clear()


class GracefulDegradationManager:
    """
    Manages graceful degradation when Elasticsearch is unavailable.

    Provides fallback responses and cached data when possible.
    """

    def __init__(self) -> None:
        self.degradation_mode = False
        self.degradation_start_time: float | None = None
        self.cached_responses: dict[str, dict[str, Any]] = {}
        self.fallback_data: dict[str, Any] = {
            "cluster_health": {
                "status": "degraded",
                "message": "Elasticsearch temporarily unavailable",
                "timestamp": None,
            },
            "search_results": {
                "results": [],
                "total": 0,
                "message": "Search temporarily unavailable",
            },
        }

    def enter_degradation_mode(self, reason: str) -> None:
        """Enter graceful degradation mode."""
        if not self.degradation_mode:
            self.degradation_mode = True
            self.degradation_start_time = time.time()
            self.fallback_data["cluster_health"]["timestamp"] = datetime.utcnow().isoformat()

            logger.warning(
                "Entering graceful degradation mode",
                extra={"reason": reason, "timestamp": self.degradation_start_time}
            )

    def exit_degradation_mode(self) -> None:
        """Exit graceful degradation mode."""
        if self.degradation_mode:
            degradation_duration = time.time() - (self.degradation_start_time or 0)
            self.degradation_mode = False
            self.degradation_start_time = None

            logger.info(
                "Exiting graceful degradation mode",
                extra={"duration_seconds": degradation_duration}
            )

    def get_fallback_response(self, operation: str) -> dict[str, Any] | None:
        """Get fallback response for an operation."""
        if not self.degradation_mode:
            return None

        # Check cached responses first
        if operation in self.cached_responses:
            cached = self.cached_responses[operation]
            cache_age = time.time() - cached.get("cached_at", 0)
            if cache_age < 300:  # Use cache for 5 minutes
                logger.debug(f"Using cached response for {operation}")
                return dict(cached["data"])

        # Return static fallback data
        fallback = self.fallback_data.get(operation)
        if fallback:
            logger.debug(f"Using fallback response for {operation}")
            return dict(fallback.copy())

        return None

    def cache_response(self, operation: str, data: dict[str, Any]) -> None:
        """Cache a response for potential fallback use."""
        self.cached_responses[operation] = {
            "data": data,
            "cached_at": time.time(),
        }


def error_handler(
    operation: str,
    include_traceback: bool = False,
    enable_recovery: bool = True,
) -> Callable[..., Callable[..., Any]]:
    """
    Decorator for comprehensive error handling in async functions.

    Args:
        operation: Name of the operation for logging
        include_traceback: Whether to include traceback in logs
        enable_recovery: Whether to attempt error recovery
    """
    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(func)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            middleware = ErrorMiddleware(
                include_traceback=include_traceback,
                enable_recovery=enable_recovery,
            )

            try:
                return await func(*args, **kwargs)
            except Exception as e:
                context = {
                    "function": func.__name__,
                    "args_count": len(args),
                    "kwargs_keys": list(kwargs.keys()),
                }

                structured_error = await middleware.handle_error(e, operation, context)
                raise structured_error

        return wrapper
    return decorator


def create_error_context(
    operation: str,
    index: str | None = None,
    query: dict[str, Any] | None = None,
    host: str | None = None,
    **additional_context: Any
) -> dict[str, Any]:
    """
    Create standardized error context for consistent logging.

    Args:
        operation: The operation being performed
        index: Elasticsearch index name
        query: Query being executed
        host: Elasticsearch host
        **additional_context: Additional context fields

    Returns:
        Standardized context dictionary
    """
    context = {
        "operation": operation,
        "timestamp": datetime.utcnow().isoformat(),
    }

    if index:
        context["index"] = index
    if query:
        context["query"] = dict(query)
    if host:
        context["host"] = host

    context.update(additional_context)
    return context
