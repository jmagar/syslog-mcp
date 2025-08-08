"""
Custom exceptions for the Syslog MCP server.

Follows FastMCP patterns for comprehensive error handling with
custom exception hierarchy, error classification, and structured logging.
"""

from typing import Any, Dict, Optional
from enum import Enum


class ErrorSeverity(Enum):
    """Error severity levels for classification and handling priorities."""
    
    LOW = "low"
    MEDIUM = "medium"  
    HIGH = "high"
    CRITICAL = "critical"


class ErrorCategory(Enum):
    """Error categories for classification and recovery strategies."""
    
    CONNECTION = "connection"
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    VALIDATION = "validation"
    TIMEOUT = "timeout"
    RATE_LIMIT = "rate_limit"
    QUERY = "query"
    INDEX = "index"
    SYSTEM = "system"
    UNKNOWN = "unknown"


class SyslogMCPError(Exception):
    """
    Base exception for all Syslog MCP server errors.
    
    Provides structured error information similar to FastMCP's error handling
    with severity, category, context, and recovery hints.
    """
    
    def __init__(
        self,
        message: str,
        *,
        severity: ErrorSeverity = ErrorSeverity.MEDIUM,
        category: ErrorCategory = ErrorCategory.UNKNOWN,
        context: Optional[Dict[str, Any]] = None,
        recoverable: bool = False,
        recovery_hint: Optional[str] = None,
        original_error: Optional[Exception] = None,
    ):
        super().__init__(message)
        self.message = message
        self.severity = severity
        self.category = category
        self.context = context or {}
        self.recoverable = recoverable
        self.recovery_hint = recovery_hint
        self.original_error = original_error
        
    def to_dict(self) -> Dict[str, Any]:
        """Convert exception to dictionary for structured logging."""
        return {
            "error_type": self.__class__.__name__,
            "message": self.message,
            "severity": self.severity.value,
            "category": self.category.value,
            "recoverable": self.recoverable,
            "recovery_hint": self.recovery_hint,
            "context": self.context,
            "original_error": str(self.original_error) if self.original_error else None,
        }


class ElasticsearchConnectionError(SyslogMCPError):
    """Raised when connection to Elasticsearch fails."""
    
    def __init__(
        self,
        message: str,
        original_error: Optional[Exception] = None,
        host: Optional[str] = None,
        **kwargs
    ):
        # Handle context passed via kwargs or create new
        context = kwargs.pop('context', {})
        if host:
            context["host"] = host
            
        super().__init__(
            message,
            severity=ErrorSeverity.HIGH,
            category=ErrorCategory.CONNECTION,
            recoverable=True,
            recovery_hint="Check Elasticsearch connectivity and retry",
            original_error=original_error,
            context=context,
            **kwargs
        )


class ElasticsearchAuthenticationError(SyslogMCPError):
    """Raised when Elasticsearch authentication fails."""
    
    def __init__(
        self,
        message: str,
        original_error: Optional[Exception] = None,
        auth_method: Optional[str] = None,
        **kwargs
    ):
        context = {"auth_method": auth_method} if auth_method else {}
        super().__init__(
            message,
            severity=ErrorSeverity.HIGH,
            category=ErrorCategory.AUTHENTICATION,
            recoverable=False,
            recovery_hint="Verify API key or credentials",
            original_error=original_error,
            context=context,
            **kwargs
        )


class ElasticsearchAuthorizationError(SyslogMCPError):
    """Raised when Elasticsearch authorization fails."""
    
    def __init__(
        self,
        message: str,
        original_error: Optional[Exception] = None,
        required_privilege: Optional[str] = None,
        **kwargs
    ):
        context = {"required_privilege": required_privilege} if required_privilege else {}
        super().__init__(
            message,
            severity=ErrorSeverity.MEDIUM,
            category=ErrorCategory.AUTHORIZATION,
            recoverable=False,
            recovery_hint="Check user permissions and privileges",
            original_error=original_error,
            context=context,
            **kwargs
        )


class ElasticsearchSSLError(SyslogMCPError):
    """Raised when SSL/TLS connection to Elasticsearch fails."""
    
    def __init__(
        self,
        message: str,
        ssl_config: Optional[Dict[str, Any]] = None,
        original_error: Optional[Exception] = None,
        **kwargs
    ):
        context = ssl_config or {}
        super().__init__(
            message,
            severity=ErrorSeverity.HIGH,
            category=ErrorCategory.CONNECTION,
            recoverable=False,
            recovery_hint="Check SSL certificates and configuration",
            original_error=original_error,
            context=context,
            **kwargs
        )


class ElasticsearchTimeoutError(SyslogMCPError):
    """Raised when Elasticsearch operations timeout."""
    
    def __init__(
        self,
        message: str,
        original_error: Optional[Exception] = None,
        operation: Optional[str] = None,
        timeout_seconds: Optional[float] = None,
        **kwargs
    ):
        context = {
            "operation": operation,
            "timeout_seconds": timeout_seconds,
        }
        context = {k: v for k, v in context.items() if v is not None}
        
        super().__init__(
            message,
            severity=ErrorSeverity.MEDIUM,
            category=ErrorCategory.TIMEOUT,
            recoverable=True,
            recovery_hint="Increase timeout or optimize query",
            original_error=original_error,
            context=context,
            **kwargs
        )


class ElasticsearchRateLimitError(SyslogMCPError):
    """Raised when Elasticsearch rate limits are exceeded."""
    
    def __init__(
        self,
        message: str,
        original_error: Optional[Exception] = None,
        retry_after: Optional[int] = None,
        **kwargs
    ):
        context = {"retry_after_seconds": retry_after} if retry_after else {}
        super().__init__(
            message,
            severity=ErrorSeverity.MEDIUM,
            category=ErrorCategory.RATE_LIMIT,
            recoverable=True,
            recovery_hint=f"Wait {retry_after} seconds before retrying" if retry_after else "Reduce request rate",
            original_error=original_error,
            context=context,
            **kwargs
        )


class ElasticsearchQueryError(SyslogMCPError):
    """Raised when Elasticsearch query is malformed or invalid."""
    
    def __init__(
        self,
        message: str,
        original_error: Optional[Exception] = None,
        query: Optional[Dict[str, Any]] = None,
        index: Optional[str] = None,
        **kwargs
    ):
        context = {}
        if query:
            context["query"] = query
        if index:
            context["index"] = index
            
        super().__init__(
            message,
            severity=ErrorSeverity.MEDIUM,
            category=ErrorCategory.QUERY,
            recoverable=False,
            recovery_hint="Review query syntax and parameters",
            original_error=original_error,
            context=context,
            **kwargs
        )


class ElasticsearchIndexError(SyslogMCPError):
    """Raised when Elasticsearch index operations fail."""
    
    def __init__(
        self,
        message: str,
        original_error: Optional[Exception] = None,
        index_name: Optional[str] = None,
        operation: Optional[str] = None,
        **kwargs
    ):
        context = {}
        if index_name:
            context["index_name"] = index_name
        if operation:
            context["operation"] = operation
            
        super().__init__(
            message,
            severity=ErrorSeverity.MEDIUM,
            category=ErrorCategory.INDEX,
            recoverable=True,
            recovery_hint="Check index existence and mapping",
            original_error=original_error,
            context=context,
            **kwargs
        )


class ElasticsearchValidationError(SyslogMCPError):
    """Raised when input validation fails."""
    
    def __init__(
        self,
        message: str,
        original_error: Optional[Exception] = None,
        field: Optional[str] = None,
        value: Optional[Any] = None,
        **kwargs
    ):
        context = {}
        if field:
            context["field"] = field
        if value is not None:
            context["invalid_value"] = str(value)
            
        super().__init__(
            message,
            severity=ErrorSeverity.LOW,
            category=ErrorCategory.VALIDATION,
            recoverable=False,
            recovery_hint="Correct the input parameters",
            original_error=original_error,
            context=context,
            **kwargs
        )


class ElasticsearchSystemError(SyslogMCPError):
    """Raised for internal system errors and unexpected failures."""
    
    def __init__(
        self,
        message: str,
        original_error: Optional[Exception] = None,
        component: Optional[str] = None,
        **kwargs
    ):
        context = {"component": component} if component else {}
        super().__init__(
            message,
            severity=ErrorSeverity.CRITICAL,
            category=ErrorCategory.SYSTEM,
            recoverable=False,
            recovery_hint="Contact system administrator",
            original_error=original_error,
            context=context,
            **kwargs
        )


class CircuitBreakerOpenError(SyslogMCPError):
    """Raised when circuit breaker is in open state."""
    
    def __init__(
        self,
        message: str = "Circuit breaker is open",
        failure_count: Optional[int] = None,
        reset_timeout: Optional[float] = None,
        **kwargs
    ):
        context = {}
        if failure_count is not None:
            context["failure_count"] = failure_count
        if reset_timeout is not None:
            context["reset_timeout_seconds"] = reset_timeout
            
        recovery_hint = f"Wait {reset_timeout} seconds for circuit breaker to reset" if reset_timeout else "Wait for circuit breaker to reset"
        
        super().__init__(
            message,
            severity=ErrorSeverity.HIGH,
            category=ErrorCategory.SYSTEM,
            recoverable=True,
            recovery_hint=recovery_hint,
            context=context,
            **kwargs
        )


class RetryableElasticsearchError(SyslogMCPError):
    """Raised for errors that should be retried."""
    
    def __init__(
        self,
        message: str,
        original_error: Optional[Exception] = None,
        attempts: Optional[int] = None,
        max_attempts: Optional[int] = None,
        **kwargs
    ):
        context = {}
        if attempts is not None:
            context["attempts"] = attempts
        if max_attempts is not None:
            context["max_attempts"] = max_attempts
            
        recovery_hint = "Operation will be retried automatically"
        if attempts and max_attempts:
            recovery_hint = f"Retrying ({attempts}/{max_attempts})"
            
        super().__init__(
            message,
            severity=ErrorSeverity.MEDIUM,
            category=ErrorCategory.SYSTEM,
            recoverable=True,
            recovery_hint=recovery_hint,
            original_error=original_error,
            context=context,
            **kwargs
        )