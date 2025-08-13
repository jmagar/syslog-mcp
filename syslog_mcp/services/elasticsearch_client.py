"""
Elasticsearch connection and client management.

This module provides an async Elasticsearch client with connection management,
configuration handling, and proper resource cleanup patterns.
"""

import asyncio
import random
import time
from collections.abc import AsyncGenerator, Callable, Coroutine
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Any, TypeVar, cast

from elasticsearch import AsyncElasticsearch
from elasticsearch.exceptions import (
    AuthenticationException,
    ConnectionError,
    NotFoundError,
    RequestError,
    SSLError,
    TransportError,
)
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Import comprehensive error handling framework
from ..exceptions import (
    CircuitBreakerOpenError,
    ElasticsearchAuthenticationError,
    ElasticsearchConnectionError,
    ElasticsearchSSLError,
    RetryableElasticsearchError,
)
from ..utils.error_handling import (
    ErrorMiddleware,
    GracefulDegradationManager,
)
from ..utils.logging import get_logger
from ..models.log_entry import LogEntry
from ..models.query import LogSearchQuery
from ..models.response import LogSearchResult, ExecutionMetrics

T = TypeVar('T')


class ElasticsearchConfig(BaseSettings):
    """Configuration for Elasticsearch connection."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

    hosts: str | list[str] = Field(default="localhost:9200", alias="ELASTICSEARCH_HOST")
    api_key: str | None = Field(default=None, alias="ELASTICSEARCH_API_KEY")
    username: str | None = Field(default=None, alias="ELASTICSEARCH_USERNAME")
    password: str | None = Field(default=None, alias="ELASTICSEARCH_PASSWORD")
    use_ssl: bool = Field(default=False, alias="ELASTICSEARCH_USE_SSL")
    verify_certs: bool = Field(default=True, alias="ELASTICSEARCH_VERIFY_CERTS")
    ca_certs: str | None = Field(default=None, alias="ELASTICSEARCH_CA_CERTS")
    client_cert: str | None = Field(default=None, alias="ELASTICSEARCH_CLIENT_CERT")
    client_key: str | None = Field(default=None, alias="ELASTICSEARCH_CLIENT_KEY")
    ssl_assert_hostname: bool = Field(default=True, alias="ELASTICSEARCH_SSL_ASSERT_HOSTNAME")
    ssl_assert_fingerprint: str | None = Field(default=None, alias="ELASTICSEARCH_SSL_FINGERPRINT")
    timeout: int = Field(default=30, alias="ELASTICSEARCH_TIMEOUT")
    max_retries: int = Field(default=3, alias="ELASTICSEARCH_MAX_RETRIES")
    retry_on_timeout: bool = Field(default=True, alias="ELASTICSEARCH_RETRY_ON_TIMEOUT")

    # Retry configuration
    retry_initial_delay: float = Field(default=1.0, alias="ELASTICSEARCH_RETRY_INITIAL_DELAY")
    retry_max_delay: float = Field(default=60.0, alias="ELASTICSEARCH_RETRY_MAX_DELAY")
    retry_backoff_multiplier: float = Field(default=2.0, alias="ELASTICSEARCH_RETRY_BACKOFF_MULTIPLIER")
    retry_jitter: bool = Field(default=True, alias="ELASTICSEARCH_RETRY_JITTER")

    # Circuit breaker configuration
    circuit_breaker_failure_threshold: int = Field(default=5, alias="ELASTICSEARCH_CB_FAILURE_THRESHOLD")
    circuit_breaker_reset_timeout: float = Field(default=60.0, alias="ELASTICSEARCH_CB_RESET_TIMEOUT")
    circuit_breaker_half_open_max_calls: int = Field(default=3, alias="ELASTICSEARCH_CB_HALF_OPEN_MAX_CALLS")

    # Connection pool configuration
    pool_maxsize: int = Field(default=10, alias="ELASTICSEARCH_POOL_MAXSIZE")
    pool_connections: int = Field(default=10, alias="ELASTICSEARCH_POOL_CONNECTIONS")
    pool_block: bool = Field(default=False, alias="ELASTICSEARCH_POOL_BLOCK")
    pool_timeout: float = Field(default=5.0, alias="ELASTICSEARCH_POOL_TIMEOUT")
    connection_timeout: float = Field(default=5.0, alias="ELASTICSEARCH_CONNECTION_TIMEOUT")
    keepalive_timeout: float = Field(default=60.0, alias="ELASTICSEARCH_KEEPALIVE_TIMEOUT")

    # Resource management
    max_idle_connections: int = Field(default=5, alias="ELASTICSEARCH_MAX_IDLE_CONNECTIONS")
    connection_max_age: float = Field(default=300.0, alias="ELASTICSEARCH_CONNECTION_MAX_AGE") # 5 minutes
    enable_connection_pooling: bool = Field(default=True, alias="ELASTICSEARCH_ENABLE_POOLING")

    # Index configuration
    default_index: str = Field(default="syslog-*", alias="ELASTICSEARCH_INDEX")

    # Authentication priority and validation
    auth_priority: list[str] = Field(
        default=["api_key", "basic", "none"],
        alias="ELASTICSEARCH_AUTH_PRIORITY"
    )

    @field_validator("hosts", mode="before")
    @classmethod
    def parse_hosts(cls, v: str | list[str]) -> list[str]:
        """Parse hosts from string or list."""
        if isinstance(v, str):
            # Handle comma-separated hosts
            if "," in v:
                hosts = [host.strip() for host in v.split(",")]
            else:
                hosts = [v]

            # Add http:// scheme if not present
            formatted_hosts = []
            for host in hosts:
                if not host.startswith(('http://', 'https://')):
                    host = f"http://{host}"
                formatted_hosts.append(host)
            return formatted_hosts
        return v

    @field_validator("api_key", mode="before")
    @classmethod
    def parse_api_key(cls, v: str | None) -> str | None:
        """Parse API key from string or environment."""
        if v is None or v == "":
            return None
        return v

    @field_validator("auth_priority", mode="before")
    @classmethod
    def parse_auth_priority(cls, v: str | list[str]) -> list[str]:
        """Parse authentication priority from string or list."""
        if isinstance(v, str):
            return [method.strip() for method in v.split(",")]
        return v

    def validate_authentication_config(self) -> tuple[bool, str]:
        """
        Validate authentication configuration.

        Returns:
            Tuple of (is_valid, error_message)
        """
        # Check if SSL is properly configured when using certificates
        if self.client_cert or self.client_key:
            if not self.use_ssl:
                return False, "SSL must be enabled when using client certificates"
            if self.client_cert and not self.client_key:
                return False, "Client key must be provided when using client certificate"
            if self.client_key and not self.client_cert:
                return False, "Client certificate must be provided when using client key"

        # Validate authentication methods
        valid_methods = {"api_key", "basic", "none"}
        for method in self.auth_priority:
            if method not in valid_methods:
                return False, f"Invalid authentication method: {method}"

        # Check API key format (basic validation)
        if self.api_key:
            if ":" not in self.api_key and len(self.api_key) < 20:
                return False, "API key appears to be invalid format"

        # Validate basic auth credentials
        if self.username and not self.password:
            return False, "Password must be provided when using username"
        if self.password and not self.username:
            return False, "Username must be provided when using password"

        return True, ""

    def get_effective_auth_method(self) -> str:
        """
        Determine the effective authentication method based on configuration and priority.

        Returns:
            The authentication method that will be used
        """
        for method in self.auth_priority:
            if method == "api_key" and self.api_key:
                return "api_key"
            elif method == "basic" and self.username and self.password:
                return "basic"
            elif method == "none":
                return "none"

        return "none"


# Use comprehensive error handling from exceptions module
# RetryableElasticsearchError and CircuitBreakerOpenError are now imported


class CircuitBreaker:
    """Circuit breaker implementation for Elasticsearch operations."""

    def __init__(
        self,
        failure_threshold: int = 5,
        reset_timeout: float = 60.0,
        half_open_max_calls: int = 3,
    ):
        self.failure_threshold = failure_threshold
        self.reset_timeout = reset_timeout
        self.half_open_max_calls = half_open_max_calls

        self._failure_count = 0
        self._last_failure_time = 0.0
        self._state = "closed"  # closed, open, half_open
        self._half_open_calls = 0
        self._lock = asyncio.Lock()

    async def call(self, func: Callable[[], Any]) -> Any:
        """Execute function with circuit breaker protection."""
        async with self._lock:
            now = time.time()

            # Check if we should transition from open to half-open
            if self._state == "open" and (now - self._last_failure_time) >= self.reset_timeout:
                self._state = "half_open"
                self._half_open_calls = 0

            # Reject calls if circuit is open
            if self._state == "open":
                raise CircuitBreakerOpenError("Circuit breaker is open")

            # Limit calls in half-open state
            if self._state == "half_open" and self._half_open_calls >= self.half_open_max_calls:
                raise CircuitBreakerOpenError("Circuit breaker is half-open with max calls reached")

        try:
            # Execute the function
            if self._state == "half_open":
                self._half_open_calls += 1

            result = await func()

            # Success - reset failure count and close circuit if needed
            async with self._lock:
                if self._state == "half_open":
                    self._state = "closed"
                self._failure_count = 0

            return result

        except Exception as e:
            # Record failure
            async with self._lock:
                self._failure_count += 1
                self._last_failure_time = time.time()

                # Open circuit if failure threshold reached
                if self._failure_count >= self.failure_threshold:
                    self._state = "open"
                elif self._state == "half_open":
                    # Go back to open state on failure in half-open
                    self._state = "open"

            raise e

    @property
    def state(self) -> str:
        """Get current circuit breaker state."""
        return self._state

    @property
    def failure_count(self) -> int:
        """Get current failure count."""
        return self._failure_count


class RetryManager:
    """Manages retry logic with exponential backoff and jitter."""

    def __init__(
        self,
        max_retries: int = 3,
        initial_delay: float = 1.0,
        max_delay: float = 60.0,
        backoff_multiplier: float = 2.0,
        jitter: bool = True,
    ):
        self.max_retries = max_retries
        self.initial_delay = initial_delay
        self.max_delay = max_delay
        self.backoff_multiplier = backoff_multiplier
        self.jitter = jitter

    def _calculate_delay(self, attempt: int) -> float:
        """Calculate delay for given attempt with exponential backoff and jitter."""
        # Exponential backoff: delay = initial_delay * (backoff_multiplier ^ attempt)
        delay = self.initial_delay * (self.backoff_multiplier ** attempt)
        delay = min(delay, self.max_delay)

        # Add jitter to prevent thundering herd
        if self.jitter:
            # Add random jitter of ±25% of calculated delay
            jitter_amount = delay * 0.25 * (random.random() * 2 - 1)  # -25% to +25%
            delay += jitter_amount
            delay = max(0.1, delay)  # Ensure minimum delay

        return delay

    def _is_retryable_error(self, error: Exception) -> bool:
        """Determine if error is retryable."""
        # Network and connection errors are retryable
        if isinstance(error, ConnectionError | TransportError):
            return True

        # Some specific authentication errors might be retryable (e.g., temporary auth service issues)
        if isinstance(error, AuthenticationException):
            # Only retry auth errors that might be transient
            error_msg = str(error).lower()
            if "timeout" in error_msg or "connection" in error_msg or "service unavailable" in error_msg:
                return True
            return False

        # SSL errors are generally not retryable
        if isinstance(error, SSLError):
            return False

        # Request errors (4xx) are generally not retryable, except some specific cases
        if isinstance(error, RequestError):
            # 408 Request Timeout, 429 Too Many Requests, 503 Service Unavailable are retryable
            if hasattr(error, 'status_code') and error.status_code in [408, 429, 503]:
                return True
            return False

        # NotFound errors are not retryable
        if isinstance(error, NotFoundError):
            return False

        # Assume other errors might be retryable (conservative approach)
        return True

    async def execute_with_retry(
        self,
        func: Callable[[], Any],
        operation_name: str = "elasticsearch_operation",
        logger: Any = None,
    ) -> Any:
        """Execute function with retry logic."""
        last_error = None

        for attempt in range(self.max_retries + 1):  # +1 for initial attempt
            try:
                result = await func()

                # Log successful retry if this wasn't the first attempt
                if attempt > 0 and logger:
                    logger.info(
                        f"Operation succeeded after {attempt} retries",
                        extra={
                            "operation": operation_name,
                            "attempt": attempt + 1,
                            "total_attempts": attempt + 1,
                        }
                    )

                return result

            except Exception as e:
                last_error = e

                # Check if error is retryable
                if not self._is_retryable_error(e):
                    if logger:
                        logger.warning(
                            f"Non-retryable error in {operation_name}",
                            extra={
                                "operation": operation_name,
                                "error": str(e),
                                "error_type": type(e).__name__,
                                "attempt": attempt + 1,
                            }
                        )
                    raise e

                # Don't retry on last attempt
                if attempt >= self.max_retries:
                    break

                # Calculate delay and wait
                delay = self._calculate_delay(attempt)

                if logger:
                    logger.warning(
                        f"Operation failed, retrying in {delay:.2f}s",
                        extra={
                            "operation": operation_name,
                            "error": str(e),
                            "error_type": type(e).__name__,
                            "attempt": attempt + 1,
                            "max_attempts": self.max_retries + 1,
                            "retry_delay": delay,
                        }
                    )

                await asyncio.sleep(delay)

        # All retries exhausted
        if logger:
            logger.error(
                f"Operation failed after {self.max_retries + 1} attempts",
                extra={
                    "operation": operation_name,
                    "final_error": str(last_error),
                    "error_type": type(last_error).__name__ if last_error else "Unknown",
                    "total_attempts": self.max_retries + 1,
                }
            )

        # Raise the last error wrapped in our custom exception
        raise RetryableElasticsearchError(
            f"Operation '{operation_name}' failed after {self.max_retries + 1} attempts: {str(last_error)}"
        ) from last_error


# Custom exception classes moved to comprehensive error handling framework
# All exceptions now inherit from SyslogMCPError with structured error information or {}


class ElasticsearchClient:
    """
    Async Elasticsearch client with connection management and health monitoring.

    This class provides a managed connection to Elasticsearch with proper
    resource cleanup, configuration handling, and error management.
    """

    def __init__(self, config: ElasticsearchConfig | None = None):
        """
        Initialize Elasticsearch client.

        Args:
            config: Elasticsearch configuration. If None, will be loaded from environment.

        Raises:
            ElasticsearchConnectionError: If configuration is invalid
        """
        self.config = config or ElasticsearchConfig()
        self.logger = get_logger(__name__)
        self._client: AsyncElasticsearch | None = None
        self._connection_lock = asyncio.Lock()

        # Connection pool statistics and management
        self._pool_stats = {
            "total_connections": 0,
            "active_connections": 0,
            "idle_connections": 0,
            "connections_created": 0,
            "connections_closed": 0,
            "pool_hits": 0,
            "pool_misses": 0,
            "last_cleanup": 0.0,
        }
        self._connection_created_time: float | None = None
        self._shutdown_event = asyncio.Event()
        self._cleanup_task: asyncio.Task[None] | None = None

        # Initialize retry manager and circuit breaker
        self._retry_manager = RetryManager(
            max_retries=self.config.max_retries,
            initial_delay=self.config.retry_initial_delay,
            max_delay=self.config.retry_max_delay,
            backoff_multiplier=self.config.retry_backoff_multiplier,
            jitter=self.config.retry_jitter,
        )

        self._circuit_breaker = CircuitBreaker(
            failure_threshold=self.config.circuit_breaker_failure_threshold,
            reset_timeout=self.config.circuit_breaker_reset_timeout,
            half_open_max_calls=self.config.circuit_breaker_half_open_max_calls,
        )

        # Initialize comprehensive error handling framework
        self._error_middleware = ErrorMiddleware(
            include_traceback=False,  # Set to True for debugging
            transform_errors=True,
            enable_recovery=True,
            log_level="ERROR",
        )
        self._degradation_manager = GracefulDegradationManager()

        # Validate configuration at initialization
        is_valid, error_message = self.config.validate_authentication_config()
        if not is_valid:
            raise ElasticsearchConnectionError(f"Invalid configuration: {error_message}")

    @property
    def is_connected(self) -> bool:
        """Check if client is connected."""
        return self._client is not None

    @property
    def circuit_breaker_state(self) -> str:
        """Get current circuit breaker state."""
        return self._circuit_breaker.state

    @property
    def circuit_breaker_failure_count(self) -> int:
        """Get current circuit breaker failure count."""
        return self._circuit_breaker.failure_count

    async def _execute_with_resilience(
        self,
        func: Callable[[], Any],
        operation_name: str,
        use_circuit_breaker: bool = True,
        use_retry: bool = True,
    ) -> Any:
        """
        Execute function with retry logic and circuit breaker protection.

        Args:
            func: Async function to execute
            operation_name: Name of operation for logging
            use_circuit_breaker: Whether to use circuit breaker protection
            use_retry: Whether to use retry logic

        Returns:
            Function result

        Raises:
            Various Elasticsearch exceptions or RetryableElasticsearchError
        """
        async def execute_operation() -> Any:
            if use_retry:
                return await self._retry_manager.execute_with_retry(
                    func, operation_name, self.logger
                )
            else:
                return await func()

        if use_circuit_breaker:
            try:
                return await self._circuit_breaker.call(execute_operation)
            except CircuitBreakerOpenError:
                self.logger.error(
                    f"Circuit breaker open for {operation_name}",
                    extra={
                        "operation": operation_name,
                        "circuit_breaker_state": self._circuit_breaker.state,
                        "failure_count": self._circuit_breaker.failure_count,
                    }
                )
                # Transform circuit breaker error using structured error framework
                structured_error = CircuitBreakerOpenError(
                    f"Circuit breaker open for {operation_name}",
                    failure_count=self._circuit_breaker.failure_count,
                    reset_timeout=self._circuit_breaker.reset_timeout,
                )
                raise structured_error
        else:
            return await execute_operation()

    async def __aenter__(self) -> "ElasticsearchClient":
        """Async context manager entry."""
        await self.connect()
        return self

    async def __aexit__(self, exc_type: type, exc_val: Exception, exc_tb: Any) -> None:
        """Async context manager exit."""
        await self.disconnect()

    async def connect(self) -> None:
        """
        Establish connection to Elasticsearch cluster.

        Raises:
            ElasticsearchConnectionError: If connection fails
        """
        async with self._connection_lock:
            if self._client is not None:
                self.logger.warning("Client already connected")
                return

            try:
                # Prepare connection parameters with only basic supported parameters
                connect_params: dict[str, Any] = {
                    "hosts": self.config.hosts,
                }

                # Configure SSL/TLS settings
                if self.config.use_ssl:
                    connect_params["use_ssl"] = True
                    connect_params["verify_certs"] = self.config.verify_certs
                    connect_params["ssl_assert_hostname"] = self.config.ssl_assert_hostname

                    # Add certificate files if provided
                    if self.config.ca_certs:
                        connect_params["ca_certs"] = self.config.ca_certs

                    if self.config.client_cert:
                        connect_params["client_cert"] = self.config.client_cert

                    if self.config.client_key:
                        connect_params["client_key"] = self.config.client_key

                    if self.config.ssl_assert_fingerprint:
                        connect_params["ssl_assert_fingerprint"] = self.config.ssl_assert_fingerprint

                    self.logger.debug(
                        "SSL configuration applied",
                        extra={
                            "verify_certs": self.config.verify_certs,
                            "ca_certs_provided": bool(self.config.ca_certs),
                            "client_cert_provided": bool(self.config.client_cert),
                            "ssl_assert_hostname": self.config.ssl_assert_hostname,
                        }
                    )

                # Configure authentication based on priority
                auth_method = self.config.get_effective_auth_method()

                if auth_method == "api_key":
                    connect_params["api_key"] = self.config.api_key
                    self.logger.debug("Using API key authentication")
                elif auth_method == "basic":
                    connect_params["http_auth"] = (self.config.username, self.config.password)
                    self.logger.debug("Using basic authentication", extra={"username": self.config.username})
                else:
                    self.logger.debug("Using no authentication")

                self.logger.info(
                    "Connecting to Elasticsearch",
                    extra={
                        "hosts": self.config.hosts,
                        "use_ssl": self.config.use_ssl,
                        "auth_method": auth_method,
                        "verify_certs": self.config.verify_certs,
                    },
                )

                # Create client
                self._client = AsyncElasticsearch(**connect_params)

                # Test connection
                await self._test_connection()

                # Update connection statistics
                self._connection_created_time = time.time()
                self._pool_stats["connections_created"] += 1
                self._pool_stats["total_connections"] = 1
                self._pool_stats["active_connections"] = 1

                # Start cleanup task for connection management
                if self.config.enable_connection_pooling:
                    self._start_cleanup_task()

                self.logger.info(
                    "Successfully connected to Elasticsearch",
                    extra={
                        "hosts": self.config.hosts,
                        "connection_pooling": self.config.enable_connection_pooling,
                        "pool_stats": self._pool_stats,
                    },
                )

            except Exception as e:
                self._client = None
                error_msg = f"Failed to connect to Elasticsearch: {str(e)}"
                self.logger.error(error_msg, extra={"error": str(e)})
                raise ElasticsearchConnectionError(error_msg, e) from e

    async def disconnect(self) -> None:
        """Disconnect from Elasticsearch cluster."""
        async with self._connection_lock:
            # Signal cleanup task to stop
            self._shutdown_event.set()

            # Cancel and wait for cleanup task
            if self._cleanup_task and not self._cleanup_task.done():
                self._cleanup_task.cancel()
                try:
                    await self._cleanup_task
                except asyncio.CancelledError:
                    pass

            if self._client is not None:
                try:
                    await self._client.close()

                    # Update connection statistics
                    self._pool_stats["connections_closed"] += 1
                    self._pool_stats["total_connections"] = 0
                    self._pool_stats["active_connections"] = 0
                    self._connection_created_time = None

                    self.logger.info(
                        "Disconnected from Elasticsearch",
                        extra={"final_pool_stats": self._pool_stats}
                    )
                except Exception as e:
                    self.logger.warning(
                        "Error during disconnect",
                        extra={"error": str(e)},
                    )
                finally:
                    self._client = None

    async def _test_connection(self) -> None:
        """
        Test the connection to Elasticsearch.

        Raises:
            ElasticsearchConnectionError: If connection test fails
        """
        if not self._client:
            raise ElasticsearchConnectionError("Client not initialized")

        try:
            # Test basic connectivity
            info = await self._client.info()
            self.logger.debug(
                "Elasticsearch connection test successful",
                extra={
                    "cluster_name": info.get("cluster_name"),
                    "version": info.get("version", {}).get("number"),
                },
            )
        except AuthenticationException as e:
            auth_method = self.config.get_effective_auth_method()
            error_msg = f"Authentication failed using {auth_method} method"
            self.logger.error(error_msg, extra={
                "auth_method": auth_method,
                "error": str(e),
            })
            raise ElasticsearchAuthenticationError(error_msg, e, auth_method) from e
        except SSLError as e:
            ssl_config = {
                "use_ssl": self.config.use_ssl,
                "verify_certs": self.config.verify_certs,
                "ca_certs_provided": bool(self.config.ca_certs),
                "client_cert_provided": bool(self.config.client_cert),
            }
            error_msg = f"SSL/TLS error: {str(e)}"
            self.logger.error(error_msg, extra={
                "ssl_config": ssl_config,
                "error": str(e),
            })
            raise ElasticsearchSSLError(error_msg, ssl_config, e) from e
        except ConnectionError as e:
            raise ElasticsearchConnectionError("Connection error", e) from e
        except TransportError as e:
            raise ElasticsearchConnectionError(f"Transport error: {str(e)}", e) from e
        except Exception as e:
            raise ElasticsearchConnectionError(f"Unexpected error: {str(e)}", e) from e

    @property
    def client(self) -> AsyncElasticsearch:
        """
        Get the Elasticsearch client instance.

        Returns:
            AsyncElasticsearch client

        Raises:
            ElasticsearchConnectionError: If not connected
        """
        if not self._client:
            raise ElasticsearchConnectionError("Client not connected. Call connect() first.")
        return self._client

    async def ping(self) -> bool:
        """
        Ping Elasticsearch cluster to check connectivity.

        Returns:
            True if ping successful, False otherwise
        """
        if not self._client:
            return False

        try:
            async def ping_operation() -> bool:
                client = cast(AsyncElasticsearch, self._client)
                return await client.ping()

            result = await self._execute_with_resilience(
                ping_operation,
                "ping",
                use_circuit_breaker=False,  # Don't use circuit breaker for ping
                use_retry=True
            )
            return cast(bool, result)
        except Exception as e:
            self.logger.warning("Ping failed after retries", extra={"error": str(e)})
            return False

    async def get_cluster_info(self) -> dict[str, Any]:
        """
        Get basic cluster information.

        Returns:
            Dictionary containing cluster info

        Raises:
            ElasticsearchConnectionError: If not connected or request fails
        """
        if not self._client:
            raise ElasticsearchConnectionError("Client not connected")

        try:
            async def info_operation() -> dict[str, Any]:
                client = cast(AsyncElasticsearch, self._client)
                info = await client.info()
                return dict(info)

            result = await self._execute_with_resilience(
                info_operation,
                "get_cluster_info",
                use_circuit_breaker=True,
                use_retry=True
            )
            return cast(dict[str, Any], result)
        except (RetryableElasticsearchError, CircuitBreakerOpenError):
            # These are already properly formatted errors from our resilience layer
            raise
        except Exception as e:
            error_msg = f"Failed to get cluster info: {str(e)}"
            self.logger.error(error_msg, extra={"error": str(e)})
            raise ElasticsearchConnectionError(error_msg, e) from e

    async def validate_credentials(self) -> tuple[bool, dict[str, Any]]:
        """
        Validate the current authentication credentials.

        Returns:
            Tuple of (is_valid, validation_info)
        """
        if not self._client:
            return False, {"error": "Client not connected"}

        try:
            # Try to get authentication info
            auth_info = await self._client.security.get_user()

            # Get the effective authentication method
            auth_method = self.config.get_effective_auth_method()

            validation_info = {
                "auth_method": auth_method,
                "authenticated": True,
                "user_count": len(auth_info) if auth_info else 0,
                "validation_timestamp": datetime.now().isoformat(),
            }

            # Add method-specific validation info
            if auth_method == "api_key":
                try:
                    api_key_info = await self._client.security.get_api_key()
                    validation_info["api_key_count"] = len(api_key_info.get("api_keys", []))
                except Exception:
                    # API key info might not be accessible
                    validation_info["api_key_accessible"] = False

            self.logger.debug("Credential validation successful", extra=validation_info)
            return True, validation_info

        except AuthenticationException as e:
            validation_info = {
                "authenticated": False,
                "auth_method": self.config.get_effective_auth_method(),
                "error": str(e),
                "validation_timestamp": datetime.now().isoformat(),
            }
            self.logger.warning("Credential validation failed", extra=validation_info)
            return False, validation_info

        except Exception as e:
            # For other exceptions, we can't determine auth status conclusively
            validation_info = {
                "authenticated": "unknown",
                "auth_method": self.config.get_effective_auth_method(),
                "error": str(e),
                "validation_timestamp": datetime.now().isoformat(),
            }
            self.logger.debug("Credential validation inconclusive", extra=validation_info)
            return True, validation_info  # Assume valid if we can't determine otherwise

    async def get_cluster_health(self, timeout: str = "30s") -> dict[str, Any]:
        """
        Get comprehensive cluster health information.

        Args:
            timeout: Timeout for the health check request

        Returns:
            Dictionary containing detailed cluster health metrics

        Raises:
            ElasticsearchConnectionError: If not connected or request fails
        """
        if not self._client:
            raise ElasticsearchConnectionError("Client not connected")

        try:
            async def health_operation() -> tuple[dict[str, Any], dict[str, Any]]:
                client = cast(AsyncElasticsearch, self._client)
                # Get basic cluster health
                health_response = await client.cluster.health(timeout=timeout)
                health = cast(dict[str, Any], health_response)

                # Get cluster stats for additional metrics
                stats_response = await client.cluster.stats()
                stats = cast(dict[str, Any], stats_response)

                return health, stats

            health, stats = await self._execute_with_resilience(
                health_operation,
                "get_cluster_health",
                use_circuit_breaker=True,
                use_retry=True
            )

            # Calculate health score (0-100)
            health_score = self._calculate_health_score(health, stats)

            health_info = {
                "cluster_name": health.get("cluster_name"),
                "status": health.get("status"),
                "timed_out": health.get("timed_out", False),
                "number_of_nodes": health.get("number_of_nodes", 0),
                "number_of_data_nodes": health.get("number_of_data_nodes", 0),
                "active_primary_shards": health.get("active_primary_shards", 0),
                "active_shards": health.get("active_shards", 0),
                "relocating_shards": health.get("relocating_shards", 0),
                "initializing_shards": health.get("initializing_shards", 0),
                "unassigned_shards": health.get("unassigned_shards", 0),
                "delayed_unassigned_shards": health.get("delayed_unassigned_shards", 0),
                "number_of_pending_tasks": health.get("number_of_pending_tasks", 0),
                "number_of_in_flight_fetch": health.get("number_of_in_flight_fetch", 0),
                "task_max_waiting_in_queue_millis": health.get("task_max_waiting_in_queue_millis", 0),
                "active_shards_percent_as_number": health.get("active_shards_percent_as_number", 0.0),
                "health_score": health_score,
                "timestamp": datetime.now().isoformat(),
            }

            # Add cluster-wide statistics
            if stats and "indices" in stats:
                indices_info = stats["indices"]
                health_info.update({
                    "total_indices": indices_info.get("count", 0),
                    "total_documents": indices_info.get("docs", {}).get("count", 0),
                    "total_size_bytes": indices_info.get("store", {}).get("size_in_bytes", 0),
                    "total_fields": indices_info.get("fielddata", {}).get("fields", {}).get("count", 0),
                })

            # Add node information
            if stats and "nodes" in stats:
                nodes_info = stats["nodes"]
                health_info.update({
                    "node_versions": list(nodes_info.get("versions", [])),
                    "node_os_info": nodes_info.get("os", {}),
                    "node_process_info": nodes_info.get("process", {}),
                    "node_jvm_info": nodes_info.get("jvm", {}),
                })

            self.logger.debug("Cluster health check completed", extra=health_info)
            return health_info

        except (RetryableElasticsearchError, CircuitBreakerOpenError):
            # These are already properly formatted errors from our resilience layer
            raise
        except Exception as e:
            error_msg = f"Failed to get cluster health: {str(e)}"
            self.logger.error(error_msg, extra={"error": str(e)})
            raise ElasticsearchConnectionError(error_msg, e) from e

    def _calculate_health_score(self, health: dict[str, Any], stats: dict[str, Any] | None = None) -> float:
        """
        Calculate a comprehensive health score (0-100) based on cluster metrics.

        Args:
            health: Cluster health response
            stats: Cluster stats response (optional)

        Returns:
            Health score as float (0-100)
        """
        score = 100.0

        # Status scoring (most important factor)
        status = health.get("status", "red").lower()
        if status == "red":
            score -= 50.0  # Major penalty for red status
        elif status == "yellow":
            score -= 20.0  # Moderate penalty for yellow status
        # Green status gets no penalty

        # Shard allocation scoring
        total_shards = health.get("active_shards", 0) + health.get("unassigned_shards", 0)
        if total_shards > 0:
            unassigned_ratio = health.get("unassigned_shards", 0) / total_shards
            score -= unassigned_ratio * 30.0  # Up to 30 point penalty for unassigned shards

        # Relocating shards penalty
        relocating_shards = health.get("relocating_shards", 0)
        if relocating_shards > 0:
            score -= min(relocating_shards * 2.0, 10.0)  # Up to 10 point penalty

        # Initializing shards penalty (less severe)
        initializing_shards = health.get("initializing_shards", 0)
        if initializing_shards > 0:
            score -= min(initializing_shards * 1.0, 5.0)  # Up to 5 point penalty

        # Pending tasks penalty
        pending_tasks = health.get("number_of_pending_tasks", 0)
        if pending_tasks > 0:
            score -= min(pending_tasks * 0.5, 5.0)  # Up to 5 point penalty

        # Timeout penalty
        if health.get("timed_out", False):
            score -= 10.0

        # Node availability scoring
        expected_nodes = health.get("number_of_nodes", 1)
        data_nodes = health.get("number_of_data_nodes", 1)
        if expected_nodes > 0:
            node_ratio = data_nodes / expected_nodes
            if node_ratio < 0.5:
                score -= 15.0  # Significant penalty if less than half nodes available
            elif node_ratio < 0.8:
                score -= 5.0   # Minor penalty for reduced nodes

        # Ensure score stays within bounds
        return max(0.0, min(100.0, score))

    async def get_cluster_stats(self) -> dict[str, Any]:
        """
        Get detailed cluster statistics.

        Returns:
            Dictionary containing cluster statistics

        Raises:
            ElasticsearchConnectionError: If not connected or request fails
        """
        if not self._client:
            raise ElasticsearchConnectionError("Client not connected")

        try:
            stats = await self._client.cluster.stats()

            # Extract key metrics and format them
            formatted_stats = {
                "cluster_name": stats.get("cluster_name"),
                "cluster_uuid": stats.get("cluster_uuid"),
                "timestamp": datetime.now().isoformat(),
                "status": stats.get("status"),

                # Node information
                "nodes": {
                    "count": stats.get("nodes", {}).get("count", {}),
                    "versions": stats.get("nodes", {}).get("versions", []),
                    "os": stats.get("nodes", {}).get("os", {}),
                    "process": stats.get("nodes", {}).get("process", {}),
                    "jvm": stats.get("nodes", {}).get("jvm", {}),
                    "fs": stats.get("nodes", {}).get("fs", {}),
                    "plugins": stats.get("nodes", {}).get("plugins", []),
                    "network_types": stats.get("nodes", {}).get("network_types", {}),
                },

                # Indices information
                "indices": {
                    "count": stats.get("indices", {}).get("count", 0),
                    "shards": stats.get("indices", {}).get("shards", {}),
                    "docs": stats.get("indices", {}).get("docs", {}),
                    "store": stats.get("indices", {}).get("store", {}),
                    "fielddata": stats.get("indices", {}).get("fielddata", {}),
                    "query_cache": stats.get("indices", {}).get("query_cache", {}),
                    "completion": stats.get("indices", {}).get("completion", {}),
                    "segments": stats.get("indices", {}).get("segments", {}),
                },
            }

            self.logger.debug("Cluster stats retrieved", extra={
                "node_count": formatted_stats["nodes"]["count"],
                "indices_count": formatted_stats["indices"]["count"],
            })

            return formatted_stats

        except Exception as e:
            error_msg = f"Failed to get cluster stats: {str(e)}"
            self.logger.error(error_msg, extra={"error": str(e)})
            raise ElasticsearchConnectionError(error_msg, e) from e

    async def get_node_info(self, node_id: str | None = None) -> dict[str, Any]:
        """
        Get information about cluster nodes.

        Args:
            node_id: Specific node ID to query (None for all nodes)

        Returns:
            Dictionary containing node information

        Raises:
            ElasticsearchConnectionError: If not connected or request fails
        """
        if not self._client:
            raise ElasticsearchConnectionError("Client not connected")

        try:
            # Get node info
            if node_id:
                nodes_info = await self._client.nodes.info(node_id=node_id)
            else:
                nodes_info = await self._client.nodes.info()

            # Get node stats for performance metrics
            if node_id:
                nodes_stats = await self._client.nodes.stats(node_id=node_id)
            else:
                nodes_stats = await self._client.nodes.stats()

            # Combine info and stats
            combined_info = {
                "cluster_name": nodes_info.get("cluster_name"),
                "timestamp": datetime.now().isoformat(),
                "nodes": {},
            }

            nodes = nodes_info.get("nodes", {})
            stats_nodes = nodes_stats.get("nodes", {})

            for node_id_key, node_data in nodes.items():
                node_stats = stats_nodes.get(node_id_key, {})

                combined_info["nodes"][node_id_key] = {
                    "name": node_data.get("name"),
                    "transport_address": node_data.get("transport_address"),
                    "host": node_data.get("host"),
                    "ip": node_data.get("ip"),
                    "version": node_data.get("version"),
                    "build_hash": node_data.get("build_hash"),
                    "roles": node_data.get("roles", []),
                    "attributes": node_data.get("attributes", {}),

                    # Operating system info
                    "os": node_data.get("os", {}),

                    # JVM info
                    "jvm": node_data.get("jvm", {}),

                    # Process info
                    "process": node_data.get("process", {}),

                    # Performance stats (if available)
                    "stats": {
                        "indices": node_stats.get("indices", {}),
                        "os": node_stats.get("os", {}),
                        "process": node_stats.get("process", {}),
                        "jvm": node_stats.get("jvm", {}),
                        "thread_pool": node_stats.get("thread_pool", {}),
                        "fs": node_stats.get("fs", {}),
                        "transport": node_stats.get("transport", {}),
                        "http": node_stats.get("http", {}),
                    } if node_stats else {},
                }

            self.logger.debug("Node info retrieved", extra={
                "node_count": len(combined_info["nodes"]),
                "requested_node": node_id,
            })

            return combined_info

        except Exception as e:
            error_msg = f"Failed to get node info: {str(e)}"
            self.logger.error(error_msg, extra={"error": str(e), "node_id": node_id})
            raise ElasticsearchConnectionError(error_msg, e) from e

    async def check_indices_health(self, index_pattern: str | None = None) -> dict[str, Any]:
        """
        Check health status of indices.

        Args:
            index_pattern: Index pattern to check (None for all indices)

        Returns:
            Dictionary containing indices health information

        Raises:
            ElasticsearchConnectionError: If not connected or request fails
        """
        if not self._client:
            raise ElasticsearchConnectionError("Client not connected")

        try:
            # Get indices stats
            if index_pattern:
                indices_stats = await self._client.indices.stats(index=index_pattern)
            else:
                indices_stats = await self._client.indices.stats()

            # Get indices health from cluster health API
            health_response = await self._client.cluster.health(
                index=index_pattern,
                level="indices"
            )

            indices_health = {
                "timestamp": datetime.now().isoformat(),
                "overall_status": health_response.get("status"),
                "indices": {},
                "summary": {
                    "total_indices": 0,
                    "green_indices": 0,
                    "yellow_indices": 0,
                    "red_indices": 0,
                    "total_shards": health_response.get("active_shards", 0),
                    "unassigned_shards": health_response.get("unassigned_shards", 0),
                },
            }

            # Process indices from health response
            indices = health_response.get("indices", {})
            indices_health["summary"]["total_indices"] = len(indices)

            for index_name, index_health in indices.items():
                status = index_health.get("status", "unknown")

                # Count by status
                if status == "green":
                    indices_health["summary"]["green_indices"] += 1
                elif status == "yellow":
                    indices_health["summary"]["yellow_indices"] += 1
                elif status == "red":
                    indices_health["summary"]["red_indices"] += 1

                # Get stats for this index
                index_stats = indices_stats.get("indices", {}).get(index_name, {})

                indices_health["indices"][index_name] = {
                    "status": status,
                    "number_of_shards": index_health.get("number_of_shards", 0),
                    "number_of_replicas": index_health.get("number_of_replicas", 0),
                    "active_primary_shards": index_health.get("active_primary_shards", 0),
                    "active_shards": index_health.get("active_shards", 0),
                    "relocating_shards": index_health.get("relocating_shards", 0),
                    "initializing_shards": index_health.get("initializing_shards", 0),
                    "unassigned_shards": index_health.get("unassigned_shards", 0),

                    # Add stats information if available
                    "stats": {
                        "docs": index_stats.get("total", {}).get("docs", {}),
                        "store": index_stats.get("total", {}).get("store", {}),
                        "indexing": index_stats.get("total", {}).get("indexing", {}),
                        "search": index_stats.get("total", {}).get("search", {}),
                        "segments": index_stats.get("total", {}).get("segments", {}),
                    } if index_stats else {},
                }

            self.logger.debug("Indices health check completed", extra={
                "total_indices": indices_health["summary"]["total_indices"],
                "overall_status": indices_health["overall_status"],
                "green_indices": indices_health["summary"]["green_indices"],
                "yellow_indices": indices_health["summary"]["yellow_indices"],
                "red_indices": indices_health["summary"]["red_indices"],
            })

            return indices_health

        except Exception as e:
            error_msg = f"Failed to check indices health: {str(e)}"
            self.logger.error(error_msg, extra={"error": str(e), "index_pattern": index_pattern})
            raise ElasticsearchConnectionError(error_msg, e) from e

    def _start_cleanup_task(self) -> None:
        """Start the connection cleanup background task."""
        if self._cleanup_task is None or self._cleanup_task.done():
            self._cleanup_task = asyncio.create_task(self._connection_cleanup_worker())

    async def _connection_cleanup_worker(self) -> None:
        """Background worker for connection pool cleanup and monitoring."""
        cleanup_interval = min(self.config.connection_max_age / 4, 60.0)  # Check every 1/4 of max age or 60s

        while not self._shutdown_event.is_set():
            try:
                # Wait for cleanup interval or shutdown signal
                try:
                    await asyncio.wait_for(self._shutdown_event.wait(), timeout=cleanup_interval)
                    # Shutdown requested
                    break
                except TimeoutError:
                    # Continue with cleanup
                    pass

                await self._perform_connection_cleanup()

            except Exception as e:
                self.logger.warning(
                    "Error in connection cleanup worker",
                    extra={"error": str(e)}
                )
                # Continue running despite errors
                await asyncio.sleep(cleanup_interval)

    async def _perform_connection_cleanup(self) -> None:
        """Perform connection cleanup based on max age and idle time."""
        if not self._connection_created_time or not self.config.enable_connection_pooling:
            return

        current_time = time.time()
        connection_age = current_time - self._connection_created_time

        # Check if connection exceeds maximum age
        if connection_age > self.config.connection_max_age:
            self.logger.info(
                "Connection exceeded maximum age, initiating reconnection",
                extra={
                    "connection_age": connection_age,
                    "max_age": self.config.connection_max_age,
                    "pool_stats": self._pool_stats,
                }
            )

            # Reconnect to refresh the connection
            await self._reconnect_client()

        # Update cleanup timestamp
        self._pool_stats["last_cleanup"] = current_time

    async def _reconnect_client(self) -> None:
        """Reconnect the client to refresh the connection pool."""
        async with self._connection_lock:
            if self._client is not None:
                try:
                    # Close existing connection
                    await self._client.close()
                    self._pool_stats["connections_closed"] += 1

                    # Create new connection with same parameters
                    # The connect method will handle setting up the new client
                    self._client = None

                    # Reconnect
                    await self.connect()

                    self.logger.info(
                        "Successfully reconnected to Elasticsearch",
                        extra={"pool_stats": self._pool_stats}
                    )

                except Exception as e:
                    self.logger.error(
                        "Failed to reconnect client",
                        extra={"error": str(e)}
                    )
                    # Don't raise - let the circuit breaker handle failures

    async def get_connection_pool_stats(self) -> dict[str, Any]:
        """
        Get connection pool statistics and health metrics.

        Returns:
            Dictionary containing pool statistics
        """
        current_time = time.time()

        stats = {
            **self._pool_stats,
            "config": {
                "pool_maxsize": self.config.pool_maxsize,
                "pool_connections": self.config.pool_connections,
                "connection_timeout": self.config.connection_timeout,
                "keepalive_timeout": self.config.keepalive_timeout,
                "connection_max_age": self.config.connection_max_age,
                "enable_pooling": self.config.enable_connection_pooling,
            },
            "current_connection": {
                "connected": self.is_connected,
                "age_seconds": (current_time - self._connection_created_time) if self._connection_created_time else 0,
                "created_at": self._connection_created_time,
            },
            "health": {
                "circuit_breaker_state": self.circuit_breaker_state,
                "cleanup_task_running": self._cleanup_task is not None and not self._cleanup_task.done(),
                "last_cleanup_age": current_time - self._pool_stats["last_cleanup"] if self._pool_stats["last_cleanup"] > 0 else None,
            },
            "timestamp": current_time,
        }

        return stats

    async def search_logs(self, query: "LogSearchQuery") -> "LogSearchResult":
        """
        Search syslog entries using Elasticsearch with comprehensive filtering.

        Args:
            query: LogSearchQuery model with search parameters

        Returns:
            LogSearchResult containing matching logs and metadata

        Raises:
            ElasticsearchConnectionError: If not connected or request fails
            ElasticsearchQueryError: If query is malformed
            ElasticsearchTimeoutError: If query times out
        """
        if not self._client:
            raise ElasticsearchConnectionError("Client not connected")

        # Import here to avoid circular import
        from ..models.response import ExecutionMetrics, LogSearchResult, ResponseStatus

        start_time = time.time()

        try:
            # Build Elasticsearch query
            es_query = self._build_search_query(query)

            async def search_operation() -> dict[str, Any]:
                client = cast(AsyncElasticsearch, self._client)
                response = await client.search(
                    index="syslog-ng",  # Use the actual index name
                    body=es_query,
                    timeout="30s",
                    size=query.limit,
                    from_=query.offset,
                )
                return cast(dict[str, Any], response)

            # Execute search with resilience
            response = await self._execute_with_resilience(
                search_operation,
                "search_logs",
                use_circuit_breaker=True,
                use_retry=True
            )

            # Parse response
            hits = response.get("hits", {})
            total_hits = hits.get("total", {}).get("value", 0)
            documents = hits.get("hits", [])

            # Convert documents to LogEntry models
            logs = []
            for doc in documents:
                try:
                    log_entry = self._parse_elasticsearch_hit(doc)
                    logs.append(log_entry)
                except Exception as e:
                    self.logger.warning(
                        "Failed to parse log entry",
                        extra={"doc_id": doc.get("_id"), "error": str(e)}
                    )
                    continue

            # Calculate execution metrics
            execution_time = round((time.time() - start_time) * 1000)  # Convert to ms and round to int
            took_ms = response.get("took", 0)

            # Get shard info from response
            shards = response.get("_shards", {})
            shards_total = shards.get("total", 1)
            shards_successful = shards.get("successful", 1)
            shards_failed = shards.get("failed", 0)
            timed_out = response.get("timed_out", False)
            
            metrics = ExecutionMetrics(
                execution_time_ms=execution_time,
                query_time_ms=took_ms,
                documents_examined=total_hits,
                documents_returned=len(logs),
                shards_total=shards_total,
                shards_successful=shards_successful,
                shards_failed=shards_failed,
                timed_out=timed_out
            )

            # Create result
            # Calculate next offset if there are more results
            next_offset = query.offset + len(logs) if (query.offset + len(logs)) < total_hits else None
            max_score = hits.get("max_score")
            
            result = LogSearchResult(
                status=ResponseStatus.SUCCESS,
                total_hits=total_hits,
                logs=logs,
                offset=query.offset,
                limit=query.limit,
                has_more=(query.offset + len(logs)) < total_hits,
                metrics=metrics,
                max_score=max_score,
                next_offset=next_offset,
                scroll_id=None,  # Not using scroll in this implementation
                query_explanation=None  # Add if explain is requested in future
            )

            self.logger.debug(
                "Search completed successfully",
                extra={
                    "total_hits": total_hits,
                    "returned": len(logs),
                    "execution_time_ms": execution_time,
                    "query_time_ms": took_ms
                }
            )

            return result

        except Exception as e:
            execution_time = round((time.time() - start_time) * 1000)  # Convert to ms and round to int

            # Create error result with metrics
            metrics = ExecutionMetrics(
                execution_time_ms=execution_time,
                query_time_ms=0,
                documents_examined=0,
                documents_returned=0,
                shards_total=1,
                shards_successful=0,
                shards_failed=1,
                timed_out=False
            )

            if isinstance(e, RetryableElasticsearchError | CircuitBreakerOpenError):
                # These are already properly formatted
                raise
            elif "timeout" in str(e).lower():
                from ..exceptions import ElasticsearchTimeoutError
                raise ElasticsearchTimeoutError(
                    f"Search query timed out: {str(e)}",
                    original_error=e,
                    operation="search_logs",
                    timeout_seconds=30.0,
                    context={"timeout_ms": 30000}
                ) from e
            elif "parsing_exception" in str(e).lower() or "illegal_argument" in str(e).lower():
                from ..exceptions import ElasticsearchQueryError
                raise ElasticsearchQueryError(
                    f"Invalid search query: {str(e)}",
                    original_error=e,
                    query=es_query,
                    index="syslog-ng"
                ) from e
            else:
                error_msg = f"Search failed: {str(e)}"
                self.logger.error(error_msg, extra={"error": str(e)})
                raise ElasticsearchConnectionError(error_msg, e) from e

    def _build_search_query(self, query: "LogSearchQuery") -> dict[str, Any]:
        """
        Build Elasticsearch query from LogSearchQuery model.

        Args:
            query: Search query parameters

        Returns:
            Elasticsearch query dictionary
        """
        es_query: dict[str, Any] = {
            "query": {
                "bool": {
                    "must": [],
                    "filter": [],
                    "must_not": []
                }
            },
            "sort": [{
                query.sort_field: {
                    "order": query.sort_order.value.lower()
                }
            }]
        }

        # Add text search query if provided
        if query.query_string:
            es_query["query"]["bool"]["must"].append({
                "multi_match": {
                    "query": query.query_string,
                    "fields": ["message", "program", "tag"],
                    "type": "best_fields",
                    "fuzziness": "AUTO"
                }
            })

        # Add time range filter
        if query.time_range:
            time_filter: dict[str, dict[str, dict[str, str]]] = {"range": {"timestamp": {}}}
            if query.time_range.start:
                time_filter["range"]["timestamp"]["gte"] = query.time_range.start.isoformat()
            if query.time_range.end:
                time_filter["range"]["timestamp"]["lte"] = query.time_range.end.isoformat()
            es_query["query"]["bool"]["filter"].append(time_filter)

        # Add field filters
        for filter_item in query.filters:
            if filter_item.operator == "eq":
                es_query["query"]["bool"]["filter"].append({
                    "term": {filter_item.field: filter_item.value}
                })
            elif filter_item.operator == "wildcard":
                es_query["query"]["bool"]["filter"].append({
                    "wildcard": {filter_item.field: filter_item.value}
                })
            elif filter_item.operator == "range":
                # Expect value to be a dict with gte/lte keys
                if isinstance(filter_item.value, dict):
                    es_query["query"]["bool"]["filter"].append({
                        "range": {filter_item.field: filter_item.value}
                    })
            elif filter_item.operator == "exists":
                es_query["query"]["bool"]["filter"].append({
                    "exists": {"field": filter_item.field}
                })

        # If no must conditions, use match_all
        if not es_query["query"]["bool"]["must"]:
            es_query["query"]["bool"]["must"].append({"match_all": {}})

        return es_query

    async def search_raw(
        self,
        query: dict[str, Any],
        index: str | None = None,
        timeout: str = "30s"
    ) -> dict[str, Any]:
        """
        Execute a raw Elasticsearch search query.

        Args:
            query: Raw Elasticsearch query dict
            index: Index to search (defaults to config.default_index)
            timeout: Query timeout

        Returns:
            Raw Elasticsearch response dict

        Raises:
            ElasticsearchConnectionError: If not connected or request fails
        """
        if not self._client:
            raise ElasticsearchConnectionError("Client not connected")

        search_index = index or self.config.default_index

        async def search_operation() -> dict[str, Any]:
            client = cast(AsyncElasticsearch, self._client)
            response = await client.search(
                index=search_index,
                body=query,
                timeout=timeout
            )
            return cast(dict[str, Any], response)

        try:
            response = await self._execute_with_resilience(
                search_operation,
                "raw_search",
                use_circuit_breaker=True,
                use_retry=True
            )
            return cast(dict[str, Any], response)
        except Exception as e:
            error_msg = f"Raw search query failed: {str(e)}"
            self.logger.error(error_msg, extra={
                "error": str(e),
                "query": query,
                "index": search_index
            })
            if "timeout" in str(e).lower():
                from ..exceptions import ElasticsearchTimeoutError
                raise ElasticsearchTimeoutError(
                    error_msg,
                    original_error=e,
                    query=query,
                    index=search_index
                ) from e
            else:
                from ..exceptions import ElasticsearchQueryError
                raise ElasticsearchQueryError(
                    error_msg,
                    original_error=e,
                    query=query,
                    index=search_index
                ) from e

    def _parse_elasticsearch_hit(self, hit: dict[str, Any]) -> "LogEntry":
        """
        Parse an Elasticsearch document hit into a LogEntry model.

        Args:
            hit: Elasticsearch document hit

        Returns:
            LogEntry model instance
        """
        # Import here to avoid circular import
        from ..models.log_entry import LogEntry, LogLevel

        source = hit.get("_source", {})

        # Parse log level, default to INFO if not found or invalid
        level_str = source.get("level", "INFO").upper()
        try:
            level = LogLevel(level_str)
        except ValueError:
            level = LogLevel.INFO

        # Create LogEntry with proper field mapping (using only valid fields)
        log_entry = LogEntry(
            timestamp=datetime.fromisoformat(source.get("timestamp", datetime.now().isoformat())),
            level=level,
            message=source.get("message", ""),
            device=source.get("device", source.get("hostname", "unknown")),
            process_id=source.get("pid", source.get("process_id")),
            process_name=source.get("process_name"),
            facility=source.get("facility"),
            source_ip=None,  # Optional field, not available in this context
            metadata=source.get("metadata", {}),
            index_name=hit.get("_index")  # Get index name from hit metadata
        )

        return log_entry

    async def get_resilience_metrics(self) -> dict[str, Any]:
        """
        Get metrics about retry and circuit breaker status.

        Returns:
            Dictionary containing resilience metrics
        """
        return {
            "circuit_breaker": {
                "state": self._circuit_breaker.state,
                "failure_count": self._circuit_breaker.failure_count,
                "failure_threshold": self._circuit_breaker.failure_threshold,
                "reset_timeout": self._circuit_breaker.reset_timeout,
                "half_open_max_calls": self._circuit_breaker.half_open_max_calls,
            },
            "retry_manager": {
                "max_retries": self._retry_manager.max_retries,
                "initial_delay": self._retry_manager.initial_delay,
                "max_delay": self._retry_manager.max_delay,
                "backoff_multiplier": self._retry_manager.backoff_multiplier,
                "jitter_enabled": self._retry_manager.jitter,
            },
            "timestamp": datetime.now().isoformat(),
        }

    def __repr__(self) -> str:
        """String representation of the client."""
        status = "connected" if self.is_connected else "disconnected"
        cb_state = self._circuit_breaker.state
        pooling = "enabled" if self.config.enable_connection_pooling else "disabled"
        active_connections = self._pool_stats["active_connections"]
        return f"ElasticsearchClient(hosts={self.config.hosts}, status={status}, circuit_breaker={cb_state}, pooling={pooling}, active={active_connections})"


@asynccontextmanager
async def create_elasticsearch_client(
    config: ElasticsearchConfig | None = None,
) -> AsyncGenerator[ElasticsearchClient, None]:
    """
    Create an Elasticsearch client as an async context manager.

    Args:
        config: Optional configuration. If None, loads from environment.

    Yields:
        Connected ElasticsearchClient instance
    """
    client = ElasticsearchClient(config)
    try:
        await client.connect()
        yield client
    finally:
        await client.disconnect()
