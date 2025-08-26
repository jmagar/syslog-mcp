"""
Focused unit tests for ElasticsearchClient core functionality.

This focuses on testable components without environment dependencies.
"""

import asyncio
import time
from datetime import datetime, timezone
from unittest.mock import AsyncMock, Mock, patch

import pytest
from elasticsearch.exceptions import (
    AuthenticationException,
    ConnectionError,
    NotFoundError,
    TransportError,
)

from syslog_mcp.exceptions import (
    CircuitBreakerOpenError,
    ElasticsearchAuthenticationError,
    ElasticsearchConnectionError,
    RetryableElasticsearchError,
)
from syslog_mcp.models.log_entry import LogEntry, LogLevel
from syslog_mcp.models.query import LogSearchQuery, TimeRange
from syslog_mcp.services.elasticsearch_client import (
    CircuitBreaker,
    ElasticsearchClient,
    ElasticsearchConfig,
    RetryManager,
)


class TestCircuitBreaker:
    """Test circuit breaker functionality."""
    
    def test_circuit_breaker_initialization(self):
        """Test circuit breaker initialization."""
        cb = CircuitBreaker(
            failure_threshold=3,
            reset_timeout=60.0,
            half_open_max_calls=2
        )
        assert cb.state == "closed"
        assert cb.failure_count == 0
        
    @pytest.mark.asyncio
    async def test_circuit_breaker_closed_success(self):
        """Test successful call in closed state."""
        cb = CircuitBreaker(failure_threshold=3, reset_timeout=60.0)
        
        mock_func = AsyncMock(return_value="success")
        result = await cb.call(mock_func)
        
        assert result == "success"
        assert cb.state == "closed"
        assert cb.failure_count == 0
        
    @pytest.mark.asyncio
    async def test_circuit_breaker_failure_tracking(self):
        """Test failure tracking in closed state."""
        cb = CircuitBreaker(failure_threshold=2, reset_timeout=60.0)
        
        mock_func = AsyncMock(side_effect=ConnectionError("Connection failed"))
        
        # First failure
        with pytest.raises(ConnectionError):
            await cb.call(mock_func)
        assert cb.state == "closed"
        assert cb.failure_count == 1
        
        # Second failure - should open circuit
        with pytest.raises(ConnectionError):
            await cb.call(mock_func)
        assert cb.state == "open"
        assert cb.failure_count == 2
        
    @pytest.mark.asyncio
    async def test_circuit_breaker_open_state(self):
        """Test circuit breaker in open state."""
        cb = CircuitBreaker(failure_threshold=1, reset_timeout=0.1)
        
        # Force circuit to open
        mock_func = AsyncMock(side_effect=ConnectionError("Connection failed"))
        with pytest.raises(ConnectionError):
            await cb.call(mock_func)
        
        assert cb.state == "open"
        
        # Should immediately raise CircuitBreakerOpenError
        with pytest.raises(CircuitBreakerOpenError):
            await cb.call(mock_func)
            
    @pytest.mark.asyncio 
    async def test_circuit_breaker_half_open_transition(self):
        """Test transition from open to half-open state."""
        cb = CircuitBreaker(failure_threshold=1, reset_timeout=0.01)
        
        # Force circuit to open
        mock_func = AsyncMock(side_effect=ConnectionError("Connection failed"))
        with pytest.raises(ConnectionError):
            await cb.call(mock_func)
        assert cb.state == "open"
        
        # Wait for reset timeout
        await asyncio.sleep(0.02)
        
        # Next call should transition to half-open
        mock_func.side_effect = None
        mock_func.return_value = "success"
        result = await cb.call(mock_func)
        
        assert result == "success"
        assert cb.state == "closed"  # Should close after successful call


class TestRetryManager:
    """Test retry manager functionality."""
    
    def test_retry_manager_initialization(self):
        """Test retry manager initialization."""
        rm = RetryManager(
            max_retries=3,
            initial_delay=1.0,
            max_delay=60.0,
            backoff_multiplier=2.0,
            jitter=True
        )
        assert rm.max_retries == 3
        assert rm.initial_delay == 1.0
        assert rm.max_delay == 60.0
        
    def test_calculate_delay(self):
        """Test delay calculation with backoff."""
        rm = RetryManager(
            max_retries=3,
            initial_delay=1.0,
            max_delay=10.0,
            backoff_multiplier=2.0,
            jitter=False
        )
        
        assert rm._calculate_delay(0) == 1.0
        assert rm._calculate_delay(1) == 2.0
        assert rm._calculate_delay(2) == 4.0
        assert rm._calculate_delay(3) == 8.0
        assert rm._calculate_delay(4) == 10.0  # Max delay cap
        
    def test_calculate_delay_with_jitter(self):
        """Test delay calculation with jitter."""
        rm = RetryManager(
            max_retries=3,
            initial_delay=1.0,
            max_delay=10.0,
            backoff_multiplier=2.0,
            jitter=True
        )
        
        delay1 = rm._calculate_delay(1)
        delay2 = rm._calculate_delay(1)
        
        # With jitter, delays should vary
        # Both should be around 2.0 but slightly different
        assert 1.0 <= delay1 <= 3.0
        assert 1.0 <= delay2 <= 3.0
        
    def test_is_retryable_error(self):
        """Test retryable error detection."""
        rm = RetryManager(max_retries=3)
        
        # Retryable errors
        assert rm._is_retryable_error(ConnectionError("Connection lost"))
        assert rm._is_retryable_error(TransportError("Timeout"))
        
        # Non-retryable errors
        assert not rm._is_retryable_error(AuthenticationException("Invalid credentials"))
        assert not rm._is_retryable_error(NotFoundError("Index not found", {}, {}))
        
    @pytest.mark.asyncio
    async def test_retry_success_on_first_attempt(self):
        """Test successful execution on first attempt."""
        rm = RetryManager(max_retries=3)
        
        mock_func = AsyncMock(return_value="success")
        result = await rm.execute_with_retry("test_op", mock_func)
        
        assert result == "success"
        mock_func.assert_called_once()
        
    @pytest.mark.asyncio
    async def test_retry_success_after_failures(self):
        """Test successful execution after retries."""
        rm = RetryManager(max_retries=3, initial_delay=0.01)
        
        mock_func = AsyncMock(side_effect=[
            ConnectionError("Temp failure 1"),
            ConnectionError("Temp failure 2"), 
            "success"
        ])
        
        result = await rm.execute_with_retry("test_op", mock_func)
        
        assert result == "success"
        assert mock_func.call_count == 3
        
    @pytest.mark.asyncio
    async def test_retry_exhausted(self):
        """Test retry exhaustion with final failure."""
        rm = RetryManager(max_retries=2, initial_delay=0.01)
        
        mock_func = AsyncMock(side_effect=ConnectionError("Persistent failure"))
        
        with pytest.raises(ConnectionError, match="Persistent failure"):
            await rm.execute_with_retry("test_op", mock_func)
            
        assert mock_func.call_count == 3  # Initial + 2 retries
        
    @pytest.mark.asyncio
    async def test_non_retryable_error_immediate_failure(self):
        """Test immediate failure for non-retryable errors."""
        rm = RetryManager(max_retries=3, initial_delay=0.01)
        
        mock_func = AsyncMock(side_effect=AuthenticationException("Invalid auth"))
        
        with pytest.raises(AuthenticationException):
            await rm.execute_with_retry("test_op", mock_func)
            
        mock_func.assert_called_once()  # Should not retry


class TestElasticsearchClientCore:
    """Test core ElasticsearchClient functionality."""
    
    def test_client_initialization(self):
        """Test client initialization."""
        client = ElasticsearchClient()
        
        assert client.config is not None
        assert client._client is None
        assert not client.is_connected()
        
    def test_circuit_breaker_properties(self):
        """Test circuit breaker state properties."""
        client = ElasticsearchClient()
        
        assert client.circuit_breaker_state == "closed"
        assert client.circuit_breaker_failure_count == 0
        
    def test_client_property_when_not_connected(self):
        """Test client property access when not connected."""
        client = ElasticsearchClient()
        
        with pytest.raises(ElasticsearchConnectionError, match="not connected"):
            _ = client.client
            
    def test_client_property_when_connected(self):
        """Test client property access when connected."""
        with patch('syslog_mcp.services.elasticsearch_client.AsyncElasticsearch') as mock_es:
            mock_instance = AsyncMock()
            mock_es.return_value = mock_instance
            
            client = ElasticsearchClient()
            client._client = mock_instance
            client._connected = True
            
            assert client.client == mock_instance
            
    @pytest.mark.asyncio
    async def test_ping_success(self):
        """Test successful ping operation."""
        with patch('syslog_mcp.services.elasticsearch_client.AsyncElasticsearch') as mock_es:
            mock_instance = AsyncMock()
            mock_instance.ping.return_value = True
            mock_es.return_value = mock_instance
            
            client = ElasticsearchClient()
            client._client = mock_instance
            client._connected = True
            
            result = await client.ping()
            assert result is True
            
    @pytest.mark.asyncio
    async def test_ping_failure(self):
        """Test ping operation failure."""
        with patch('syslog_mcp.services.elasticsearch_client.AsyncElasticsearch') as mock_es:
            mock_instance = AsyncMock()
            mock_instance.ping.return_value = False
            mock_es.return_value = mock_instance
            
            client = ElasticsearchClient()
            client._client = mock_instance
            client._connected = True
            
            result = await client.ping()
            assert result is False
            
    @pytest.mark.asyncio
    async def test_ping_not_connected(self):
        """Test ping when not connected."""
        client = ElasticsearchClient()
        
        result = await client.ping()
        assert result is False
        
    @pytest.mark.asyncio
    async def test_connect_success(self):
        """Test successful connection."""
        with patch('syslog_mcp.services.elasticsearch_client.AsyncElasticsearch') as mock_es:
            mock_instance = AsyncMock()
            mock_instance.ping.return_value = True
            mock_instance.info.return_value = {"version": {"number": "8.0.0"}}
            mock_es.return_value = mock_instance
            
            client = ElasticsearchClient()
            await client.connect()
            
            assert client.is_connected()
            mock_instance.ping.assert_called_once()
            
    @pytest.mark.asyncio
    async def test_connect_authentication_error(self):
        """Test connection with authentication error."""
        with patch('syslog_mcp.services.elasticsearch_client.AsyncElasticsearch') as mock_es:
            mock_instance = AsyncMock()
            mock_instance.ping.side_effect = AuthenticationException("Invalid credentials")
            mock_es.return_value = mock_instance
            
            client = ElasticsearchClient()
            
            with pytest.raises(ElasticsearchAuthenticationError):
                await client.connect()
                
            assert not client.is_connected()
            
    @pytest.mark.asyncio
    async def test_connect_connection_error(self):
        """Test connection with general connection error."""
        with patch('syslog_mcp.services.elasticsearch_client.AsyncElasticsearch') as mock_es:
            mock_instance = AsyncMock()
            mock_instance.ping.side_effect = ConnectionError("Connection refused")
            mock_es.return_value = mock_instance
            
            client = ElasticsearchClient()
            
            with pytest.raises(ElasticsearchConnectionError):
                await client.connect()
                
            assert not client.is_connected()
            
    @pytest.mark.asyncio
    async def test_disconnect(self):
        """Test client disconnection."""
        with patch('syslog_mcp.services.elasticsearch_client.AsyncElasticsearch') as mock_es:
            mock_instance = AsyncMock()
            mock_instance.ping.return_value = True
            mock_instance.info.return_value = {"version": {"number": "8.0.0"}}
            mock_es.return_value = mock_instance
            
            client = ElasticsearchClient()
            await client.connect()
            assert client.is_connected()
            
            await client.disconnect()
            assert not client.is_connected()
            mock_instance.close.assert_called_once()
            
    @pytest.mark.asyncio
    async def test_disconnect_when_not_connected(self):
        """Test disconnect when already disconnected."""
        client = ElasticsearchClient()
        
        # Should not raise any errors
        await client.disconnect()
        assert not client.is_connected()
        
    @pytest.mark.asyncio
    async def test_get_cluster_info_success(self):
        """Test successful cluster info retrieval."""
        mock_info = {
            "name": "es-node-1",
            "cluster_name": "test-cluster",
            "version": {"number": "8.0.0"},
            "tagline": "You Know, for Search"
        }
        
        with patch('syslog_mcp.services.elasticsearch_client.AsyncElasticsearch') as mock_es:
            mock_instance = AsyncMock()
            mock_instance.info.return_value = mock_info
            mock_es.return_value = mock_instance
            
            client = ElasticsearchClient()
            client._client = mock_instance
            client._connected = True
            
            info = await client.get_cluster_info()
            assert info == mock_info
            mock_instance.info.assert_called_once()
            
    @pytest.mark.asyncio
    async def test_validate_credentials_success(self):
        """Test successful credential validation."""
        mock_info = {"name": "es-node-1", "cluster_name": "test-cluster"}
        
        with patch('syslog_mcp.services.elasticsearch_client.AsyncElasticsearch') as mock_es:
            mock_instance = AsyncMock()
            mock_instance.info.return_value = mock_info
            mock_es.return_value = mock_instance
            
            client = ElasticsearchClient()
            client._client = mock_instance
            client._connected = True
            
            is_valid, details = await client.validate_credentials()
            assert is_valid is True
            assert details == mock_info
            
    @pytest.mark.asyncio
    async def test_validate_credentials_auth_failure(self):
        """Test credential validation with authentication failure."""
        with patch('syslog_mcp.services.elasticsearch_client.AsyncElasticsearch') as mock_es:
            mock_instance = AsyncMock()
            mock_instance.info.side_effect = AuthenticationException("Invalid credentials")
            mock_es.return_value = mock_instance
            
            client = ElasticsearchClient()
            client._client = mock_instance
            client._connected = True
            
            is_valid, details = await client.validate_credentials()
            assert is_valid is False
            assert "authentication" in details["error"].lower()
            
    def test_calculate_health_score_green(self):
        """Test health score calculation for green status."""
        client = ElasticsearchClient()
        
        health = {
            "status": "green",
            "number_of_nodes": 3,
            "active_primary_shards": 10,
            "active_shards": 20,
            "relocating_shards": 0,
            "initializing_shards": 0,
            "unassigned_shards": 0
        }
        
        score = client._calculate_health_score(health)
        assert score >= 90  # Green should have high score
        
    def test_calculate_health_score_yellow(self):
        """Test health score calculation for yellow status."""
        client = ElasticsearchClient()
        
        health = {
            "status": "yellow",
            "number_of_nodes": 1,
            "active_primary_shards": 10,
            "active_shards": 10,
            "relocating_shards": 0,
            "initializing_shards": 0,
            "unassigned_shards": 10
        }
        
        score = client._calculate_health_score(health)
        assert 50 <= score < 90  # Yellow should have medium score
        
    def test_calculate_health_score_red(self):
        """Test health score calculation for red status."""
        client = ElasticsearchClient()
        
        health = {
            "status": "red",
            "number_of_nodes": 1,
            "active_primary_shards": 5,
            "active_shards": 5,
            "relocating_shards": 0,
            "initializing_shards": 0,
            "unassigned_shards": 15
        }
        
        score = client._calculate_health_score(health)
        assert score < 50  # Red should have low score
        
    def test_build_search_query_basic(self):
        """Test basic search query building."""
        query = LogSearchQuery(
            query="test message",
            time_range=TimeRange(
                start_time=datetime(2025, 1, 15, 10, 0, 0, tzinfo=timezone.utc),
                end_time=datetime(2025, 1, 15, 11, 0, 0, tzinfo=timezone.utc)
            ),
            size=50
        )
        
        client = ElasticsearchClient()
        es_query = client._build_search_query(query)
        
        assert es_query["size"] == 50
        assert "query" in es_query
        assert "sort" in es_query
        
        # Check time range filter
        bool_query = es_query["query"]["bool"]
        assert "filter" in bool_query
        
    def test_build_search_query_with_filters(self):
        """Test search query building with filters."""
        query = LogSearchQuery(
            query="error",
            device="test-device",
            program="test-program",
            level="ERROR",
            facility="syslog",
            size=25
        )
        
        client = ElasticsearchClient()
        es_query = client._build_search_query(query)
        
        assert es_query["size"] == 25
        
        # Should have term filters for device, program, level, facility
        bool_query = es_query["query"]["bool"]
        assert "filter" in bool_query
        
    def test_parse_elasticsearch_hit(self):
        """Test parsing Elasticsearch hit to LogEntry."""
        hit = {
            "_id": "test-id",
            "_source": {
                "timestamp": "2025-01-15T10:30:00Z",
                "device": "test-device", 
                "program": "test-program",
                "level": "INFO",
                "facility": "syslog",
                "message": "test message"
            }
        }
        
        client = ElasticsearchClient()
        log_entry = client._parse_elasticsearch_hit(hit)
        
        assert isinstance(log_entry, LogEntry)
        assert log_entry.device == "test-device"
        assert log_entry.program == "test-program"
        assert log_entry.level == LogLevel.INFO
        assert log_entry.facility == "syslog"
        assert log_entry.message == "test message"
        
    @pytest.mark.asyncio
    async def test_search_logs_success(self):
        """Test successful log search operation."""
        query = LogSearchQuery(
            query="test message",
            time_range=TimeRange(
                start_time=datetime.now(timezone.utc),
                end_time=datetime.now(timezone.utc)
            ),
            size=10
        )
        
        mock_response = {
            "hits": {
                "total": {"value": 1},
                "hits": [{
                    "_id": "1",
                    "_source": {
                        "timestamp": "2025-01-15T10:30:00Z",
                        "device": "test-device",
                        "program": "test-program", 
                        "level": "INFO",
                        "facility": "syslog",
                        "message": "test message"
                    }
                }]
            },
            "took": 5
        }
        
        with patch('syslog_mcp.services.elasticsearch_client.AsyncElasticsearch') as mock_es:
            mock_instance = AsyncMock()
            mock_instance.search.return_value = mock_response
            mock_es.return_value = mock_instance
            
            client = ElasticsearchClient()
            client._client = mock_instance
            client._connected = True
            
            result = await client.search_logs(query)
            
            assert result.total_hits == 1
            assert len(result.hits) == 1
            assert result.hits[0].device == "test-device"
            assert result.hits[0].message == "test message"
            assert result.execution_metrics.execution_time_ms == 5
            
    @pytest.mark.asyncio
    async def test_search_raw_success(self):
        """Test raw search operation."""
        mock_response = {
            "hits": {"total": {"value": 100}},
            "took": 10
        }
        
        with patch('syslog_mcp.services.elasticsearch_client.AsyncElasticsearch') as mock_es:
            mock_instance = AsyncMock()
            mock_instance.search.return_value = mock_response
            mock_es.return_value = mock_instance
            
            client = ElasticsearchClient()
            client._client = mock_instance
            client._connected = True
            
            result = await client.search_raw(
                index="test-index",
                body={"query": {"match_all": {}}}
            )
            
            assert result == mock_response
            mock_instance.search.assert_called_once()
            
    @pytest.mark.asyncio
    async def test_get_resilience_metrics(self):
        """Test resilience metrics collection."""
        client = ElasticsearchClient()
        
        metrics = await client.get_resilience_metrics()
        
        assert "circuit_breaker" in metrics
        assert "retry_manager" in metrics
        assert "connection_pool" in metrics
        
        # Circuit breaker metrics
        cb_metrics = metrics["circuit_breaker"]
        assert "state" in cb_metrics
        assert "failure_count" in cb_metrics
        
    def test_repr(self):
        """Test string representation."""
        client = ElasticsearchClient()
        
        repr_str = repr(client)
        assert "ElasticsearchClient" in repr_str
        assert "connected=False" in repr_str


class TestElasticsearchClientErrorHandling:
    """Test error handling scenarios."""
    
    @pytest.mark.asyncio
    async def test_execute_with_resilience_circuit_breaker_open(self):
        """Test operation when circuit breaker is open."""
        client = ElasticsearchClient()
        
        # Force circuit breaker to open state
        client._circuit_breaker._state = "open"
        client._circuit_breaker._last_failure_time = time.time()
        
        async def test_operation():
            return "success"
            
        with pytest.raises(CircuitBreakerOpenError):
            await client._execute_with_resilience("test", test_operation)
            
    @pytest.mark.asyncio
    async def test_execute_with_resilience_retry_exhausted(self):
        """Test operation with retry exhaustion."""
        client = ElasticsearchClient()
        client._retry_manager.max_retries = 1
        client._retry_manager.initial_delay = 0.01
        
        call_count = 0
        async def failing_operation():
            nonlocal call_count
            call_count += 1
            raise ConnectionError("Persistent failure")
            
        with pytest.raises(ConnectionError):
            await client._execute_with_resilience("test", failing_operation)
            
        assert call_count == 2  # Initial + 1 retry
        
    @pytest.mark.asyncio
    async def test_execute_with_resilience_success_after_retry(self):
        """Test successful operation after retries."""
        client = ElasticsearchClient()
        client._retry_manager.initial_delay = 0.01
        
        call_count = 0
        async def intermittent_operation():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise ConnectionError("Temporary failure")
            return "success"
            
        result = await client._execute_with_resilience("test", intermittent_operation)
        assert result == "success"
        assert call_count == 3


class TestElasticsearchClientIntegration:
    """Integration-style tests with realistic scenarios."""
    
    @pytest.mark.asyncio
    async def test_context_manager_success(self):
        """Test async context manager successful flow."""
        with patch('syslog_mcp.services.elasticsearch_client.AsyncElasticsearch') as mock_es:
            mock_instance = AsyncMock()
            mock_instance.ping.return_value = True
            mock_instance.info.return_value = {"version": {"number": "8.0.0"}}
            mock_es.return_value = mock_instance
            
            async with ElasticsearchClient() as client:
                assert client.is_connected()
                
            # Should disconnect on exit
            mock_instance.close.assert_called_once()
            
    @pytest.mark.asyncio 
    async def test_context_manager_with_exception(self):
        """Test async context manager with exception."""
        with patch('syslog_mcp.services.elasticsearch_client.AsyncElasticsearch') as mock_es:
            mock_instance = AsyncMock()
            mock_instance.ping.return_value = True
            mock_instance.info.return_value = {"version": {"number": "8.0.0"}}
            mock_es.return_value = mock_instance
            
            with pytest.raises(ValueError):
                async with ElasticsearchClient() as client:
                    assert client.is_connected()
                    raise ValueError("Test error")
                    
            # Should still disconnect on exception
            mock_instance.close.assert_called_once()
            
    @pytest.mark.asyncio
    async def test_full_connection_lifecycle(self):
        """Test complete connection lifecycle."""
        with patch('syslog_mcp.services.elasticsearch_client.AsyncElasticsearch') as mock_es:
            mock_instance = AsyncMock()
            mock_instance.ping.return_value = True
            mock_instance.info.return_value = {"version": {"number": "8.0.0"}}
            mock_instance.cluster.health.return_value = {"status": "green"}
            mock_es.return_value = mock_instance
            
            client = ElasticsearchClient()
            
            # Initial state
            assert not client.is_connected()
            
            # Connect
            await client.connect()
            assert client.is_connected()
            
            # Test operations
            ping_result = await client.ping()
            assert ping_result is True
            
            info = await client.get_cluster_info()
            assert "version" in info
            
            # Disconnect
            await client.disconnect()
            assert not client.is_connected()