"""
Tests for connection pooling functionality in Elasticsearch client.
"""

import asyncio
import pytest
import time
from unittest.mock import AsyncMock, Mock, patch

from syslog_mcp.services.elasticsearch_client import (
    ElasticsearchConfig,
    ElasticsearchClient,
    ElasticsearchConnectionError,
)


class TestConnectionPooling:
    """Tests for connection pooling functionality."""

    def test_connection_pool_config_has_required_fields(self):
        """Test that connection pool configuration has all required fields."""
        config = ElasticsearchConfig()
        
        # Test that all pool-related fields exist and have reasonable values
        assert hasattr(config, 'pool_maxsize')
        assert hasattr(config, 'pool_connections') 
        assert hasattr(config, 'pool_timeout')
        assert hasattr(config, 'connection_timeout')
        assert hasattr(config, 'keepalive_timeout')
        assert hasattr(config, 'connection_max_age')
        assert hasattr(config, 'enable_connection_pooling')
        
        # Values should be positive numbers
        assert config.pool_maxsize > 0
        assert config.pool_connections > 0
        assert config.pool_timeout > 0
        assert config.connection_timeout > 0
        assert config.keepalive_timeout > 0
        assert config.connection_max_age > 0

    def test_connection_pool_config_defaults(self):
        """Test default connection pool configuration values."""
        config = ElasticsearchConfig()
        
        assert config.pool_maxsize == 10
        assert config.pool_connections == 10
        assert config.pool_block is False
        assert config.pool_timeout == 5.0
        assert config.connection_timeout == 5.0
        assert config.keepalive_timeout == 60.0
        assert config.max_idle_connections == 5
        assert config.connection_max_age == 300.0
        assert config.enable_connection_pooling is True

    def test_client_pool_stats_initialization(self):
        """Test that client initializes pool statistics properly."""
        config = ElasticsearchConfig()
        client = ElasticsearchClient(config)
        
        expected_stats = {
            "total_connections": 0,
            "active_connections": 0,
            "idle_connections": 0,
            "connections_created": 0,
            "connections_closed": 0,
            "pool_hits": 0,
            "pool_misses": 0,
            "last_cleanup": 0.0,
        }
        
        assert client._pool_stats == expected_stats
        assert client._connection_created_time is None
        assert client._cleanup_task is None

    @pytest.mark.asyncio
    async def test_connection_with_pooling_enabled(self):
        """Test connection establishment with pooling enabled."""
        config = ElasticsearchConfig(
            hosts="localhost:9200",
            enable_connection_pooling=True,
            pool_maxsize=15,
            pool_connections=10,
        )
        client = ElasticsearchClient(config)
        
        # Mock AsyncElasticsearch
        mock_es = AsyncMock()
        mock_es.info.return_value = {
            "cluster_name": "test-cluster",
            "version": {"number": "8.0.0"}
        }
        
        with patch("syslog_mcp.services.elasticsearch_client.AsyncElasticsearch", return_value=mock_es):
            await client.connect()
            
            # Verify pooling configuration was applied
            assert client.is_connected
            assert client._pool_stats["connections_created"] == 1
            assert client._pool_stats["active_connections"] == 1
            assert client._connection_created_time is not None
            assert client._cleanup_task is not None
            
            # Verify AsyncElasticsearch was called with pool settings
            # Note: The actual call verification depends on the elasticsearch-py internals
            await client.disconnect()

    @pytest.mark.asyncio
    async def test_connection_with_pooling_disabled(self):
        """Test connection establishment with pooling disabled."""
        config = ElasticsearchConfig(
            hosts="localhost:9200",
            enable_connection_pooling=False,
        )
        client = ElasticsearchClient(config)
        
        # Mock AsyncElasticsearch
        mock_es = AsyncMock()
        mock_es.info.return_value = {
            "cluster_name": "test-cluster",
            "version": {"number": "8.0.0"}
        }
        
        with patch("syslog_mcp.services.elasticsearch_client.AsyncElasticsearch", return_value=mock_es):
            await client.connect()
            
            # Verify no cleanup task was started
            assert client.is_connected
            assert client._cleanup_task is None
            
            await client.disconnect()

    @pytest.mark.asyncio
    async def test_connection_pool_stats(self):
        """Test connection pool statistics collection."""
        config = ElasticsearchConfig(
            pool_maxsize=20,
            pool_connections=15,
            connection_max_age=600.0,
        )
        client = ElasticsearchClient(config)
        
        # Get initial stats
        stats = await client.get_connection_pool_stats()
        
        assert stats["config"]["pool_maxsize"] == 20
        assert stats["config"]["pool_connections"] == 15
        assert stats["config"]["connection_max_age"] == 600.0
        assert stats["current_connection"]["connected"] is False
        assert stats["health"]["circuit_breaker_state"] == "closed"
        assert stats["health"]["cleanup_task_running"] is False

    @pytest.mark.asyncio
    async def test_connection_pool_stats_when_connected(self):
        """Test connection pool statistics when connected."""
        config = ElasticsearchConfig()
        client = ElasticsearchClient(config)
        
        # Mock connection
        mock_es = AsyncMock()
        mock_es.info.return_value = {"cluster_name": "test"}
        
        with patch("syslog_mcp.services.elasticsearch_client.AsyncElasticsearch", return_value=mock_es):
            await client.connect()
            
            stats = await client.get_connection_pool_stats()
            
            assert stats["current_connection"]["connected"] is True
            assert stats["current_connection"]["age_seconds"] >= 0
            assert stats["current_connection"]["created_at"] is not None
            assert stats["total_connections"] == 1
            assert stats["active_connections"] == 1
            assert stats["connections_created"] == 1
            assert stats["health"]["cleanup_task_running"] is True
            
            await client.disconnect()

    @pytest.mark.asyncio
    async def test_disconnect_updates_pool_stats(self):
        """Test that disconnect properly updates pool statistics."""
        config = ElasticsearchConfig()
        client = ElasticsearchClient(config)
        
        # Mock connection
        mock_es = AsyncMock()
        mock_es.info.return_value = {"cluster_name": "test"}
        
        with patch("syslog_mcp.services.elasticsearch_client.AsyncElasticsearch", return_value=mock_es):
            await client.connect()
            
            # Verify connected state
            assert client._pool_stats["active_connections"] == 1
            assert client._pool_stats["connections_created"] == 1
            
            await client.disconnect()
            
            # Verify disconnected state
            assert client._pool_stats["active_connections"] == 0
            assert client._pool_stats["total_connections"] == 0
            assert client._pool_stats["connections_closed"] == 1
            assert client._connection_created_time is None

    @pytest.mark.asyncio
    async def test_cleanup_task_lifecycle(self):
        """Test cleanup task start and stop lifecycle."""
        config = ElasticsearchConfig(
            enable_connection_pooling=True,
            connection_max_age=1.0,  # Short for testing
        )
        client = ElasticsearchClient(config)
        
        # Mock connection
        mock_es = AsyncMock()
        mock_es.info.return_value = {"cluster_name": "test"}
        
        with patch("syslog_mcp.services.elasticsearch_client.AsyncElasticsearch", return_value=mock_es):
            await client.connect()
            
            # Verify cleanup task started
            assert client._cleanup_task is not None
            assert not client._cleanup_task.done()
            
            await client.disconnect()
            
            # Verify cleanup task stopped
            assert client._cleanup_task.done()

    @pytest.mark.asyncio
    async def test_connection_age_based_cleanup(self):
        """Test that connections are cleaned up based on age."""
        config = ElasticsearchConfig(
            enable_connection_pooling=True,
            connection_max_age=0.1,  # Very short for testing
        )
        client = ElasticsearchClient(config)
        
        # Mock connection
        mock_es = AsyncMock()
        mock_es.info.return_value = {"cluster_name": "test"}
        
        # Track reconnection calls
        original_connect = client.connect
        connect_call_count = 0
        
        async def mock_connect():
            nonlocal connect_call_count
            connect_call_count += 1
            return await original_connect()
            
        client.connect = mock_connect
        
        with patch("syslog_mcp.services.elasticsearch_client.AsyncElasticsearch", return_value=mock_es):
            await client.connect()
            initial_connect_count = connect_call_count
            
            # Wait longer than max age
            await asyncio.sleep(0.2)
            
            # Trigger cleanup manually
            await client._perform_connection_cleanup()
            
            # Should have triggered a reconnection
            assert connect_call_count > initial_connect_count
            
            await client.disconnect()

    @pytest.mark.asyncio
    async def test_reconnect_client_functionality(self):
        """Test the _reconnect_client method."""
        config = ElasticsearchConfig()
        client = ElasticsearchClient(config)
        
        # Mock initial connection
        mock_es1 = AsyncMock()
        mock_es1.info.return_value = {"cluster_name": "test"}
        
        mock_es2 = AsyncMock()
        mock_es2.info.return_value = {"cluster_name": "test"}
        
        with patch("syslog_mcp.services.elasticsearch_client.AsyncElasticsearch", side_effect=[mock_es1, mock_es2]):
            await client.connect()
            
            initial_created_count = client._pool_stats["connections_created"]
            initial_closed_count = client._pool_stats["connections_closed"]
            
            # Reconnect
            await client._reconnect_client()
            
            # Verify statistics updated
            assert client._pool_stats["connections_created"] == initial_created_count + 1
            assert client._pool_stats["connections_closed"] == initial_closed_count + 1
            assert client.is_connected
            
            await client.disconnect()

    @pytest.mark.asyncio
    async def test_cleanup_worker_error_handling(self):
        """Test that cleanup worker handles errors gracefully."""
        config = ElasticsearchConfig(
            enable_connection_pooling=True,
            connection_max_age=0.05,  # Very short for testing
        )
        client = ElasticsearchClient(config)
        
        # Mock connection
        mock_es = AsyncMock()
        mock_es.info.return_value = {"cluster_name": "test"}
        
        # Make cleanup method raise an error
        original_cleanup = client._perform_connection_cleanup
        
        async def failing_cleanup():
            raise Exception("Cleanup error")
            
        client._perform_connection_cleanup = failing_cleanup
        
        with patch("syslog_mcp.services.elasticsearch_client.AsyncElasticsearch", return_value=mock_es):
            await client.connect()
            
            # Wait a bit to let cleanup worker run and handle the error
            await asyncio.sleep(0.1)
            
            # Worker should still be running despite the error
            assert not client._cleanup_task.done()
            
            # Restore original method and disconnect
            client._perform_connection_cleanup = original_cleanup
            await client.disconnect()

    @pytest.mark.asyncio
    async def test_client_repr_includes_pooling_info(self):
        """Test that client string representation includes pooling information."""
        config = ElasticsearchConfig(
            hosts=["localhost:9200"],
            enable_connection_pooling=True,
        )
        client = ElasticsearchClient(config)
        
        repr_str = repr(client)
        assert "pooling=enabled" in repr_str
        assert "active=0" in repr_str
        
        # Mock connection to test connected state
        mock_es = AsyncMock()
        mock_es.info.return_value = {"cluster_name": "test"}
        
        with patch("syslog_mcp.services.elasticsearch_client.AsyncElasticsearch", return_value=mock_es):
            await client.connect()
            
            repr_str = repr(client)
            assert "pooling=enabled" in repr_str
            assert "active=1" in repr_str
            assert "status=connected" in repr_str
            
            await client.disconnect()

    def test_client_with_pooling_disabled_repr(self):
        """Test client representation with pooling disabled."""
        config = ElasticsearchConfig(enable_connection_pooling=False)
        client = ElasticsearchClient(config)
        
        repr_str = repr(client)
        assert "pooling=disabled" in repr_str
        assert "active=0" in repr_str

    @pytest.mark.asyncio
    async def test_connection_pool_parameters_applied(self):
        """Test that connection pool parameters are correctly applied."""
        config = ElasticsearchConfig(
            hosts="localhost:9200",
            pool_maxsize=25,
            pool_connections=20,
            connection_timeout=15.0,
            pool_timeout=12.0,
            keepalive_timeout=180.0,
            enable_connection_pooling=True,
        )
        client = ElasticsearchClient(config)
        
        mock_es = AsyncMock()
        mock_es.info.return_value = {"cluster_name": "test"}
        
        with patch("syslog_mcp.services.elasticsearch_client.AsyncElasticsearch") as mock_es_class:
            mock_es_class.return_value = mock_es
            
            await client.connect()
            
            # Verify AsyncElasticsearch was called with correct parameters
            call_args = mock_es_class.call_args[1]  # Get keyword arguments
            assert call_args["connections_per_node"] == 20
            assert call_args["maxsize"] == 25
            assert call_args["connection_timeout"] == 15.0
            assert call_args["pool_timeout"] == 12.0
            assert call_args["keep_alive_timeout"] == 180.0
            assert call_args["keep_alive"] is True
            
            await client.disconnect()