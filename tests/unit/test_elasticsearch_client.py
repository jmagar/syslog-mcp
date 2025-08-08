"""
Tests for the Elasticsearch client module.
"""

from unittest.mock import AsyncMock, patch, MagicMock

import pytest
from elasticsearch import AsyncElasticsearch
from elasticsearch.exceptions import AuthenticationException, ConnectionError, SSLError

from syslog_mcp.services.elasticsearch_client import (
    ElasticsearchClient,
    ElasticsearchConfig,
    ElasticsearchConnectionError,
    ElasticsearchAuthenticationError,
    ElasticsearchSSLError,
    create_elasticsearch_client,
)


class TestElasticsearchConfig:
    """Tests for Elasticsearch configuration."""

    def test_default_config(self):
        """Test default configuration values."""
        # Test with explicit values to avoid .env file interference
        config = ElasticsearchConfig(
            ELASTICSEARCH_HOST="localhost:9200",
            ELASTICSEARCH_API_KEY=None,
        )
        assert config.hosts == ["localhost:9200"]
        assert config.api_key is None
        assert config.username is None
        assert config.password is None
        assert config.use_ssl is False
        assert config.verify_certs is True
        assert config.timeout == 30
        assert config.max_retries == 3

    def test_hosts_parsing_single(self):
        """Test parsing single host."""
        config = ElasticsearchConfig(ELASTICSEARCH_HOST="example.com:9200")
        assert config.hosts == ["example.com:9200"]

    def test_hosts_parsing_multiple(self):
        """Test parsing multiple hosts."""
        config = ElasticsearchConfig(ELASTICSEARCH_HOST="host1:9200,host2:9200,host3:9200")
        assert config.hosts == ["host1:9200", "host2:9200", "host3:9200"]

    def test_hosts_parsing_list(self):
        """Test hosts as list."""
        hosts = ["host1:9200", "host2:9200"]
        config = ElasticsearchConfig(ELASTICSEARCH_HOST=hosts)
        assert config.hosts == hosts

    def test_api_key_parsing_empty(self):
        """Test API key parsing with empty values."""
        config = ElasticsearchConfig(ELASTICSEARCH_HOST="localhost:9200", ELASTICSEARCH_API_KEY="")
        assert config.api_key is None

        config = ElasticsearchConfig(ELASTICSEARCH_HOST="localhost:9200", ELASTICSEARCH_API_KEY=None)
        assert config.api_key is None

    def test_api_key_parsing_valid(self):
        """Test API key parsing with valid value."""
        config = ElasticsearchConfig(ELASTICSEARCH_HOST="localhost:9200", ELASTICSEARCH_API_KEY="test-key")
        assert config.api_key == "test-key"
    
    def test_auth_priority_parsing(self):
        """Test authentication priority parsing."""
        config = ElasticsearchConfig(
            ELASTICSEARCH_HOST="localhost:9200",
            ELASTICSEARCH_AUTH_PRIORITY="api_key,basic,none"
        )
        assert config.auth_priority == ["api_key", "basic", "none"]
    
    def test_auth_priority_list(self):
        """Test authentication priority as list."""
        priority = ["basic", "api_key"]
        config = ElasticsearchConfig(
            ELASTICSEARCH_HOST="localhost:9200",
            ELASTICSEARCH_AUTH_PRIORITY=priority
        )
        assert config.auth_priority == priority
    
    def test_validate_authentication_config_valid(self):
        """Test valid authentication configuration."""
        config = ElasticsearchConfig(
            ELASTICSEARCH_HOST="localhost:9200",
            ELASTICSEARCH_API_KEY="test:key_value_with_colon_and_sufficient_length",
        )
        is_valid, error = config.validate_authentication_config()
        assert is_valid
        assert error == ""
    
    def test_validate_authentication_config_invalid_api_key(self):
        """Test invalid API key format."""
        config = ElasticsearchConfig(
            ELASTICSEARCH_HOST="localhost:9200",
            ELASTICSEARCH_API_KEY="short",
        )
        is_valid, error = config.validate_authentication_config()
        assert not is_valid
        assert "API key appears to be invalid format" in error
    
    def test_validate_authentication_config_missing_password(self):
        """Test missing password with username."""
        config = ElasticsearchConfig(
            ELASTICSEARCH_HOST="localhost:9200",
            ELASTICSEARCH_USERNAME="user",
        )
        is_valid, error = config.validate_authentication_config()
        assert not is_valid
        assert "Password must be provided when using username" in error
    
    def test_validate_authentication_config_ssl_cert_without_key(self):
        """Test SSL certificate without key."""
        config = ElasticsearchConfig(
            ELASTICSEARCH_HOST="localhost:9200",
            ELASTICSEARCH_USE_SSL=True,
            ELASTICSEARCH_CLIENT_CERT="/path/to/cert.pem",
        )
        is_valid, error = config.validate_authentication_config()
        assert not is_valid
        assert "Client key must be provided when using client certificate" in error
    
    def test_validate_authentication_config_cert_without_ssl(self):
        """Test certificates without SSL enabled."""
        config = ElasticsearchConfig(
            ELASTICSEARCH_HOST="localhost:9200",
            ELASTICSEARCH_USE_SSL=False,
            ELASTICSEARCH_CLIENT_CERT="/path/to/cert.pem",
            ELASTICSEARCH_CLIENT_KEY="/path/to/key.pem",
        )
        is_valid, error = config.validate_authentication_config()
        assert not is_valid
        assert "SSL must be enabled when using client certificates" in error
    
    def test_get_effective_auth_method_api_key_priority(self):
        """Test effective auth method with API key priority."""
        config = ElasticsearchConfig(
            ELASTICSEARCH_HOST="localhost:9200",
            ELASTICSEARCH_API_KEY="test:key_value_with_colon_and_sufficient_length",
            ELASTICSEARCH_USERNAME="user",
            ELASTICSEARCH_PASSWORD="pass",
            ELASTICSEARCH_AUTH_PRIORITY=["api_key", "basic", "none"]
        )
        assert config.get_effective_auth_method() == "api_key"
    
    def test_get_effective_auth_method_basic_priority(self):
        """Test effective auth method with basic auth priority."""
        config = ElasticsearchConfig(
            ELASTICSEARCH_HOST="localhost:9200",
            ELASTICSEARCH_USERNAME="user",
            ELASTICSEARCH_PASSWORD="pass",
            ELASTICSEARCH_AUTH_PRIORITY=["basic", "api_key", "none"]
        )
        assert config.get_effective_auth_method() == "basic"
    
    def test_get_effective_auth_method_none_fallback(self):
        """Test effective auth method falling back to none."""
        config = ElasticsearchConfig(
            ELASTICSEARCH_HOST="localhost:9200",
            ELASTICSEARCH_AUTH_PRIORITY=["api_key", "basic", "none"]
        )
        assert config.get_effective_auth_method() == "none"


class TestElasticsearchClient:
    """Tests for Elasticsearch client."""

    @pytest.fixture
    def config(self):
        """Test configuration."""
        return ElasticsearchConfig(
            ELASTICSEARCH_HOST="localhost:9200",
            ELASTICSEARCH_TIMEOUT=10,
            ELASTICSEARCH_MAX_RETRIES=2,
        )

    @pytest.fixture
    def client(self, config):
        """Test client instance."""
        return ElasticsearchClient(config)

    def test_init_default_config(self):
        """Test client initialization with default config."""
        client = ElasticsearchClient()
        assert isinstance(client.config, ElasticsearchConfig)
        assert not client.is_connected

    def test_init_custom_config(self, config):
        """Test client initialization with custom config."""
        client = ElasticsearchClient(config)
        assert client.config == config
        assert not client.is_connected

    def test_repr(self, client):
        """Test string representation."""
        repr_str = repr(client)
        assert "ElasticsearchClient" in repr_str
        assert "disconnected" in repr_str

    @pytest.mark.asyncio
    async def test_connect_success(self, client):
        """Test successful connection."""
        mock_es_client = AsyncMock(spec=AsyncElasticsearch)
        mock_es_client.info = AsyncMock(return_value={
            "cluster_name": "test-cluster",
            "version": {"number": "8.0.0"},
        })

        with patch("syslog_mcp.services.elasticsearch_client.AsyncElasticsearch") as mock_es:
            mock_es.return_value = mock_es_client

            await client.connect()

            assert client.is_connected
            assert client._client == mock_es_client
            mock_es_client.info.assert_called_once()

    @pytest.mark.asyncio 
    async def test_connect_authentication_error(self, client):
        """Test connection with authentication error."""
        mock_es_client = AsyncMock(spec=AsyncElasticsearch)
        
        # Create a simple exception and use monkeypatch to make isinstance work
        auth_error = Exception("missing authentication token")
        mock_es_client.info = AsyncMock(side_effect=auth_error)

        # Patch isinstance to recognize our exception as AuthenticationException
        def mock_isinstance(obj, class_or_tuple):
            if obj is auth_error and class_or_tuple == AuthenticationException:
                return True
            return isinstance.__wrapped__(obj, class_or_tuple) if hasattr(isinstance, '__wrapped__') else type(obj) == class_or_tuple or issubclass(type(obj), class_or_tuple) if isinstance(class_or_tuple, type) else any(isinstance(obj, cls) for cls in class_or_tuple)

        with patch("syslog_mcp.services.elasticsearch_client.AsyncElasticsearch") as mock_es:
            mock_es.return_value = mock_es_client
            
            with patch('builtins.isinstance', side_effect=mock_isinstance):
                with pytest.raises(ElasticsearchAuthenticationError, match="Authentication failed"):
                    await client.connect()

                assert not client.is_connected

    @pytest.mark.asyncio
    async def test_connect_connection_error(self, client):
        """Test connection with connection error."""
        mock_es_client = AsyncMock(spec=AsyncElasticsearch)
        # Create a simple subclass that behaves like ConnectionError
        class MockConnectionError(ConnectionError, Exception):
            def __init__(self, message):
                Exception.__init__(self, message)
        
        conn_error = MockConnectionError("Connection failed")
        mock_es_client.info = AsyncMock(side_effect=conn_error)

        with patch("syslog_mcp.services.elasticsearch_client.AsyncElasticsearch") as mock_es:
            mock_es.return_value = mock_es_client

            with pytest.raises(ElasticsearchConnectionError, match="Connection error"):
                await client.connect()

    @pytest.mark.asyncio
    async def test_connect_already_connected(self, client):
        """Test connecting when already connected."""
        mock_es_client = AsyncMock(spec=AsyncElasticsearch)
        mock_es_client.info = AsyncMock(return_value={"cluster_name": "test"})

        with patch("syslog_mcp.services.elasticsearch_client.AsyncElasticsearch") as mock_es:
            mock_es.return_value = mock_es_client

            # First connection
            await client.connect()
            assert client.is_connected

            # Second connection attempt
            await client.connect()
            assert client.is_connected

            # Should only create client once
            assert mock_es.call_count == 1

    @pytest.mark.asyncio
    async def test_disconnect(self, client):
        """Test disconnection."""
        mock_es_client = AsyncMock(spec=AsyncElasticsearch)
        mock_es_client.info = AsyncMock(return_value={"cluster_name": "test"})
        mock_es_client.close = AsyncMock()

        with patch("syslog_mcp.services.elasticsearch_client.AsyncElasticsearch") as mock_es:
            mock_es.return_value = mock_es_client

            await client.connect()
            assert client.is_connected

            await client.disconnect()
            assert not client.is_connected
            mock_es_client.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_disconnect_error_handling(self, client):
        """Test disconnect with error handling."""
        mock_es_client = AsyncMock(spec=AsyncElasticsearch)
        mock_es_client.info = AsyncMock(return_value={"cluster_name": "test"})
        mock_es_client.close = AsyncMock(side_effect=Exception("Close failed"))

        with patch("syslog_mcp.services.elasticsearch_client.AsyncElasticsearch") as mock_es:
            mock_es.return_value = mock_es_client

            await client.connect()

            # Should not raise exception, just log warning
            await client.disconnect()
            assert not client.is_connected

    @pytest.mark.asyncio
    async def test_ping_success(self, client):
        """Test successful ping."""
        mock_es_client = AsyncMock(spec=AsyncElasticsearch)
        mock_es_client.info = AsyncMock(return_value={"cluster_name": "test"})
        mock_es_client.ping = AsyncMock(return_value=True)

        with patch("syslog_mcp.services.elasticsearch_client.AsyncElasticsearch") as mock_es:
            mock_es.return_value = mock_es_client

            await client.connect()
            result = await client.ping()

            assert result is True
            mock_es_client.ping.assert_called_once()

    @pytest.mark.asyncio
    async def test_ping_not_connected(self, client):
        """Test ping when not connected."""
        result = await client.ping()
        assert result is False

    @pytest.mark.asyncio
    async def test_ping_failure(self, client):
        """Test ping failure."""
        mock_es_client = AsyncMock(spec=AsyncElasticsearch)
        mock_es_client.info = AsyncMock(return_value={"cluster_name": "test"})
        mock_es_client.ping = AsyncMock(side_effect=Exception("Ping failed"))

        with patch("syslog_mcp.services.elasticsearch_client.AsyncElasticsearch") as mock_es:
            mock_es.return_value = mock_es_client

            await client.connect()
            result = await client.ping()

            assert result is False

    @pytest.mark.asyncio
    async def test_get_cluster_info_success(self, client):
        """Test getting cluster info."""
        mock_info = {
            "cluster_name": "test-cluster",
            "version": {"number": "8.0.0"},
        }
        mock_es_client = AsyncMock(spec=AsyncElasticsearch)
        mock_es_client.info = AsyncMock(return_value=mock_info)

        with patch("syslog_mcp.services.elasticsearch_client.AsyncElasticsearch") as mock_es:
            mock_es.return_value = mock_es_client

            await client.connect()
            info = await client.get_cluster_info()

            assert info == mock_info

    @pytest.mark.asyncio
    async def test_get_cluster_info_not_connected(self, client):
        """Test getting cluster info when not connected."""
        with pytest.raises(ElasticsearchConnectionError, match="not connected"):
            await client.get_cluster_info()

    @pytest.mark.asyncio
    async def test_client_property_success(self, client):
        """Test client property when connected."""
        mock_es_client = AsyncMock(spec=AsyncElasticsearch)
        mock_es_client.info = AsyncMock(return_value={"cluster_name": "test"})

        with patch("syslog_mcp.services.elasticsearch_client.AsyncElasticsearch") as mock_es:
            mock_es.return_value = mock_es_client

            await client.connect()
            assert client.client == mock_es_client

    def test_client_property_not_connected(self, client):
        """Test client property when not connected."""
        with pytest.raises(ElasticsearchConnectionError, match="not connected"):
            _ = client.client

    @pytest.mark.asyncio
    async def test_context_manager(self, config):
        """Test async context manager."""
        mock_es_client = AsyncMock(spec=AsyncElasticsearch)
        mock_es_client.info = AsyncMock(return_value={"cluster_name": "test"})
        mock_es_client.close = AsyncMock()

        with patch("syslog_mcp.services.elasticsearch_client.AsyncElasticsearch") as mock_es:
            mock_es.return_value = mock_es_client

            async with ElasticsearchClient(config) as client:
                assert client.is_connected
                assert client.client == mock_es_client

            # Should be disconnected after exiting context
            assert not client.is_connected
            mock_es_client.close.assert_called_once()

    
    @pytest.mark.asyncio
    async def test_validate_credentials_success(self, client):
        """Test successful credential validation."""
        mock_es_client = AsyncMock(spec=AsyncElasticsearch)
        mock_es_client.info = AsyncMock(return_value={"cluster_name": "test"})
        # Create mock security namespace
        mock_security = AsyncMock()
        mock_security.get_user = AsyncMock(return_value={"user1": {"username": "user1"}})
        mock_es_client.security = mock_security
        
        with patch("syslog_mcp.services.elasticsearch_client.AsyncElasticsearch") as mock_es:
            mock_es.return_value = mock_es_client

            await client.connect()
            is_valid, info = await client.validate_credentials()
            
            assert is_valid is True
            assert info["authenticated"] is True
            assert info["auth_method"] == "none"
            assert info["user_count"] == 1

    @pytest.mark.asyncio
    async def test_validate_credentials_authentication_error(self, client):
        """Test credential validation with authentication error."""
        mock_es_client = AsyncMock(spec=AsyncElasticsearch)
        mock_es_client.info = AsyncMock(return_value={"cluster_name": "test"})
        
        # Create proper authentication error
        auth_error = AuthenticationException("missing authentication token")
        
        # Create mock security namespace
        mock_security = AsyncMock()
        mock_security.get_user = AsyncMock(side_effect=auth_error)
        mock_es_client.security = mock_security
        
        with patch("syslog_mcp.services.elasticsearch_client.AsyncElasticsearch") as mock_es:
            mock_es.return_value = mock_es_client

            await client.connect()
            is_valid, info = await client.validate_credentials()
            
            assert is_valid is False
            assert info["authenticated"] is False
            assert "missing authentication token" in info["error"]

    @pytest.mark.asyncio
    async def test_validate_credentials_not_connected(self, client):
        """Test credential validation when not connected."""
        is_valid, info = await client.validate_credentials()
        
        assert is_valid is False
        assert info["error"] == "Client not connected"


class TestCreateElasticsearchClient:
    """Tests for client factory function."""

    @pytest.mark.asyncio
    async def test_create_client_success(self):
        """Test successful client creation."""
        mock_es_client = AsyncMock(spec=AsyncElasticsearch)
        mock_es_client.info = AsyncMock(return_value={"cluster_name": "test"})
        mock_es_client.close = AsyncMock()

        with patch("syslog_mcp.services.elasticsearch_client.AsyncElasticsearch") as mock_es:
            mock_es.return_value = mock_es_client

            async with create_elasticsearch_client() as client:
                assert isinstance(client, ElasticsearchClient)
                assert client.is_connected

            # Should be disconnected after exiting context
            mock_es_client.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_client_with_config(self):
        """Test client creation with custom config."""
        config = ElasticsearchConfig(ELASTICSEARCH_HOST="test:9200", ELASTICSEARCH_TIMEOUT=5)
        mock_es_client = AsyncMock(spec=AsyncElasticsearch)
        mock_es_client.info = AsyncMock(return_value={"cluster_name": "test"})
        mock_es_client.close = AsyncMock()

        with patch("syslog_mcp.services.elasticsearch_client.AsyncElasticsearch") as mock_es:
            mock_es.return_value = mock_es_client

            async with create_elasticsearch_client(config) as client:
                assert client.config == config
                assert client.is_connected

    @pytest.mark.asyncio
    async def test_create_client_connection_error(self):
        """Test client creation with connection error."""
        mock_es_client = AsyncMock(spec=AsyncElasticsearch)
        # Create a simple subclass that behaves like ConnectionError
        class MockConnectionError(ConnectionError, Exception):
            def __init__(self, message):
                Exception.__init__(self, message)
        
        conn_error = MockConnectionError("Connection failed")
        mock_es_client.info = AsyncMock(side_effect=conn_error)

        with patch("syslog_mcp.services.elasticsearch_client.AsyncElasticsearch") as mock_es:
            mock_es.return_value = mock_es_client

            with pytest.raises(ElasticsearchConnectionError):
                async with create_elasticsearch_client():
                    pass
    
    @pytest.mark.asyncio
    async def test_connect_ssl_error(self):
        """Test connection with SSL error."""
        config = ElasticsearchConfig(ELASTICSEARCH_HOST="localhost:9200")
        client = ElasticsearchClient(config)
        
        mock_es_client = AsyncMock(spec=AsyncElasticsearch)
        
        # Create proper SSL error using the correct format
        ssl_error = SSLError("SSL certificate verification failed")
        mock_es_client.info = AsyncMock(side_effect=ssl_error)

        with patch("syslog_mcp.services.elasticsearch_client.AsyncElasticsearch") as mock_es:
            mock_es.return_value = mock_es_client

            with pytest.raises(ElasticsearchSSLError, match="SSL/TLS error"):
                await client.connect()

    @pytest.mark.asyncio
    async def test_init_with_invalid_config(self):
        """Test client initialization with invalid configuration."""
        config = ElasticsearchConfig(
            ELASTICSEARCH_HOST="localhost:9200",
            ELASTICSEARCH_USERNAME="user",  # Missing password
        )
        
        with pytest.raises(ElasticsearchConnectionError, match="Invalid configuration"):
            ElasticsearchClient(config)
    
    @pytest.mark.asyncio
    async def test_connect_with_ssl_configuration(self):
        """Test connection with comprehensive SSL configuration."""
        config = ElasticsearchConfig(
            ELASTICSEARCH_HOST="localhost:9200",
            ELASTICSEARCH_USE_SSL=True,
            ELASTICSEARCH_VERIFY_CERTS=True,
            ELASTICSEARCH_CA_CERTS="/path/to/ca.crt",
            ELASTICSEARCH_CLIENT_CERT="/path/to/client.crt",
            ELASTICSEARCH_CLIENT_KEY="/path/to/client.key",
            ELASTICSEARCH_SSL_ASSERT_HOSTNAME=False,
            ELASTICSEARCH_SSL_FINGERPRINT="abc123",
        )
        client = ElasticsearchClient(config)
        
        mock_es_client = AsyncMock(spec=AsyncElasticsearch)
        mock_es_client.info = AsyncMock(return_value={"cluster_name": "test"})

        with patch("syslog_mcp.services.elasticsearch_client.AsyncElasticsearch") as mock_es:
            mock_es.return_value = mock_es_client

            await client.connect()
            
            # Verify SSL parameters were passed
            call_args = mock_es.call_args[1]
            assert call_args["use_ssl"] is True
            assert call_args["verify_certs"] is True
            assert call_args["ca_certs"] == "/path/to/ca.crt"
            assert call_args["client_cert"] == "/path/to/client.crt"
            assert call_args["client_key"] == "/path/to/client.key"
            assert call_args["ssl_assert_hostname"] is False
            assert call_args["ssl_assert_fingerprint"] == "abc123"

    @pytest.mark.asyncio
    async def test_connect_with_auth_priority(self):
        """Test connection with authentication priority."""
        config = ElasticsearchConfig(
            ELASTICSEARCH_HOST="localhost:9200",
            ELASTICSEARCH_API_KEY="test:key_value_with_colon_and_sufficient_length",
            ELASTICSEARCH_USERNAME="user",
            ELASTICSEARCH_PASSWORD="pass",
            ELASTICSEARCH_AUTH_PRIORITY=["basic", "api_key", "none"]
        )
        client = ElasticsearchClient(config)
        
        mock_es_client = AsyncMock(spec=AsyncElasticsearch)
        mock_es_client.info = AsyncMock(return_value={"cluster_name": "test"})

        with patch("syslog_mcp.services.elasticsearch_client.AsyncElasticsearch") as mock_es:
            mock_es.return_value = mock_es_client

            await client.connect()
            
            # Should use basic auth due to priority
            call_args = mock_es.call_args[1]
            assert call_args["http_auth"] == ("user", "pass")
            assert "api_key" not in call_args


class TestElasticsearchHealthChecking:
    """Tests for Elasticsearch health checking and monitoring functionality."""

    @pytest.fixture
    def client(self):
        """Test client with health check setup."""
        config = ElasticsearchConfig(ELASTICSEARCH_HOST="localhost:9200")
        return ElasticsearchClient(config)

    @pytest.mark.asyncio
    async def test_get_cluster_health_success(self, client):
        """Test successful cluster health retrieval."""
        mock_es_client = AsyncMock(spec=AsyncElasticsearch)
        mock_es_client.info = AsyncMock(return_value={"cluster_name": "test"})
        
        # Mock cluster health response
        mock_health = {
            "cluster_name": "test-cluster",
            "status": "green",
            "timed_out": False,
            "number_of_nodes": 3,
            "number_of_data_nodes": 3,
            "active_primary_shards": 10,
            "active_shards": 20,
            "relocating_shards": 0,
            "initializing_shards": 0,
            "unassigned_shards": 0,
            "delayed_unassigned_shards": 0,
            "number_of_pending_tasks": 0,
            "number_of_in_flight_fetch": 0,
            "task_max_waiting_in_queue_millis": 0,
            "active_shards_percent_as_number": 100.0,
        }
        
        # Mock cluster stats response
        mock_stats = {
            "indices": {
                "count": 5,
                "docs": {"count": 1000},
                "store": {"size_in_bytes": 1048576},
                "fielddata": {"fields": {"count": 50}},
            },
            "nodes": {
                "versions": ["8.0.0"],
                "os": {"name": "Linux"},
                "process": {"cpu": {"percent": 25}},
                "jvm": {"version": "11.0.0"},
            }
        }
        
        # Create mock cluster namespace
        mock_cluster = AsyncMock()
        mock_cluster.health = AsyncMock(return_value=mock_health)
        mock_cluster.stats = AsyncMock(return_value=mock_stats)
        mock_es_client.cluster = mock_cluster

        with patch("syslog_mcp.services.elasticsearch_client.AsyncElasticsearch") as mock_es:
            mock_es.return_value = mock_es_client

            await client.connect()
            health_info = await client.get_cluster_health()

            assert health_info["cluster_name"] == "test-cluster"
            assert health_info["status"] == "green"
            assert health_info["number_of_nodes"] == 3
            assert health_info["total_indices"] == 5
            assert health_info["total_documents"] == 1000
            assert health_info["health_score"] == 100.0  # Perfect score for green status
            assert "timestamp" in health_info

    @pytest.mark.asyncio
    async def test_get_cluster_health_not_connected(self, client):
        """Test cluster health when not connected."""
        with pytest.raises(ElasticsearchConnectionError, match="Client not connected"):
            await client.get_cluster_health()

    @pytest.mark.asyncio
    async def test_calculate_health_score_green(self, client):
        """Test health score calculation for green cluster."""
        health_data = {
            "status": "green",
            "active_shards": 20,
            "unassigned_shards": 0,
            "relocating_shards": 0,
            "initializing_shards": 0,
            "number_of_pending_tasks": 0,
            "timed_out": False,
            "number_of_nodes": 3,
            "number_of_data_nodes": 3,
        }
        
        score = client._calculate_health_score(health_data)
        assert score == 100.0

    @pytest.mark.asyncio
    async def test_calculate_health_score_yellow(self, client):
        """Test health score calculation for yellow cluster."""
        health_data = {
            "status": "yellow",
            "active_shards": 15,
            "unassigned_shards": 5,  # Some unassigned shards
            "relocating_shards": 0,
            "initializing_shards": 0,
            "number_of_pending_tasks": 0,
            "timed_out": False,
            "number_of_nodes": 3,
            "number_of_data_nodes": 3,
        }
        
        score = client._calculate_health_score(health_data)
        # Should be 100 (start) - 20 (yellow) - 7.5 (25% unassigned shards * 30) = 72.5
        assert score == 72.5

    @pytest.mark.asyncio
    async def test_calculate_health_score_red(self, client):
        """Test health score calculation for red cluster."""
        health_data = {
            "status": "red",
            "active_shards": 10,
            "unassigned_shards": 10,  # 50% unassigned
            "relocating_shards": 2,
            "initializing_shards": 1,
            "number_of_pending_tasks": 5,
            "timed_out": True,
            "number_of_nodes": 2,
            "number_of_data_nodes": 1,  # Only 50% of nodes available
        }
        
        score = client._calculate_health_score(health_data)
        # Should be heavily penalized: 100 - 50(red) - 15(50% unassigned) - 4(relocating) - 1(init) - 2.5(tasks) - 10(timeout) - 5(nodes 50% ratio) = 12.5
        assert score == 12.5

    @pytest.mark.asyncio
    async def test_get_cluster_stats_success(self, client):
        """Test successful cluster stats retrieval."""
        mock_es_client = AsyncMock(spec=AsyncElasticsearch)
        mock_es_client.info = AsyncMock(return_value={"cluster_name": "test"})
        
        mock_stats = {
            "cluster_name": "test-cluster",
            "cluster_uuid": "abc-123",
            "status": "green",
            "nodes": {
                "count": {"total": 3, "data": 3, "master": 1},
                "versions": ["8.0.0"],
                "os": {"name": "Linux", "count": 3},
                "process": {"cpu": {"percent": 25}},
                "jvm": {"version": "11.0.0", "count": 3},
                "fs": {"total_in_bytes": 1073741824},
                "plugins": [],
                "network_types": {},
            },
            "indices": {
                "count": 5,
                "shards": {"total": 20, "primaries": 10, "replication": 1.0},
                "docs": {"count": 1000, "deleted": 50},
                "store": {"size_in_bytes": 1048576},
                "fielddata": {"memory_size_in_bytes": 10240},
                "query_cache": {"memory_size_in_bytes": 5120, "hit_count": 100},
                "completion": {"size_in_bytes": 2048},
                "segments": {"count": 50, "memory_in_bytes": 20480},
            }
        }
        
        # Create mock cluster namespace
        mock_cluster = AsyncMock()
        mock_cluster.stats = AsyncMock(return_value=mock_stats)
        mock_es_client.cluster = mock_cluster

        with patch("syslog_mcp.services.elasticsearch_client.AsyncElasticsearch") as mock_es:
            mock_es.return_value = mock_es_client

            await client.connect()
            stats = await client.get_cluster_stats()

            assert stats["cluster_name"] == "test-cluster"
            assert stats["cluster_uuid"] == "abc-123"
            assert stats["status"] == "green"
            assert stats["nodes"]["count"]["total"] == 3
            assert stats["indices"]["count"] == 5
            assert stats["indices"]["docs"]["count"] == 1000
            assert "timestamp" in stats

    @pytest.mark.asyncio
    async def test_get_node_info_success(self, client):
        """Test successful node info retrieval."""
        mock_es_client = AsyncMock(spec=AsyncElasticsearch)
        mock_es_client.info = AsyncMock(return_value={"cluster_name": "test"})
        
        mock_nodes_info = {
            "cluster_name": "test-cluster",
            "nodes": {
                "node-1": {
                    "name": "test-node-1",
                    "transport_address": "127.0.0.1:9300",
                    "host": "localhost",
                    "ip": "127.0.0.1",
                    "version": "8.0.0",
                    "build_hash": "abc123",
                    "roles": ["master", "data"],
                    "attributes": {},
                    "os": {"name": "Linux"},
                    "jvm": {"version": "11.0.0"},
                    "process": {"id": 12345},
                }
            }
        }
        
        mock_nodes_stats = {
            "cluster_name": "test-cluster", 
            "nodes": {
                "node-1": {
                    "indices": {"docs": {"count": 500}},
                    "os": {"cpu": {"percent": 25}},
                    "process": {"cpu": {"percent": 15}},
                    "jvm": {"mem": {"heap_used_percent": 45}},
                    "thread_pool": {"search": {"queue": 0}},
                    "fs": {"total": {"total_in_bytes": 1073741824}},
                    "transport": {"rx_count": 1000},
                    "http": {"current_open": 5},
                }
            }
        }
        
        # Create mock nodes namespace
        mock_nodes = AsyncMock()
        mock_nodes.info = AsyncMock(return_value=mock_nodes_info)
        mock_nodes.stats = AsyncMock(return_value=mock_nodes_stats)
        mock_es_client.nodes = mock_nodes

        with patch("syslog_mcp.services.elasticsearch_client.AsyncElasticsearch") as mock_es:
            mock_es.return_value = mock_es_client

            await client.connect()
            node_info = await client.get_node_info()

            assert node_info["cluster_name"] == "test-cluster"
            assert "node-1" in node_info["nodes"]
            assert node_info["nodes"]["node-1"]["name"] == "test-node-1"
            assert node_info["nodes"]["node-1"]["version"] == "8.0.0"
            assert node_info["nodes"]["node-1"]["roles"] == ["master", "data"]
            assert node_info["nodes"]["node-1"]["stats"]["indices"]["docs"]["count"] == 500
            assert "timestamp" in node_info

    @pytest.mark.asyncio
    async def test_get_node_info_specific_node(self, client):
        """Test node info retrieval for specific node."""
        mock_es_client = AsyncMock(spec=AsyncElasticsearch)
        mock_es_client.info = AsyncMock(return_value={"cluster_name": "test"})
        
        mock_nodes_info = {
            "cluster_name": "test-cluster",
            "nodes": {
                "node-1": {
                    "name": "specific-node",
                    "version": "8.0.0",
                    "roles": ["data"],
                }
            }
        }
        
        mock_nodes_stats = {
            "cluster_name": "test-cluster",
            "nodes": {
                "node-1": {
                    "indices": {"docs": {"count": 100}},
                }
            }
        }
        
        # Create mock nodes namespace
        mock_nodes = AsyncMock()
        mock_nodes.info = AsyncMock(return_value=mock_nodes_info)
        mock_nodes.stats = AsyncMock(return_value=mock_nodes_stats)
        mock_es_client.nodes = mock_nodes

        with patch("syslog_mcp.services.elasticsearch_client.AsyncElasticsearch") as mock_es:
            mock_es.return_value = mock_es_client

            await client.connect()
            node_info = await client.get_node_info(node_id="node-1")

            # Verify the specific node was requested
            mock_nodes.info.assert_called_with(node_id="node-1")
            mock_nodes.stats.assert_called_with(node_id="node-1")
            assert "node-1" in node_info["nodes"]

    @pytest.mark.asyncio
    async def test_check_indices_health_success(self, client):
        """Test successful indices health check."""
        mock_es_client = AsyncMock(spec=AsyncElasticsearch)
        mock_es_client.info = AsyncMock(return_value={"cluster_name": "test"})
        
        mock_indices_stats = {
            "indices": {
                "index-1": {
                    "total": {
                        "docs": {"count": 100},
                        "store": {"size_in_bytes": 10240},
                        "indexing": {"index_total": 150},
                        "search": {"query_total": 50},
                        "segments": {"count": 5},
                    }
                },
                "index-2": {
                    "total": {
                        "docs": {"count": 200},
                        "store": {"size_in_bytes": 20480},
                        "indexing": {"index_total": 250},
                        "search": {"query_total": 75},
                        "segments": {"count": 8},
                    }
                }
            }
        }
        
        mock_health_response = {
            "status": "yellow",
            "active_shards": 6,
            "unassigned_shards": 2,
            "indices": {
                "index-1": {
                    "status": "green",
                    "number_of_shards": 2,
                    "number_of_replicas": 1,
                    "active_primary_shards": 2,
                    "active_shards": 4,
                    "relocating_shards": 0,
                    "initializing_shards": 0,
                    "unassigned_shards": 0,
                },
                "index-2": {
                    "status": "yellow",
                    "number_of_shards": 2,
                    "number_of_replicas": 1,
                    "active_primary_shards": 2,
                    "active_shards": 2,
                    "relocating_shards": 0,
                    "initializing_shards": 0,
                    "unassigned_shards": 2,
                }
            }
        }
        
        # Create mock indices and cluster namespaces
        mock_indices = AsyncMock()
        mock_indices.stats = AsyncMock(return_value=mock_indices_stats)
        mock_es_client.indices = mock_indices
        
        mock_cluster = AsyncMock()
        mock_cluster.health = AsyncMock(return_value=mock_health_response)
        mock_es_client.cluster = mock_cluster

        with patch("syslog_mcp.services.elasticsearch_client.AsyncElasticsearch") as mock_es:
            mock_es.return_value = mock_es_client

            await client.connect()
            indices_health = await client.check_indices_health()

            assert indices_health["overall_status"] == "yellow"
            assert indices_health["summary"]["total_indices"] == 2
            assert indices_health["summary"]["green_indices"] == 1
            assert indices_health["summary"]["yellow_indices"] == 1
            assert indices_health["summary"]["red_indices"] == 0
            assert indices_health["summary"]["total_shards"] == 6
            assert indices_health["summary"]["unassigned_shards"] == 2
            
            # Check individual index data
            assert indices_health["indices"]["index-1"]["status"] == "green"
            assert indices_health["indices"]["index-1"]["stats"]["docs"]["count"] == 100
            assert indices_health["indices"]["index-2"]["status"] == "yellow"
            assert indices_health["indices"]["index-2"]["unassigned_shards"] == 2
            assert "timestamp" in indices_health

    @pytest.mark.asyncio
    async def test_check_indices_health_specific_pattern(self, client):
        """Test indices health check with specific pattern."""
        mock_es_client = AsyncMock(spec=AsyncElasticsearch)
        mock_es_client.info = AsyncMock(return_value={"cluster_name": "test"})
        
        mock_indices_stats = {"indices": {}}
        mock_health_response = {"status": "green", "indices": {}}
        
        # Create mock indices and cluster namespaces
        mock_indices = AsyncMock()
        mock_indices.stats = AsyncMock(return_value=mock_indices_stats)
        mock_es_client.indices = mock_indices
        
        mock_cluster = AsyncMock()
        mock_cluster.health = AsyncMock(return_value=mock_health_response)
        mock_es_client.cluster = mock_cluster

        with patch("syslog_mcp.services.elasticsearch_client.AsyncElasticsearch") as mock_es:
            mock_es.return_value = mock_es_client

            await client.connect()
            await client.check_indices_health(index_pattern="logs-*")

            # Verify the pattern was passed to both calls
            mock_indices.stats.assert_called_with(index="logs-*")
            mock_cluster.health.assert_called_with(index="logs-*", level="indices")

    @pytest.mark.asyncio
    async def test_health_check_methods_not_connected(self, client):
        """Test health check methods when not connected."""
        # Test all health check methods fail when not connected
        with pytest.raises(ElasticsearchConnectionError, match="Client not connected"):
            await client.get_cluster_stats()
        
        with pytest.raises(ElasticsearchConnectionError, match="Client not connected"):
            await client.get_node_info()
        
        with pytest.raises(ElasticsearchConnectionError, match="Client not connected"):
            await client.check_indices_health()
