"""
Tests for serialization and deserialization utilities.
"""

import json
import pytest
from datetime import datetime, timezone, timedelta
from decimal import Decimal
from typing import Any, Dict, List

from pydantic import ValidationError

from syslog_mcp.models.serialization import (
    SerializationConfig, ModelSerializer, ModelDeserializer,
    ValidationErrorReporter, DeserializationError,
    serialize_model, deserialize_model, validate_and_report_errors
)
from syslog_mcp.models.log_entry import LogEntry, LogLevel
from syslog_mcp.models.device import DeviceInfo, DeviceStatus
from syslog_mcp.models.response import (
    LogSearchResult, ResponseStatus, ExecutionMetrics
)


class TestSerializationConfig:
    """Test serialization configuration."""
    
    def test_default_exclusion_patterns(self):
        """Test default sensitive field patterns."""
        config = SerializationConfig()
        
        expected_patterns = {
            'password', 'secret', 'token', 'key', 'credential',
            'auth', 'api_key', 'private', 'confidential'
        }
        
        assert config.DEFAULT_EXCLUDE_PATTERNS == expected_patterns
    
    def test_elasticsearch_field_mappings(self):
        """Test Elasticsearch field mapping configuration."""
        config = SerializationConfig()
        
        expected_mappings = {
            'timestamp': '@timestamp',
            'device': 'host.name',
            'level': 'log.level',
            'message': 'message',
            'facility': 'log.syslog.facility.name',
            'severity': 'log.syslog.severity.name',
            'metadata': 'labels',
        }
        
        assert config.ELASTICSEARCH_FIELD_MAPPINGS == expected_mappings


class TestModelSerializer:
    """Test model serialization functionality."""
    
    def create_sample_log(self) -> LogEntry:
        """Create sample log entry for testing."""
        return LogEntry(
            timestamp=datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc),
            device="web-server-01",
            level=LogLevel.ERROR,
            message="Authentication failed for user admin",
            facility="auth",
            process_id=1234,
            metadata={"user_id": "12345", "session_id": "abcdef"}
        )
    
    def test_to_dict_basic(self):
        """Test basic dictionary serialization."""
        serializer = ModelSerializer()
        log = self.create_sample_log()
        
        result = serializer.to_dict(log)
        
        assert result['device'] == "web-server-01"
        assert result['level'] == LogLevel.ERROR
        assert result['message'] == "Authentication failed for user admin"
        assert isinstance(result['timestamp'], datetime)
    
    def test_to_dict_with_exclusions(self):
        """Test dictionary serialization with field exclusions."""
        serializer = ModelSerializer()
        log = self.create_sample_log()
        
        result = serializer.to_dict(log, exclude={'metadata', 'facility'})
        
        assert 'metadata' not in result
        assert 'facility' not in result
        assert 'device' in result
        assert 'message' in result
    
    def test_to_dict_with_inclusions(self):
        """Test dictionary serialization with field inclusions."""
        serializer = ModelSerializer()
        log = self.create_sample_log()
        
        result = serializer.to_dict(log, include={'device', 'level'})
        
        assert 'device' in result
        assert 'level' in result
        assert 'message' not in result
        assert 'timestamp' not in result
    
    def test_to_dict_exclude_none(self):
        """Test excluding None values."""
        serializer = ModelSerializer()
        log = LogEntry(
            timestamp=datetime.now(timezone.utc),
            device="test-server",
            level=LogLevel.INFO,
            message="Test message",
            facility=None,  # This should be excluded
            process_id=None,   # This should be excluded
            process_name=None   # This should be excluded
        )
        
        result = serializer.to_dict(log, exclude_none=True)
        
        assert 'facility' not in result
        assert 'process_id' not in result
        assert 'process_name' not in result
        assert 'device' in result
        # metadata has default_factory=dict so it won't be None
        assert 'metadata' in result
    
    def test_to_json_basic(self):
        """Test basic JSON serialization."""
        serializer = ModelSerializer()
        log = self.create_sample_log()
        
        json_str = serializer.to_json(log)
        
        # Should be valid JSON
        parsed = json.loads(json_str)
        assert parsed['device'] == "web-server-01"
        assert parsed['level'] == "ERROR"
        assert parsed['message'] == "Authentication failed for user admin"
    
    def test_to_json_formatted(self):
        """Test JSON serialization with formatting."""
        serializer = ModelSerializer()
        log = self.create_sample_log()
        
        json_str = serializer.to_json(log, indent=2, sort_keys=True)
        
        # Should be indented and sorted
        assert '\n' in json_str
        assert '  ' in json_str
        
        # Parse to verify it's still valid
        parsed = json.loads(json_str)
        assert parsed['device'] == "web-server-01"
    
    def test_to_elasticsearch_doc_log_entry(self):
        """Test Elasticsearch document conversion for log entries."""
        serializer = ModelSerializer()
        log = self.create_sample_log()
        
        es_doc = serializer.to_elasticsearch_doc(log)
        
        # Check ECS-compliant structure
        assert '@timestamp' in es_doc
        assert 'host' in es_doc
        assert es_doc['host']['name'] == "web-server-01"
        assert 'log' in es_doc
        assert es_doc['log']['level'] == LogLevel.ERROR
        assert es_doc['message'] == "Authentication failed for user admin"
        
        # Check event metadata
        assert 'event' in es_doc
        assert es_doc['event']['dataset'] == 'syslog.log'
        assert es_doc['event']['kind'] == 'event'
        assert es_doc['event']['category'] == ['system']
        assert es_doc['event']['type'] == ['error']  # ERROR level -> error type
    
    def test_to_elasticsearch_doc_warning_level(self):
        """Test Elasticsearch document for warning level logs."""
        serializer = ModelSerializer()
        log = LogEntry(
            timestamp=datetime.now(timezone.utc),
            device="test-server",
            level=LogLevel.WARN,
            message="Warning message"
        )
        
        es_doc = serializer.to_elasticsearch_doc(log)
        
        assert es_doc['event']['type'] == ['warning']
    
    def test_to_elasticsearch_doc_info_level(self):
        """Test Elasticsearch document for info level logs."""
        serializer = ModelSerializer()
        log = LogEntry(
            timestamp=datetime.now(timezone.utc),
            device="test-server",
            level=LogLevel.INFO,
            message="Info message"
        )
        
        es_doc = serializer.to_elasticsearch_doc(log)
        
        assert es_doc['event']['type'] == ['info']
    
    def test_to_elasticsearch_doc_other_model(self):
        """Test Elasticsearch document for non-log models."""
        serializer = ModelSerializer()
        device = DeviceInfo(name="test-device")
        
        es_doc = serializer.to_elasticsearch_doc(device, doc_type="device")
        
        assert '_index' in es_doc
        assert es_doc['_index'] == 'syslog-device'
        assert '_source' in es_doc
        assert es_doc['_source']['name'] == 'test-device'
    
    def test_filter_sensitive_fields(self):
        """Test filtering of sensitive field data."""
        serializer = ModelSerializer()
        data = {
            'username': 'admin',
            'password': 'secret123',
            'api_key': 'key123',
            'message': 'Login successful',
            'nested': {
                'token': 'jwt_token',
                'user_id': '12345'
            }
        }
        
        filtered = serializer.filter_sensitive_fields(data)
        
        assert filtered['username'] == 'admin'
        assert filtered['password'] == '[REDACTED]'
        assert filtered['api_key'] == '[REDACTED]'
        assert filtered['message'] == 'Login successful'
        assert filtered['nested']['token'] == '[REDACTED]'
        assert filtered['nested']['user_id'] == '12345'
    
    def test_filter_sensitive_additional_patterns(self):
        """Test filtering with additional patterns."""
        serializer = ModelSerializer()
        data = {
            'username': 'admin',
            'internal_id': '12345',
            'debug_info': 'sensitive data'
        }
        
        filtered = serializer.filter_sensitive_fields(
            data, 
            additional_patterns={'internal', 'debug'}
        )
        
        assert filtered['username'] == 'admin'
        assert filtered['internal_id'] == '[REDACTED]'
        assert filtered['debug_info'] == '[REDACTED]'


class TestModelDeserializer:
    """Test model deserialization functionality."""
    
    def test_from_dict_valid_data(self):
        """Test deserialization from valid dictionary."""
        deserializer = ModelDeserializer()
        data = {
            'timestamp': datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc),
            'device': 'web-server',
            'level': LogLevel.INFO,
            'message': 'Test message'
        }
        
        log = deserializer.from_dict(LogEntry, data)
        
        assert isinstance(log, LogEntry)
        assert log.device == 'web-server'
        assert log.level == LogLevel.INFO
        assert log.message == 'Test message'
    
    def test_from_dict_strict_validation(self):
        """Test strict validation with invalid data."""
        deserializer = ModelDeserializer()
        data = {
            'device': 'web-server',
            # Missing required 'timestamp', 'level', 'message'
        }
        
        with pytest.raises(ValidationError):
            deserializer.from_dict(LogEntry, data, strict=True)
    
    def test_from_dict_lenient_validation(self):
        """Test lenient validation with recovery."""
        deserializer = ModelDeserializer()
        data = {
            'device': 'web-server',
            # Missing required fields - should be recovered
        }
        
        log = deserializer.from_dict(LogEntry, data, strict=False)
        
        assert isinstance(log, LogEntry)
        assert log.device == 'web-server'
        assert log.level == LogLevel.INFO  # Default from recovery
        assert log.message  # Should have some message
        assert log.timestamp  # Should have timestamp
    
    def test_from_json_valid(self):
        """Test JSON deserialization."""
        deserializer = ModelDeserializer()
        json_data = {
            'timestamp': '2024-01-01T12:00:00Z',
            'device': 'web-server',
            'level': 'INFO',
            'message': 'Test message'
        }
        json_str = json.dumps(json_data)
        
        log = deserializer.from_json(LogEntry, json_str)
        
        assert isinstance(log, LogEntry)
        assert log.device == 'web-server'
        assert log.level == LogLevel.INFO
    
    def test_from_json_invalid_json(self):
        """Test JSON deserialization with invalid JSON."""
        deserializer = ModelDeserializer()
        invalid_json = "{ invalid json"
        
        with pytest.raises(DeserializationError, match="Invalid JSON"):
            deserializer.from_json(LogEntry, invalid_json)
    
    def test_from_elasticsearch_doc(self):
        """Test Elasticsearch document deserialization."""
        deserializer = ModelDeserializer()
        es_doc = {
            '_source': {
                '@timestamp': '2024-01-01T12:00:00Z',
                'host': {'name': 'web-server'},
                'log': {'level': 'INFO'},
                'message': 'Test message'
            }
        }
        
        log = deserializer.from_elasticsearch_doc(LogEntry, es_doc)
        
        assert isinstance(log, LogEntry)
        assert log.device == 'web-server'
        assert log.level == 'INFO'  # String from ES
        assert log.message == 'Test message'
    
    def test_from_elasticsearch_doc_no_source(self):
        """Test Elasticsearch document without _source field."""
        deserializer = ModelDeserializer()
        es_doc = {
            '@timestamp': '2024-01-01T12:00:00Z',
            'host': {'name': 'web-server'},
            'log': {'level': 'INFO'},
            'message': 'Test message'
        }
        
        log = deserializer.from_elasticsearch_doc(LogEntry, es_doc)
        
        assert isinstance(log, LogEntry)
        assert log.device == 'web-server'
    
    def test_validation_recovery_datetime(self):
        """Test recovery from datetime parsing errors."""
        deserializer = ModelDeserializer()
        data = {
            'timestamp': '2024-01-01T12:00:00Z',  # String timestamp
            'device': 'web-server',
            'level': 'INFO',
            'message': 'Test message'
        }
        
        # Should recover by parsing the datetime string
        log = deserializer.from_dict(LogEntry, data, strict=False)
        
        assert isinstance(log, LogEntry)
        assert isinstance(log.timestamp, datetime)
        assert log.timestamp.year == 2024
    
    def test_minimal_instance_creation(self):
        """Test creation of minimal valid instance."""
        deserializer = ModelDeserializer()
        
        # Create minimal LogEntry instance
        minimal = deserializer._create_minimal_instance(LogEntry)
        
        assert isinstance(minimal, LogEntry)
        assert minimal.device == 'unknown'
        assert minimal.level == LogLevel.INFO
        assert '[Parsing failed' in minimal.message


class TestValidationErrorReporter:
    """Test validation error reporting."""
    
    def test_format_validation_errors(self):
        """Test formatting of validation errors."""
        # Create invalid data to trigger validation error
        try:
            LogEntry(
                timestamp="invalid_datetime",
                device="",  # Empty device
                level="INVALID_LEVEL",
                message=""  # Empty message
            )
        except ValidationError as e:
            report = ValidationErrorReporter.format_validation_errors(e)
            
            assert 'error_count' in report
            assert 'errors' in report
            assert 'error_summary' in report
            assert report['error_count'] > 0
            
            # Check error details
            errors = report['errors']
            assert len(errors) > 0
            
            for error in errors:
                assert 'field' in error
                assert 'message' in error
                assert 'type' in error
                assert 'input_value' in error
    
    def test_format_with_input_truncation(self):
        """Test input value truncation in error reports."""
        try:
            LogEntry(
                timestamp=datetime.now(timezone.utc),
                device="x" * 200,  # Very long device name
                level=LogLevel.INFO,
                message="Test"
            )
        except ValidationError as e:
            report = ValidationErrorReporter.format_validation_errors(
                e, max_input_length=50
            )
            
            # Find the device error
            device_error = None
            for error in report['errors']:
                if 'device' in error['field']:
                    device_error = error
                    break
            
            if device_error:
                input_str = str(device_error['input_value'])
                assert len(input_str) <= 53  # 50 + "..."


class TestConvenienceFunctions:
    """Test convenience functions for serialization/deserialization."""
    
    def test_serialize_model_json(self):
        """Test serialize_model with JSON format."""
        log = LogEntry(
            timestamp=datetime.now(timezone.utc),
            device="test-server",
            level=LogLevel.INFO,
            message="Test message"
        )
        
        result = serialize_model(log, format="json")
        
        assert isinstance(result, str)
        parsed = json.loads(result)
        assert parsed['device'] == "test-server"
    
    def test_serialize_model_dict(self):
        """Test serialize_model with dict format."""
        log = LogEntry(
            timestamp=datetime.now(timezone.utc),
            device="test-server", 
            level=LogLevel.INFO,
            message="Test message"
        )
        
        result = serialize_model(log, format="dict")
        
        assert isinstance(result, dict)
        assert result['device'] == "test-server"
    
    def test_serialize_model_elasticsearch(self):
        """Test serialize_model with Elasticsearch format."""
        log = LogEntry(
            timestamp=datetime.now(timezone.utc),
            device="test-server",
            level=LogLevel.INFO,
            message="Test message"
        )
        
        result = serialize_model(log, format="elasticsearch")
        
        assert isinstance(result, dict)
        assert '@timestamp' in result
        assert 'host' in result
        assert result['host']['name'] == "test-server"
    
    def test_serialize_model_invalid_format(self):
        """Test serialize_model with invalid format."""
        log = LogEntry(
            timestamp=datetime.now(timezone.utc),
            device="test-server",
            level=LogLevel.INFO,
            message="Test message"
        )
        
        with pytest.raises(ValueError, match="Unsupported format"):
            serialize_model(log, format="xml")
    
    def test_deserialize_model_auto_json(self):
        """Test deserialize_model with auto-detection (JSON)."""
        json_data = json.dumps({
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'device': 'test-server',
            'level': 'INFO',
            'message': 'Test message'
        })
        
        log = deserialize_model(LogEntry, json_data, format="auto")
        
        assert isinstance(log, LogEntry)
        assert log.device == "test-server"
    
    def test_deserialize_model_auto_dict(self):
        """Test deserialize_model with auto-detection (dict)."""
        data = {
            'timestamp': datetime.now(timezone.utc),
            'device': 'test-server',
            'level': LogLevel.INFO,
            'message': 'Test message'
        }
        
        log = deserialize_model(LogEntry, data, format="auto")
        
        assert isinstance(log, LogEntry)
        assert log.device == "test-server"
    
    def test_deserialize_model_auto_elasticsearch(self):
        """Test deserialize_model with auto-detection (Elasticsearch)."""
        es_data = {
            '_source': {
                '@timestamp': datetime.now(timezone.utc).isoformat(),
                'host': {'name': 'test-server'},
                'log': {'level': 'INFO'},
                'message': 'Test message'
            }
        }
        
        log = deserialize_model(LogEntry, es_data, format="auto")
        
        assert isinstance(log, LogEntry)
        assert log.device == "test-server"
    
    def test_validate_and_report_errors_valid(self):
        """Test validation reporting with valid data."""
        data = {
            'timestamp': datetime.now(timezone.utc),
            'device': 'test-server',
            'level': LogLevel.INFO,
            'message': 'Test message'
        }
        
        result = validate_and_report_errors(LogEntry, data)
        
        assert result['valid'] is True
        assert 'model' in result
        assert isinstance(result['model'], LogEntry)
    
    def test_validate_and_report_errors_invalid(self):
        """Test validation reporting with invalid data."""
        data = {
            'device': 'test-server',
            # Missing required fields
        }
        
        result = validate_and_report_errors(LogEntry, data)
        
        assert result['valid'] is False
        assert 'errors' in result
        assert 'error_count' in result['errors']
        assert result['errors']['error_count'] > 0


class TestSerializationIntegration:
    """Test integration of serialization with complex models."""
    
    def test_log_search_result_serialization(self):
        """Test serialization of complex response models."""
        metrics = ExecutionMetrics(
            execution_time_ms=150,
            query_time_ms=130,
            documents_examined=1000,
            documents_returned=50
        )
        
        logs = [
            LogEntry(
                timestamp=datetime.now(timezone.utc),
                device=f"server-{i:02d}",
                level=LogLevel.INFO,
                message=f"Test message {i}"
            )
            for i in range(3)
        ]
        
        result = LogSearchResult(
            status=ResponseStatus.SUCCESS,
            total_hits=100,
            logs=logs,
            metrics=metrics
        )
        
        # Serialize to JSON
        json_str = serialize_model(result, format="json")
        parsed = json.loads(json_str)
        
        assert parsed['status'] == "success"
        assert parsed['total_hits'] == 100
        assert len(parsed['logs']) == 3
        assert 'metrics' in parsed
        assert parsed['metrics']['execution_time_ms'] == 150
    
    def test_roundtrip_serialization(self):
        """Test complete roundtrip serialization/deserialization."""
        original_log = LogEntry(
            timestamp=datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc),
            device="web-server-01",
            level=LogLevel.ERROR,
            message="Authentication failed",
            facility="auth",
            process_id=1234,
            metadata={"user": "admin", "session": "12345"}
        )
        
        # Serialize to JSON
        json_str = serialize_model(original_log, format="json")
        
        # Deserialize back to model
        recovered_log = deserialize_model(LogEntry, json_str, format="json")
        
        # Compare key fields
        assert recovered_log.device == original_log.device
        assert recovered_log.level == original_log.level
        assert recovered_log.message == original_log.message
        assert recovered_log.facility == original_log.facility
        assert recovered_log.process_id == original_log.process_id
        
        # Timestamps should be equivalent (allowing for serialization precision)
        assert abs((recovered_log.timestamp - original_log.timestamp).total_seconds()) < 1