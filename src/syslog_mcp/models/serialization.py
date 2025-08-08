"""
Serialization and deserialization utilities for Pydantic models.

Provides helpers for converting models to/from various formats including JSON,
dictionary, and Elasticsearch documents. Handles datetime serialization,
field filtering, and error recovery for malformed data.
"""

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Union, Type, TypeVar, Callable
from decimal import Decimal

from pydantic import BaseModel, ValidationError
from pydantic_core import to_jsonable_python

from .log_entry import LogEntry, LogLevel
from .device import DeviceInfo, DeviceStatus, DeviceType
from .query import LogSearchQuery, DeviceSearchQuery, AggregationQuery
from .response import (
    LogSearchResult, DeviceSearchResult, HealthCheckResult,
    ErrorResponse, OperationSummary
)

ModelType = TypeVar('ModelType', bound=BaseModel)


class SerializationConfig:
    """Configuration for model serialization."""
    
    # Default exclusion patterns for sensitive data
    DEFAULT_EXCLUDE_PATTERNS = {
        'password', 'secret', 'token', 'key', 'credential',
        'auth', 'api_key', 'private', 'confidential'
    }
    
    # Default JSON encoder settings
    JSON_ENCODERS = {
        datetime: lambda v: v.isoformat() if v else None,
        Decimal: lambda v: float(v) if v else None,
        bytes: lambda v: v.decode('utf-8', errors='ignore') if v else None,
    }
    
    # Elasticsearch field mappings
    ELASTICSEARCH_FIELD_MAPPINGS = {
        'timestamp': '@timestamp',
        'device': 'host.name',
        'level': 'log.level',
        'message': 'message',
        'facility': 'log.syslog.facility.name',
        'severity': 'log.syslog.severity.name',
        'metadata': 'labels',
    }


class ModelSerializer:
    """
    Enhanced serializer for Pydantic models with format-specific options.
    """
    
    def __init__(self, config: Optional[SerializationConfig] = None):
        self.config = config or SerializationConfig()
    
    def to_dict(
        self, 
        model: BaseModel, 
        exclude: Optional[Union[set, dict]] = None,
        include: Optional[Union[set, dict]] = None,
        by_alias: bool = False,
        exclude_unset: bool = False,
        exclude_defaults: bool = False,
        exclude_none: bool = False,
        round_trip: bool = False,
        warnings: bool = True,
    ) -> Dict[str, Any]:
        """
        Convert model to dictionary with comprehensive filtering options.
        
        Args:
            model: Pydantic model instance
            exclude: Fields to exclude
            include: Fields to include (if specified, only these are included)
            by_alias: Use field aliases
            exclude_unset: Exclude fields that weren't explicitly set
            exclude_defaults: Exclude fields with default values
            exclude_none: Exclude fields with None values
            round_trip: Enable round-trip serialization
            warnings: Whether to show warnings
            
        Returns:
            Dictionary representation of the model
        """
        return model.model_dump(
            exclude=exclude,
            include=include,
            by_alias=by_alias,
            exclude_unset=exclude_unset,
            exclude_defaults=exclude_defaults,
            exclude_none=exclude_none,
            round_trip=round_trip,
            warnings=warnings,
        )
    
    def to_json(
        self,
        model: BaseModel,
        exclude: Optional[Union[set, dict]] = None,
        include: Optional[Union[set, dict]] = None,
        by_alias: bool = True,
        exclude_unset: bool = True,
        exclude_none: bool = True,
        indent: Optional[int] = None,
        separators: Optional[tuple] = None,
        sort_keys: bool = False
    ) -> str:
        """
        Convert model to JSON string with formatting options.
        
        Args:
            model: Pydantic model instance
            exclude: Fields to exclude
            include: Fields to include
            by_alias: Use field aliases
            exclude_unset: Exclude unset fields
            exclude_none: Exclude None values
            indent: JSON indentation
            separators: JSON separators
            sort_keys: Sort dictionary keys
            
        Returns:
            JSON string representation
        """
        data = self.to_dict(
            model,
            exclude=exclude,
            include=include,
            by_alias=by_alias,
            exclude_unset=exclude_unset,
            exclude_none=exclude_none
        )
        
        # Convert to JSON-serializable format
        json_data = to_jsonable_python(data)
        
        return json.dumps(
            json_data,
            indent=indent,
            separators=separators,
            sort_keys=sort_keys,
            ensure_ascii=False
        )
    
    def to_elasticsearch_doc(
        self,
        model: BaseModel,
        index_prefix: str = "syslog",
        doc_type: str = "log"
    ) -> Dict[str, Any]:
        """
        Convert model to Elasticsearch document format.
        
        Args:
            model: Pydantic model instance
            index_prefix: Elasticsearch index prefix
            doc_type: Document type
            
        Returns:
            Elasticsearch document dictionary
        """
        # Get base dictionary
        data = self.to_dict(model, by_alias=True, exclude_none=True)
        
        # Apply Elasticsearch field mappings
        if isinstance(model, LogEntry):
            es_doc = {}
            for field_name, es_field in self.config.ELASTICSEARCH_FIELD_MAPPINGS.items():
                if field_name in data:
                    self._set_nested_field(es_doc, es_field, data[field_name])
            
            # Add ECS-compliant fields
            es_doc['@timestamp'] = data.get('timestamp')
            es_doc['event'] = {
                'dataset': f'{index_prefix}.{doc_type}',
                'kind': 'event',
                'category': ['system'],
                'type': ['info']
            }
            
            if 'level' in data:
                level_name = data['level'].lower() if isinstance(data['level'], str) else str(data['level']).lower()
                if level_name in ['error', 'crit', 'alert', 'emerg']:
                    es_doc['event']['type'] = ['error']
                elif level_name in ['warn', 'warning']:
                    es_doc['event']['type'] = ['warning']
            
            return es_doc
        
        # For other models, return as-is with metadata
        return {
            '_index': f'{index_prefix}-{doc_type}',
            '_source': data
        }
    
    def _set_nested_field(self, doc: Dict[str, Any], field_path: str, value: Any) -> None:
        """Set nested field in document using dot notation."""
        parts = field_path.split('.')
        current = doc
        
        for part in parts[:-1]:
            if part not in current:
                current[part] = {}
            current = current[part]
        
        current[parts[-1]] = value
    
    def filter_sensitive_fields(
        self,
        data: Dict[str, Any],
        additional_patterns: Optional[set] = None
    ) -> Dict[str, Any]:
        """
        Filter out sensitive fields based on naming patterns.
        
        Args:
            data: Data dictionary to filter
            additional_patterns: Additional field patterns to exclude
            
        Returns:
            Filtered data dictionary
        """
        exclude_patterns = self.config.DEFAULT_EXCLUDE_PATTERNS.copy()
        if additional_patterns:
            exclude_patterns.update(additional_patterns)
        
        filtered = {}
        for key, value in data.items():
            key_lower = key.lower()
            
            # Check if key matches any exclusion pattern
            if any(pattern in key_lower for pattern in exclude_patterns):
                filtered[key] = "[REDACTED]"
            elif isinstance(value, dict):
                filtered[key] = self.filter_sensitive_fields(value, additional_patterns)
            else:
                filtered[key] = value
        
        return filtered


class ModelDeserializer:
    """
    Enhanced deserializer with error recovery and validation reporting.
    """
    
    def from_dict(
        self,
        model_class: Type[ModelType],
        data: Dict[str, Any],
        strict: bool = True,
        validate_assignment: bool = True
    ) -> ModelType:
        """
        Create model instance from dictionary with validation.
        
        Args:
            model_class: Pydantic model class
            data: Dictionary data
            strict: Use strict validation
            validate_assignment: Validate field assignments
            
        Returns:
            Model instance
            
        Raises:
            ValidationError: If data is invalid and strict=True
            DeserializationError: If data cannot be parsed
        """
        try:
            return model_class.model_validate(
                data,
                strict=strict,
                context={'validate_assignment': validate_assignment}
            )
        except ValidationError as e:
            if strict:
                raise
            # Try to recover by filling missing fields with defaults
            return self._recover_from_validation_error(model_class, data, e)
    
    def from_json(
        self,
        model_class: Type[ModelType],
        json_str: str,
        strict: bool = True
    ) -> ModelType:
        """
        Create model instance from JSON string.
        
        Args:
            model_class: Pydantic model class
            json_str: JSON string
            strict: Use strict validation
            
        Returns:
            Model instance
        """
        try:
            data = json.loads(json_str)
            return self.from_dict(model_class, data, strict=strict)
        except json.JSONDecodeError as e:
            raise DeserializationError(f"Invalid JSON: {e}")
        except Exception as e:
            raise DeserializationError(f"Failed to deserialize: {e}")
    
    def from_elasticsearch_doc(
        self,
        model_class: Type[ModelType],
        es_doc: Dict[str, Any],
        source_field: str = "_source"
    ) -> ModelType:
        """
        Create model instance from Elasticsearch document.
        
        Args:
            model_class: Pydantic model class
            es_doc: Elasticsearch document
            source_field: Field containing source data
            
        Returns:
            Model instance
        """
        # Extract source data
        if source_field in es_doc:
            data = es_doc[source_field]
        else:
            data = es_doc
        
        # Convert Elasticsearch fields back to model fields
        if model_class == LogEntry:
            data = self._convert_elasticsearch_to_log_entry(data)
        
        return self.from_dict(model_class, data, strict=False)
    
    def _convert_elasticsearch_to_log_entry(self, es_data: Dict[str, Any]) -> Dict[str, Any]:
        """Convert Elasticsearch document back to LogEntry format."""
        log_data = {}
        
        # Reverse field mappings
        reverse_mappings = {
            v: k for k, v in SerializationConfig.ELASTICSEARCH_FIELD_MAPPINGS.items()
        }
        
        # Extract nested fields
        for es_field, model_field in reverse_mappings.items():
            value = self._get_nested_field(es_data, es_field)
            if value is not None:
                log_data[model_field] = value
        
        # Handle direct mappings
        if '@timestamp' in es_data:
            log_data['timestamp'] = es_data['@timestamp']
        
        # Extract host information
        if 'host' in es_data and 'name' in es_data['host']:
            log_data['device'] = es_data['host']['name']
        
        # Extract log level
        if 'log' in es_data and 'level' in es_data['log']:
            log_data['level'] = es_data['log']['level']
        
        return log_data
    
    def _get_nested_field(self, doc: Dict[str, Any], field_path: str) -> Any:
        """Get nested field value using dot notation."""
        parts = field_path.split('.')
        current = doc
        
        for part in parts:
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                return None
        
        return current
    
    def _recover_from_validation_error(
        self,
        model_class: Type[ModelType],
        data: Dict[str, Any],
        error: ValidationError
    ) -> ModelType:
        """
        Attempt to recover from validation error by providing defaults.
        """
        # Create a copy of the data to modify
        recovered_data = data.copy()
        
        # Try to fix common issues
        for error_dict in error.errors():
            field_path = error_dict.get('loc', [])
            error_type = error_dict.get('type', '')
            
            if field_path:
                field_name = field_path[0]
                
                # Handle missing required fields
                if error_type == 'missing':
                    if field_name == 'timestamp' and model_class == LogEntry:
                        recovered_data['timestamp'] = datetime.now(timezone.utc)
                    elif field_name == 'device' and model_class == LogEntry:
                        recovered_data['device'] = 'unknown'
                    elif field_name == 'level' and model_class == LogEntry:
                        recovered_data['level'] = LogLevel.INFO
                    elif field_name == 'message' and model_class == LogEntry:
                        recovered_data['message'] = '[No message]'
                
                # Handle type conversion errors
                elif error_type.startswith('datetime'):
                    if isinstance(recovered_data.get(field_name), str):
                        try:
                            # Try common timestamp formats
                            timestamp_str = recovered_data[field_name]
                            recovered_data[field_name] = datetime.fromisoformat(
                                timestamp_str.replace('Z', '+00:00')
                            )
                        except ValueError:
                            recovered_data[field_name] = datetime.now(timezone.utc)
        
        # Try validation again
        try:
            return model_class.model_validate(recovered_data, strict=False)
        except ValidationError:
            # If recovery fails, create minimal valid instance
            return self._create_minimal_instance(model_class)
    
    def _create_minimal_instance(self, model_class: Type[ModelType]) -> ModelType:
        """Create minimal valid instance with required fields only."""
        if model_class == LogEntry:
            return model_class(
                timestamp=datetime.now(timezone.utc),
                device='unknown',
                level=LogLevel.INFO,
                message='[Parsing failed - minimal instance created]'
            )
        else:
            # For other models, try to create with empty dict and let defaults handle it
            return model_class()


class ValidationErrorReporter:
    """
    Utility for comprehensive validation error reporting.
    """
    
    @staticmethod
    def format_validation_errors(
        error: ValidationError,
        include_input: bool = False,
        max_input_length: int = 100
    ) -> Dict[str, Any]:
        """
        Format validation error for human-readable reporting.
        
        Args:
            error: Pydantic validation error
            include_input: Whether to include input data
            max_input_length: Maximum length for input data display
            
        Returns:
            Formatted error report
        """
        errors = []
        
        for error_dict in error.errors():
            formatted_error = {
                'field': '.'.join(str(loc) for loc in error_dict.get('loc', [])),
                'message': error_dict.get('msg', 'Validation failed'),
                'type': error_dict.get('type', 'unknown'),
                'input_value': error_dict.get('input', None)
            }
            
            # Truncate long input values
            if formatted_error['input_value'] is not None:
                input_str = str(formatted_error['input_value'])
                if len(input_str) > max_input_length:
                    formatted_error['input_value'] = input_str[:max_input_length] + "..."
            
            errors.append(formatted_error)
        
        report = {
            'error_count': len(errors),
            'errors': errors,
            'error_summary': error.title if hasattr(error, 'title') else 'Validation Error'
        }
        
        if include_input and hasattr(error, 'input'):
            input_data = str(error.input)
            if len(input_data) > max_input_length:
                input_data = input_data[:max_input_length] + "..."
            report['input_data'] = input_data
        
        return report


class DeserializationError(Exception):
    """Custom exception for deserialization failures."""
    pass


# Convenience functions for common operations
def serialize_model(
    model: BaseModel,
    format: str = "json",
    **kwargs
) -> Union[str, Dict[str, Any]]:
    """
    Serialize model to specified format.
    
    Args:
        model: Model to serialize
        format: Output format ('json', 'dict', 'elasticsearch')
        **kwargs: Additional serialization options
        
    Returns:
        Serialized data
    """
    serializer = ModelSerializer()
    
    if format == "json":
        return serializer.to_json(model, **kwargs)
    elif format == "dict":
        return serializer.to_dict(model, **kwargs)
    elif format == "elasticsearch":
        return serializer.to_elasticsearch_doc(model, **kwargs)
    else:
        raise ValueError(f"Unsupported format: {format}")


def deserialize_model(
    model_class: Type[ModelType],
    data: Union[str, Dict[str, Any]],
    format: str = "auto",
    **kwargs
) -> ModelType:
    """
    Deserialize data to model instance.
    
    Args:
        model_class: Target model class
        data: Data to deserialize
        format: Input format ('json', 'dict', 'elasticsearch', 'auto')
        **kwargs: Additional deserialization options
        
    Returns:
        Model instance
    """
    deserializer = ModelDeserializer()
    
    if format == "auto":
        if isinstance(data, str):
            format = "json"
        elif isinstance(data, dict):
            if "_source" in data or "_index" in data:
                format = "elasticsearch"
            else:
                format = "dict"
    
    if format == "json":
        return deserializer.from_json(model_class, data, **kwargs)
    elif format == "dict":
        return deserializer.from_dict(model_class, data, **kwargs)
    elif format == "elasticsearch":
        return deserializer.from_elasticsearch_doc(model_class, data, **kwargs)
    else:
        raise ValueError(f"Unsupported format: {format}")


def validate_and_report_errors(
    model_class: Type[ModelType],
    data: Dict[str, Any],
    include_input: bool = True
) -> Dict[str, Any]:
    """
    Validate data and return detailed error report if validation fails.
    
    Args:
        model_class: Model class to validate against
        data: Data to validate
        include_input: Whether to include input in error report
        
    Returns:
        Dictionary with 'valid' bool and either 'model' or 'errors'
    """
    try:
        model = model_class.model_validate(data)
        return {'valid': True, 'model': model}
    except ValidationError as e:
        error_report = ValidationErrorReporter.format_validation_errors(
            e, include_input=include_input
        )
        return {'valid': False, 'errors': error_report}