use std::{env, fs};
use opentelemetry_proto::tonic::{
    collector::{logs::v1::ExportLogsServiceRequest, metrics::v1::ExportMetricsServiceRequest, trace::v1::ExportTraceServiceRequest},
    common::v1::{AnyValue, KeyValue, any_value::Value as AnyValueKind},
    logs::v1::{LogRecord, ResourceLogs, ScopeLogs},
    metrics::v1::{Gauge, Metric, NumberDataPoint, ResourceMetrics, ScopeMetrics, metric, number_data_point},
    resource::v1::Resource,
    trace::v1::{ResourceSpans, ScopeSpans, Span},
};
use prost::Message;

fn kv(key: &str, value: &str) -> KeyValue { KeyValue { key: key.into(), value: Some(AnyValue { value: Some(AnyValueKind::StringValue(value.into())) }), key_strindex: 0 } }
fn resource(run: &str) -> Resource { Resource { attributes: vec![kv("service.name", "cortex-live"), kv("host.name", run), kv("session.id", run), kv("project.path", run), kv("cortex.run_id", run)], ..Default::default() } }
fn main() {
    let mut a=env::args().skip(1); let run=a.next().expect("RUN_ID"); let dir=a.next().expect("OUT_DIR"); fs::create_dir_all(&dir).unwrap();
    let log=ExportLogsServiceRequest { resource_logs: vec![ResourceLogs { resource:Some(resource(&run)), scope_logs:vec![ScopeLogs { log_records:vec![LogRecord { time_unix_nano:1_787_833_600_000_000_000, body:Some(AnyValue{value:Some(AnyValueKind::StringValue(format!("{run}-otlp-log-0040")))}), event_name:"cortex.live".into(), attributes:vec![kv("cortex.marker",&format!("{run}-otlp-log-0040"))], ..Default::default()}], ..Default::default()}], ..Default::default()}] };
    let metrics=ExportMetricsServiceRequest { resource_metrics:vec![ResourceMetrics { resource:Some(resource(&run)), scope_metrics:vec![ScopeMetrics { metrics:vec![Metric { name:format!("cortex_live_{run}_metric"), data:Some(metric::Data::Gauge(Gauge { data_points:vec![NumberDataPoint { time_unix_nano:1_787_833_600_000_000_000, value:Some(number_data_point::Value::AsInt(42)), attributes:vec![kv("cortex.marker",&format!("{run}-otlp-metric-0041"))], ..Default::default()}] })), ..Default::default()}], ..Default::default()}], ..Default::default()}] };
    let traces=ExportTraceServiceRequest { resource_spans:vec![ResourceSpans { resource:Some(resource(&run)), scope_spans:vec![ScopeSpans { spans:vec![Span { trace_id:vec![1;16], span_id:vec![2;8], name:format!("{run}-otlp-trace-0042"), start_time_unix_nano:1_787_833_600_000_000_000, end_time_unix_nano:1_787_833_600_000_001_000, attributes:vec![kv("cortex.marker",&format!("{run}-otlp-trace-0042"))], ..Default::default()}], ..Default::default()}], ..Default::default()}] };
    fs::write(format!("{dir}/logs.pb"),log.encode_to_vec()).unwrap(); fs::write(format!("{dir}/metrics.pb"),metrics.encode_to_vec()).unwrap(); fs::write(format!("{dir}/traces.pb"),traces.encode_to_vec()).unwrap();
}
