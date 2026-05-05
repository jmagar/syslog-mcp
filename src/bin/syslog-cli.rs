use anyhow::{anyhow, Result};
use serde::Serialize;
use syslog_mcp::app::{
    CorrelateEventsRequest, GetErrorsRequest, SearchLogsRequest, TailLogsRequest,
};
use syslog_mcp::runtime::RuntimeCore;

#[tokio::main]
async fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let Some(command) = args.next() else {
        print_usage();
        return Err(anyhow!("missing command"));
    };
    if command == "help" || command == "--help" || command == "-h" {
        print_usage();
        return Ok(());
    }

    let runtime = RuntimeCore::load_query_only()?;
    let service = runtime.service();
    let options = Options::parse(args.collect())?;

    match command.as_str() {
        "search" => print_json(
            &service
                .search_logs(SearchLogsRequest {
                    query: options.get("query"),
                    hostname: options.get("hostname"),
                    source_ip: options
                        .get("source-ip")
                        .or_else(|| options.get("source_ip")),
                    severity: options.get("severity"),
                    app_name: options.get("app-name").or_else(|| options.get("app_name")),
                    from: options.get("from"),
                    to: options.get("to"),
                    limit: options.get_parse("limit")?,
                })
                .await?,
        )?,
        "tail" => print_json(
            &service
                .tail_logs(TailLogsRequest {
                    hostname: options.get("hostname"),
                    source_ip: options
                        .get("source-ip")
                        .or_else(|| options.get("source_ip")),
                    app_name: options.get("app-name").or_else(|| options.get("app_name")),
                    n: options.get_parse("n")?,
                })
                .await?,
        )?,
        "errors" => print_json(
            &service
                .get_errors(GetErrorsRequest {
                    from: options.get("from"),
                    to: options.get("to"),
                })
                .await?,
        )?,
        "hosts" => print_json(&service.list_hosts().await?)?,
        "correlate" => {
            let reference_time = options
                .get("reference-time")
                .or_else(|| options.get("reference_time"))
                .ok_or_else(|| anyhow!("correlate requires --reference-time"))?;
            print_json(
                &service
                    .correlate_events(CorrelateEventsRequest {
                        reference_time,
                        window_minutes: options
                            .get_parse_alias("window-minutes", "window_minutes")?,
                        severity_min: options
                            .get("severity-min")
                            .or_else(|| options.get("severity_min")),
                        hostname: options.get("hostname"),
                        source_ip: options
                            .get("source-ip")
                            .or_else(|| options.get("source_ip")),
                        query: options.get("query"),
                        limit: options.get_parse("limit")?,
                    })
                    .await?,
            )?;
        }
        "stats" => print_json(&service.get_stats().await?)?,
        _ => {
            print_usage();
            return Err(anyhow!("unknown command: {command}"));
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "syslog-cli/tests.rs"]
mod tests;

#[derive(Debug)]
struct Options {
    pairs: Vec<(String, String)>,
}

impl Options {
    fn parse(args: Vec<String>) -> Result<Self> {
        let mut pairs = Vec::new();
        let mut iter = args.into_iter();
        while let Some(raw) = iter.next() {
            let Some(key) = raw.strip_prefix("--") else {
                return Err(anyhow!("unexpected positional argument: {raw}"));
            };
            if let Some((key, value)) = key.split_once('=') {
                pairs.push((key.to_string(), value.to_string()));
            } else {
                let value = iter
                    .next()
                    .filter(|value| !value.starts_with("--"))
                    .ok_or_else(|| anyhow!("missing value for --{key}"))?;
                pairs.push((key.to_string(), value));
            }
        }
        Ok(Self { pairs })
    }

    fn get(&self, key: &str) -> Option<String> {
        self.pairs
            .iter()
            .rev()
            .find(|(candidate, _)| candidate == key)
            .map(|(_, value)| value.clone())
    }

    fn get_parse<T>(&self, key: &str) -> Result<Option<T>>
    where
        T: std::str::FromStr,
        T::Err: std::fmt::Display,
    {
        self.get(key)
            .map(|value| {
                value
                    .parse()
                    .map_err(|e| anyhow!("invalid value for --{key}={value}: {e}"))
            })
            .transpose()
    }

    fn get_parse_alias<T>(&self, preferred: &str, fallback: &str) -> Result<Option<T>>
    where
        T: std::str::FromStr,
        T::Err: std::fmt::Display,
    {
        match self.get_parse(preferred)? {
            Some(value) => Ok(Some(value)),
            None => self.get_parse(fallback),
        }
    }
}

fn print_json<T: Serialize>(value: &T) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

fn print_usage() {
    eprintln!(
        "Usage:
  syslog-cli search [--query text] [--hostname host] [--source-ip ip:port] [--severity level] [--app-name app] [--from ts] [--to ts] [--limit n]
  syslog-cli tail [--hostname host] [--source-ip ip:port] [--app-name app] [--n n]
  syslog-cli errors [--from ts] [--to ts]
  syslog-cli hosts
  syslog-cli correlate --reference-time ts [--window-minutes n] [--severity-min level] [--hostname host] [--source-ip ip:port] [--query text] [--limit n]
  syslog-cli stats"
    );
}
