use super::{AuthOutcome, ParserError, ParserId, SourceKind};

#[test]
fn source_kind_as_str_matches_serde() {
    assert_eq!(SourceKind::SyslogUdp.as_str(), "syslog-udp");
    assert_eq!(SourceKind::DockerStream.as_str(), "docker-stream");
    assert_eq!(SourceKind::DockerEvent.as_str(), "docker-event");
    assert_eq!(SourceKind::AdguardApi.as_str(), "adguard-api");
    assert_eq!(SourceKind::UnifiApi.as_str(), "unifi-api");
    assert_eq!(SourceKind::ShellHistory.as_str(), "shell-history");
    assert_eq!(SourceKind::AgentCommand.as_str(), "agent-command");
    assert_eq!(SourceKind::FileTail.as_str(), "file-tail");
    assert_eq!(SourceKind::AgentFileTail.as_str(), "agent-file-tail");
}

#[test]
fn source_kind_is_syslog_covers_both() {
    assert!(SourceKind::SyslogUdp.is_syslog());
    assert!(SourceKind::SyslogTcp.is_syslog());
    assert!(!SourceKind::DockerStream.is_syslog());
}

#[test]
fn auth_outcome_as_str_round_trip() {
    for variant in [
        AuthOutcome::Success,
        AuthOutcome::Failure,
        AuthOutcome::Denied,
        AuthOutcome::Challenge,
    ] {
        let s = variant.as_str();
        let parsed: AuthOutcome = serde_json::from_str(&format!("\"{s}\"")).unwrap();
        assert_eq!(parsed, variant);
    }
}

#[test]
fn parser_id_as_str_matches_serde() {
    assert_eq!(ParserId::Kernel.as_str(), "kernel");
    assert_eq!(ParserId::DockerEvent.as_str(), "docker_event");
    assert_eq!(ParserId::Authelia.as_str(), "authelia");
    assert_eq!(ParserId::Swag.as_str(), "swag");
    assert_eq!(ParserId::Adguard.as_str(), "adguard");
    assert_eq!(ParserId::Fail2ban.as_str(), "fail2ban");
}

#[test]
fn parser_error_display_for_storage() {
    let err = ParserError::MissingField("http_status");
    assert_eq!(format!("{err}"), "missing required field: http_status");
}
