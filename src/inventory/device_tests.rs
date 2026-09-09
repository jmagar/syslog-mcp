use super::*;

#[test]
fn parse_meminfo_is_optional_and_non_panicking() {
    let _ = parse_meminfo();
}

#[cfg(unix)]
#[tokio::test]
#[serial_test::serial]
async fn collect_builds_device_facts_from_local_command_output() {
    let _fixtures = command_fixtures([
        ("hostname", Some("devhost\n")),
        ("uname", Some("Linux test 1 x86_64 GNU/Linux\n")),
        (
            "ip",
            Some(
                r#"[{"ifname":"lo","addr_info":[{"local":"127.0.0.1"}]},{"ifname":"eth0","addr_info":[{"local":"192.0.2.42"},{"local":"fd00::42"}]}]
"#,
            ),
        ),
        (
            "ss",
            Some(
                r#"Netid State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process
tcp   LISTEN 0      128    0.0.0.0:3100    0.0.0.0:*
udp   UNCONN 0      0      [::]:1514       [::]:*
"#,
            ),
        ),
        (
            "df",
            Some(
                r#"Filesystem Type 1024-blocks Used Available Capacity Mounted on
/dev/sda1 ext4 1000 250 750 25% /
/dev/sdb1 zfs 2000 500 1500 25% /mnt/data
"#,
            ),
        ),
    ]);

    let output = collect(std::time::Duration::from_secs(5)).await;

    assert!(output.warnings.is_empty(), "{:?}", output.warnings);
    assert_eq!(output.nodes.len(), 1);
    let node = &output.nodes[0];
    assert_eq!(node.hostname, "devhost");
    assert_eq!(node.ips, vec!["192.0.2.42", "fd00::42"]);
    assert_eq!(node.os.as_deref(), Some("Linux test 1 x86_64 GNU/Linux"));
    assert_eq!(node.listeners.len(), 2);
    assert_eq!(node.listeners[0].protocol, "tcp");
    assert_eq!(node.listeners[0].port, Some(3100));
    assert_eq!(node.listeners[1].protocol, "udp");
    assert_eq!(node.listeners[1].port, Some(1514));
    assert_eq!(node.storage.len(), 2);
    assert_eq!(node.storage[0].mount, "/");
    assert_eq!(node.storage[0].total_bytes, Some(1000 * 1024));
    assert_eq!(node.storage[1].mount, "/mnt/data");
    assert_eq!(output.storage.len(), 2);
}

#[cfg(unix)]
#[tokio::test]
#[serial_test::serial]
async fn collect_warns_when_optional_device_commands_are_missing() {
    let _fixtures = command_fixtures([
        ("hostname", Some("")),
        ("uname", None),
        ("ip", None),
        ("ss", None),
        ("df", None),
    ]);

    let output = collect(std::time::Duration::from_millis(50)).await;

    assert_eq!(output.nodes.len(), 1);
    assert_eq!(output.nodes[0].hostname, "localhost");
    assert!(output.nodes[0].ips.is_empty());
    assert!(output.nodes[0].listeners.is_empty());
    assert!(output.nodes[0].storage.is_empty());
    assert!(
        output
            .warnings
            .iter()
            .any(|warning| warning.contains("ip -j addr unavailable"))
    );
    assert!(
        output
            .warnings
            .iter()
            .any(|warning| warning.contains("ss -lntu unavailable"))
    );
    assert!(
        output
            .warnings
            .iter()
            .any(|warning| warning.contains("df -PT unavailable"))
    );
}
