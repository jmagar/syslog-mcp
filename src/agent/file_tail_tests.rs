use super::*;

#[test]
fn source_id_is_uri_safe_and_stable() {
    assert_eq!(source_id("plex media/server"), "plex-media-server");
    assert_eq!(source_id("---"), "file-tail");
}
