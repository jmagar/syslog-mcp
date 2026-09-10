use super::*;
use serde_json::json;

#[tokio::test]
async fn rejects_oversized_unterminated_frame_before_reading_remaining_bytes() {
    let bytes = vec![b'x'; MAX_FRAME_BYTES + 4096];
    let mut remaining = bytes.as_slice();
    let error = read_frame(&mut remaining).await.unwrap_err();
    assert!(error.to_string().contains("frame exceeds"));
    assert_eq!(remaining.len(), 4095);
}

#[tokio::test]
async fn accepts_bounded_frame_and_clean_eof() {
    let mut bytes = b"{}\n".as_slice();
    assert_eq!(read_frame(&mut bytes).await.unwrap(), Some("{}\n".into()));
    assert_eq!(read_frame(&mut bytes).await.unwrap(), None);
}

#[test]
fn cumulative_deltas_are_bounded_before_callback() {
    let mut parser = GeminiStreamState::new(5);
    let mut streamed = String::new();
    let mut callback = |delta: &str| {
        streamed.push_str(delta);
        Ok(())
    };
    let frame = json!({"type":"message", "role":"assistant", "content":"éé"}).to_string();
    parser.handle_line(&frame, &mut callback).unwrap();
    assert!(parser.handle_line(&frame, &mut callback).is_err());
    assert_eq!(streamed, "éé");
    assert_eq!(parser.text, "éé");
}

#[test]
fn result_and_write_file_output_cannot_bypass_cap() {
    for frame in [
        json!({"type":"result", "status":"success", "response":"ééé"}),
        json!({"type":"tool_use", "name":"write_file", "parameters":{"content":"ééé"}}),
        json!({"type":"message", "role":"assistant", "content":[{"text":"éé"},{"text":"é"}]}),
    ] {
        let mut parser = GeminiStreamState::new(5);
        let mut called = false;
        assert!(
            parser
                .handle_line(&frame.to_string(), &mut |_| {
                    called = true;
                    Ok(())
                })
                .is_err()
        );
        assert!(!called);
        assert!(parser.result_text.is_none());
        assert!(parser.text.is_empty());
    }
}

#[test]
fn exact_output_cap_accepts_multibyte_result() {
    let mut parser = GeminiStreamState::new(4);
    parser
        .handle_line(
            &json!({"type":"result","status":"success","response":"éé"}).to_string(),
            &mut |_| Ok(()),
        )
        .unwrap();
    assert_eq!(parser.finish().unwrap(), "éé");
}
