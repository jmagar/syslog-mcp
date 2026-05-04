use super::*;

#[tokio::test]
async fn tcp_connection_allows_multiple_lines_beyond_connection_total_size() {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<crate::db::LogBatchEntry>(16);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let accept_task = tokio::spawn(async move {
        let (server_stream, peer) = listener.accept().await.unwrap();
        handle_tcp_connection(server_stream, peer, tx, 64, 5).await;
    });

    let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
    use tokio::io::AsyncWriteExt;
    client
        .write_all(
            b"<34>Oct 11 22:14:15 host app: first message\n<34>Oct 11 22:14:16 host app: second message\n",
        )
        .await
        .unwrap();
    client.shutdown().await.unwrap();

    let first = tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv())
        .await
        .unwrap()
        .unwrap();
    let second = tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv())
        .await
        .unwrap()
        .unwrap();

    assert!(first.message.contains("first message"));
    assert!(second.message.contains("second message"));

    accept_task.await.unwrap();
}
