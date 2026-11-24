#![allow(clippy::disallowed_methods)]

use super::*;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;

#[tokio::test]
async fn half_close_keeps_response_direction_open() {
    crate::native_ws::native_ws_tests::init_host();
    let (mut caller, client) = tokio::io::duplex(32);
    let (upstream, mut workload) = tokio::io::duplex(32);
    let copying = tokio::spawn(pump(
        client,
        upstream,
        CancellationToken::new(),
        CancellationToken::new(),
    ));
    let exercise = async {
        caller.write_all(b"request").await.unwrap();
        caller.shutdown().await.unwrap();
        let mut request = Vec::new();
        workload.read_to_end(&mut request).await.unwrap();
        assert_eq!(request, b"request");
        workload
            .write_all(b"response after request EOF")
            .await
            .unwrap();
        workload.shutdown().await.unwrap();
        let mut response = Vec::new();
        caller.read_to_end(&mut response).await.unwrap();
        assert_eq!(response, b"response after request EOF");
        copying.await.unwrap().unwrap();
    };
    tokio::time::timeout(Duration::from_secs(2), exercise)
        .await
        .unwrap();
}

#[tokio::test]
async fn blocked_write_does_not_starve_reverse_direction_and_revocation_drops_both() {
    crate::native_ws::native_ws_tests::init_host();
    let (caller, client) = tokio::io::duplex(32);
    let (upstream, mut workload) = tokio::io::duplex(32);
    let revoked = CancellationToken::new();
    let copying = tokio::spawn(pump(
        client,
        upstream,
        CancellationToken::new(),
        revoked.clone(),
    ));
    let (mut caller_read, mut caller_write) = tokio::io::split(caller);
    let mut blocked = tokio::spawn(async move {
        let payload = vec![42; 1024 * 1024].into_boxed_slice();
        caller_write.write_all(&payload).await
    });
    let exercise = async {
        workload.write_all(b"reverse").await.unwrap();
        let mut response = [0; 7];
        caller_read.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"reverse");
        assert!(
            tokio::time::timeout(Duration::from_millis(20), &mut blocked)
                .await
                .is_err()
        );
        revoked.cancel();
        assert!(copying.await.unwrap().is_err());
        assert!(blocked.await.unwrap().is_err());
        let mut buffered = Vec::new();
        workload.read_to_end(&mut buffered).await.unwrap();
        assert!(buffered.len() <= 32);
        assert!(buffered.iter().all(|byte| *byte == 42));
    };
    tokio::time::timeout(Duration::from_secs(2), exercise)
        .await
        .unwrap();
}

#[tokio::test]
async fn already_revoked_owner_never_forwards_buffered_bytes() {
    crate::native_ws::native_ws_tests::init_host();
    let (mut caller, client) = tokio::io::duplex(32);
    let (upstream, mut workload) = tokio::io::duplex(32);
    caller.write_all(b"must not escape").await.unwrap();
    let owner = CancellationToken::new();
    owner.cancel();
    assert!(pump(client, upstream, owner, CancellationToken::new())
        .await
        .is_err());
    assert_eq!(workload.read(&mut [0; 1]).await.unwrap(), 0);
}

#[tokio::test]
async fn service_drop_cancels_owned_task_and_closes_its_transports() {
    crate::native_ws::native_ws_tests::init_host();
    let (mut caller, client) = tokio::io::duplex(32);
    let (upstream, mut workload) = tokio::io::duplex(32);
    let service = DuplexService::default();
    let permit = service.admit().unwrap();
    let (entered, started) = tokio::sync::oneshot::channel();
    service.spawn(async move {
        let _permit = permit;
        let _ = entered.send(());
        let _ = pump(
            client,
            upstream,
            CancellationToken::new(),
            CancellationToken::new(),
        )
        .await;
    });
    started.await.unwrap();
    drop(service);
    let closed = async {
        assert_eq!(caller.read(&mut [0; 1]).await.unwrap(), 0);
        assert_eq!(workload.read(&mut [0; 1]).await.unwrap(), 0);
    };
    tokio::time::timeout(Duration::from_secs(2), closed)
        .await
        .unwrap();
}
