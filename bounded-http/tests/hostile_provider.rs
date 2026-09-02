//! The bounded-read guards, driven against a real hostile HTTP provider.
//!
//! Nothing is mocked: a throwaway loopback server plays the malicious storage
//! provider and `read_body_bounded` reads it over a real `reqwest` connection,
//! exactly as the provider-facing storage backends do. `vault-core`'s S3 tests
//! drive the same function end-to-end through `S3Storage::download`.

use bounded_http::{read_body_bounded, read_text_bounded, BoundedReadError};

/// Serve exactly one HTTP/1.1 response, then close. Returns the URL to GET.
///
/// Same shape as `vault-core`'s `spawn_hostile_provider`, deliberately — a
/// reader comparing the two should see the same harness.
async fn spawn_hostile_provider(head: String, body: Vec<u8>) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    tokio::spawn(async move {
        if let Ok((mut sock, _)) = listener.accept().await {
            let mut buf = [0u8; 8192];
            let _ = sock.read(&mut buf).await;
            // Writes may fail once the client hangs up — that IS the behaviour
            // under test, so errors are ignored.
            let _ = sock.write_all(head.as_bytes()).await;
            let _ = sock.write_all(&body).await;
            let _ = sock.flush().await;
        }
    });

    format!("http://127.0.0.1:{port}/object")
}

async fn get(url: &str) -> reqwest::Response {
    reqwest::Client::new().get(url).send().await.unwrap()
}

/// Guard 1: a declared `Content-Length` over the ceiling is refused on the
/// header alone — the body is never buffered, and the attacker pays for the
/// whole transfer they do not get to deliver.
#[tokio::test]
async fn declared_oversize_is_refused_without_buffering() {
    let url = spawn_hostile_provider(
        "HTTP/1.1 200 OK\r\nContent-Length: 5242880\r\n\r\n".to_string(),
        vec![0u8; 4096], // never fully read
    )
    .await;

    let err = read_body_bounded(get(&url).await, 1024)
        .await
        .expect_err("a 5 MiB declared body under a 1 KiB ceiling must be refused");

    match err {
        BoundedReadError::DeclaredTooLarge { declared, max } => {
            assert_eq!(declared, 5_242_880);
            assert_eq!(max, 1024);
        }
        other => panic!("expected DeclaredTooLarge, got {other:?}"),
    }
}

/// Guard 2: the case a `Content-Length` check alone cannot catch — the provider
/// declares nothing (chunked transfer encoding) and streams past the ceiling.
/// This is why the byte counter exists; without it, guard 1 is trivially evaded
/// by simply not declaring a length.
#[tokio::test]
async fn undeclared_oversize_is_aborted_mid_stream() {
    // 8 × 64 KiB = 512 KiB, chunked, no Content-Length.
    let mut body = Vec::new();
    let chunk = vec![b'A'; 64 * 1024];
    for _ in 0..8 {
        body.extend_from_slice(format!("{:x}\r\n", chunk.len()).as_bytes());
        body.extend_from_slice(&chunk);
        body.extend_from_slice(b"\r\n");
    }
    body.extend_from_slice(b"0\r\n\r\n");

    let url = spawn_hostile_provider(
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_string(),
        body,
    )
    .await;

    let err = read_body_bounded(get(&url).await, 100 * 1024)
        .await
        .expect_err("an undeclared body over the ceiling must be aborted mid-stream");

    assert!(
        matches!(err, BoundedReadError::StreamedTooLarge { max } if max == 100 * 1024),
        "expected StreamedTooLarge, got {err:?}"
    );
}

/// A lying `Content-Length` — declares small, sends large. Guard 1 waves it
/// through, guard 2 has to catch it. This is the precise reason the comment says
/// "either alone is defeatable".
#[tokio::test]
async fn lying_content_length_is_caught_by_the_stream_counter() {
    let url = spawn_hostile_provider(
        // Declares 16 bytes, actually sends 256 KiB.
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_string(),
        {
            let mut body = Vec::new();
            let chunk = vec![b'B'; 256 * 1024];
            body.extend_from_slice(format!("{:x}\r\n", chunk.len()).as_bytes());
            body.extend_from_slice(&chunk);
            body.extend_from_slice(b"\r\n0\r\n\r\n");
            body
        },
    )
    .await;

    let err = read_body_bounded(get(&url).await, 8 * 1024)
        .await
        .expect_err("a body over the ceiling must be refused however it was declared");
    assert!(matches!(err, BoundedReadError::StreamedTooLarge { .. }), "{err:?}");
}

/// Positive control. A guard that also broke legitimate reads would be worse
/// than the defect it fixes — every pack download goes through this path.
#[tokio::test]
async fn under_ceiling_body_reads_back_byte_for_byte() {
    let payload: Vec<u8> = (0..4096u32).map(|i| (i % 251) as u8).collect();
    let url = spawn_hostile_provider(
        format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", payload.len()),
        payload.clone(),
    )
    .await;

    let got = read_body_bounded(get(&url).await, 64 * 1024).await.unwrap();
    assert_eq!(got, payload, "a legitimate object must round-trip unchanged");
}

/// Exactly-at-the-ceiling must pass. An off-by-one here refuses a legitimate
/// object at the boundary, which would surface as a rare unexplained download
/// failure rather than as a test result.
#[tokio::test]
async fn body_exactly_at_the_ceiling_is_accepted() {
    let payload = vec![b'C'; 1024];
    let url = spawn_hostile_provider(
        format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", payload.len()),
        payload.clone(),
    )
    .await;

    let got = read_body_bounded(get(&url).await, 1024).await.unwrap();
    assert_eq!(got.len(), 1024);
}

/// **The error-path hole, which is the subtle half of M-9.** A hostile provider
/// answering 500 with a huge body defeated the object ceiling *in the same
/// call*, because the error branch read the body with an unbounded
/// `resp.text()`. `read_text_bounded` never returns an error — the caller is
/// already reporting a different failure and must not have it replaced by this
/// one — so it yields a marker instead, and the marker says so out loud.
#[tokio::test]
async fn diagnostic_read_of_a_hostile_error_body_is_bounded_and_says_so() {
    let url = spawn_hostile_provider(
        "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 52428800\r\n\r\n".to_string(),
        vec![b'X'; 4096],
    )
    .await;

    let text = read_text_bounded(get(&url).await, 64 * 1024).await;

    assert!(
        text.contains("suppressed") || text.contains("truncated"),
        "an oversized error body must yield an explicit marker, not silence \
         and not 50 MB of X: {text}"
    );
    assert!(
        text.len() < 4096,
        "the marker must be short — the whole point is not buffering the body: {} bytes",
        text.len()
    );
}

/// A normal-sized error body still reaches the caller intact, or every provider
/// error becomes undiagnosable.
#[tokio::test]
async fn diagnostic_read_of_a_normal_error_body_is_returned_verbatim() {
    let body = b"<Error><Code>NoSuchKey</Code></Error>".to_vec();
    let url = spawn_hostile_provider(
        format!(
            "HTTP/1.1 404 Not Found\r\nContent-Length: {}\r\n\r\n",
            body.len()
        ),
        body.clone(),
    )
    .await;

    let text = read_text_bounded(get(&url).await, 64 * 1024).await;
    assert_eq!(text, String::from_utf8(body).unwrap());
}
