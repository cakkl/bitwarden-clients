#![cfg(windows)]

use serial_test::serial;
use tokio::{io::AsyncWriteExt, net::windows::named_pipe::ClientOptions};

mod common;
use common::{
    agent_with_keys, always_approving_agent, always_denying_agent,
    framed_invalid_session_bind_extension, framed_request_identities,
    framed_session_bind_extension, framed_sign_request, init_tracing, parse_first_key_name,
    parse_sign_response_algorithm, read_framed_response, test_ecdsa_p256_key,
    test_ecdsa_p256_key_blob, test_ecdsa_p384_key, test_ecdsa_p384_key_blob, test_ecdsa_p521_key,
    test_ecdsa_p521_key_blob, test_ed25519_key, test_ed25519_key_blob, test_rsa_key,
    test_rsa_key_blob, unsupported_dsa_key_blob, MockApprovalRequester,
};
use ssh_agent::{BitwardenSSHAgent, InMemoryEncryptedKeyStore};

type Agent = BitwardenSSHAgent<InMemoryEncryptedKeyStore, MockApprovalRequester>;

/// Returns a pipe name no other test uses.
///
/// Tests share one OS namespace, and a listener from a previous test can briefly outlive its agent
/// while `stop()` winds down, making a later client connect to an instance being torn down.
fn unique_pipe_name() -> String {
    static COUNTER: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    format!(
        r"\\.\pipe\bw-ssh-agent-test-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    )
}

/// Starts `agent` on a fresh pipe and returns its name.
fn start(agent: &mut Agent) -> String {
    let name = unique_pipe_name();
    agent
        .start_on_pipe(&name)
        .expect("failed to start the agent on a test pipe");
    name
}

/// Restarts an agent on a pipe it already used, retrying while the old listener still owns it.
async fn restart(agent: &mut Agent, name: &str) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);

    loop {
        match agent.start_on_pipe(name) {
            Ok(()) => return,
            Err(error) => {
                assert!(
                    std::time::Instant::now() < deadline,
                    "restart failed: {error}"
                );
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        }
    }
}

fn setup() {
    init_tracing();
}

#[serial]
#[tokio::test(flavor = "multi_thread")]
async fn test_start_creates_pipe() {
    setup();
    let mut agent = always_approving_agent();

    let pipe = start(&mut agent);

    // The pipe is created synchronously before start() returns,
    // so no sleep is needed — the OS accepts the connection immediately.
    let result = ClientOptions::new().open(&pipe);
    assert!(
        result.is_ok(),
        "client connection to named pipe should succeed"
    );
    agent.stop();
}

#[serial]
#[tokio::test(flavor = "multi_thread")]
async fn test_client_can_connect() {
    setup();
    let mut agent = always_approving_agent();
    let pipe = start(&mut agent);

    let result = ClientOptions::new().open(&pipe);

    assert!(
        result.is_ok(),
        "client connection to named pipe should succeed"
    );
    agent.stop();
}

#[serial]
#[tokio::test(flavor = "multi_thread")]
async fn test_stop_clears_running_state() {
    setup();
    let mut agent = always_approving_agent();
    let _pipe = start(&mut agent);

    agent.stop();

    assert!(!agent.is_running());
}

#[serial]
#[tokio::test(flavor = "multi_thread")]
async fn test_server_can_restart() {
    setup();
    let mut agent = always_approving_agent();

    let pipe = start(&mut agent);
    agent.stop();
    restart(&mut agent, &pipe).await;

    assert!(agent.is_running());
    assert!(ClientOptions::new().open(&pipe).is_ok());
    agent.stop();
}

#[serial]
#[tokio::test(flavor = "multi_thread")]
async fn test_list_keys_returns_empty_when_no_keys_set() {
    setup();
    let mut agent = always_approving_agent();
    let pipe = start(&mut agent);

    let mut client = ClientOptions::new().open(&pipe).unwrap();
    client
        .write_all(&framed_request_identities())
        .await
        .unwrap();
    let response = read_framed_response(&mut client).await;

    assert_eq!(response[0], 12, "expected IDENTITIES_ANSWER type byte");
    assert_eq!(
        u32::from_be_bytes(response[1..5].try_into().unwrap()),
        0,
        "expected zero keys"
    );

    agent.stop();
}

#[serial]
#[tokio::test(flavor = "multi_thread")]
async fn test_list_keys_returns_keys_after_replace() {
    setup();
    let mut agent = agent_with_keys(vec![test_ed25519_key()]);
    let pipe = start(&mut agent);

    let mut client = ClientOptions::new().open(&pipe).unwrap();
    client
        .write_all(&framed_request_identities())
        .await
        .unwrap();
    let response = read_framed_response(&mut client).await;

    assert_eq!(response[0], 12, "expected IDENTITIES_ANSWER type byte");
    let count = u32::from_be_bytes(response[1..5].try_into().unwrap());
    assert_eq!(count, 1, "expected one key");
    assert_eq!(parse_first_key_name(&response), "Test Key");

    agent.stop();
}

#[serial]
#[tokio::test(flavor = "multi_thread")]
async fn test_list_keys_updates_after_replace() {
    setup();
    let mut agent = always_approving_agent();
    let pipe = start(&mut agent);

    // Initially no keys
    let mut client = ClientOptions::new().open(&pipe).unwrap();
    client
        .write_all(&framed_request_identities())
        .await
        .unwrap();
    let response = read_framed_response(&mut client).await;
    assert_eq!(u32::from_be_bytes(response[1..5].try_into().unwrap()), 0);

    // Add a key
    agent.replace(vec![test_ed25519_key()]).unwrap();

    // New connection sees the key
    let mut client2 = ClientOptions::new().open(&pipe).unwrap();
    client2
        .write_all(&framed_request_identities())
        .await
        .unwrap();
    let response2 = read_framed_response(&mut client2).await;
    assert_eq!(u32::from_be_bytes(response2[1..5].try_into().unwrap()), 1);
    assert_eq!(parse_first_key_name(&response2), "Test Key");

    agent.stop();
}

#[serial]
#[tokio::test(flavor = "multi_thread")]
async fn test_list_keys_multiple_connections_see_same_keys() {
    setup();
    let mut agent = agent_with_keys(vec![test_ed25519_key()]);
    let pipe = start(&mut agent);

    for _ in 0..3 {
        let mut client = ClientOptions::new().open(&pipe).unwrap();
        client
            .write_all(&framed_request_identities())
            .await
            .unwrap();
        let response = read_framed_response(&mut client).await;
        assert_eq!(u32::from_be_bytes(response[1..5].try_into().unwrap()), 1);
    }

    agent.stop();
}

#[serial]
#[tokio::test(flavor = "multi_thread")]
async fn test_sign_request_returns_sign_response() {
    setup();
    let mut agent = agent_with_keys(vec![test_ed25519_key()]);
    let pipe = start(&mut agent);

    let mut client = ClientOptions::new().open(&pipe).unwrap();
    client
        .write_all(&framed_sign_request(
            &test_ed25519_key_blob(),
            b"test data",
            0,
        ))
        .await
        .unwrap();
    let response = read_framed_response(&mut client).await;

    assert_eq!(response[0], 14, "expected SIGN_RESPONSE type byte");

    agent.stop();
}

#[serial]
#[tokio::test(flavor = "multi_thread")]
async fn test_sign_request_denied_returns_failure() {
    setup();
    let mut agent = always_denying_agent();
    agent.replace(vec![test_ed25519_key()]).unwrap();
    let pipe = start(&mut agent);

    let mut client = ClientOptions::new().open(&pipe).unwrap();
    client
        .write_all(&framed_sign_request(
            &test_ed25519_key_blob(),
            b"test data",
            0,
        ))
        .await
        .unwrap();
    let response = read_framed_response(&mut client).await;

    assert_eq!(response[0], 5, "expected FAILURE type byte");

    agent.stop();
}

#[serial]
#[tokio::test(flavor = "multi_thread")]
async fn test_sign_request_unknown_key_returns_failure() {
    setup();
    let mut agent = always_approving_agent();
    let pipe = start(&mut agent);

    let mut client = ClientOptions::new().open(&pipe).unwrap();
    client
        .write_all(&framed_sign_request(
            &test_ed25519_key_blob(),
            b"test data",
            0,
        ))
        .await
        .unwrap();
    let response = read_framed_response(&mut client).await;

    assert_eq!(response[0], 5, "expected FAILURE type byte");

    agent.stop();
}

#[serial]
#[tokio::test(flavor = "multi_thread")]
async fn test_sign_request_rsa_sha512_flag_produces_sha512_signature() {
    setup();
    let mut agent = agent_with_keys(vec![test_rsa_key()]);
    let pipe = start(&mut agent);

    let mut client = ClientOptions::new().open(&pipe).unwrap();
    client
        .write_all(&framed_sign_request(&test_rsa_key_blob(), b"test data", 4))
        .await
        .unwrap();
    let response = read_framed_response(&mut client).await;

    assert_eq!(response[0], 14, "expected SIGN_RESPONSE type byte");
    assert_eq!(
        parse_sign_response_algorithm(&response),
        "rsa-sha2-512",
        "expected SHA-512 algorithm when flags=4"
    );

    agent.stop();
}

#[serial]
#[tokio::test(flavor = "multi_thread")]
async fn test_sign_request_rsa_sha256_flag_produces_sha256_signature() {
    setup();
    let mut agent = agent_with_keys(vec![test_rsa_key()]);
    let pipe = start(&mut agent);

    let mut client = ClientOptions::new().open(&pipe).unwrap();
    client
        .write_all(&framed_sign_request(&test_rsa_key_blob(), b"test data", 2))
        .await
        .unwrap();
    let response = read_framed_response(&mut client).await;

    assert_eq!(response[0], 14, "expected SIGN_RESPONSE type byte");
    assert_eq!(
        parse_sign_response_algorithm(&response),
        "rsa-sha2-256",
        "expected SHA-256 algorithm when flags=2"
    );

    agent.stop();
}

#[serial]
#[tokio::test(flavor = "multi_thread")]
async fn test_sign_request_ecdsa_p256_produces_p256_signature() {
    setup();
    let mut agent = agent_with_keys(vec![test_ecdsa_p256_key()]);
    let pipe = start(&mut agent);

    let mut client = ClientOptions::new().open(&pipe).unwrap();
    client
        .write_all(&framed_sign_request(
            &test_ecdsa_p256_key_blob(),
            b"test data",
            0,
        ))
        .await
        .unwrap();
    let response = read_framed_response(&mut client).await;

    assert_eq!(response[0], 14, "expected SIGN_RESPONSE type byte");
    assert_eq!(
        parse_sign_response_algorithm(&response),
        "ecdsa-sha2-nistp256",
        "expected P-256 algorithm in response"
    );

    agent.stop();
}

#[serial]
#[tokio::test(flavor = "multi_thread")]
async fn test_sign_request_ecdsa_p384_produces_p384_signature() {
    setup();
    let mut agent = agent_with_keys(vec![test_ecdsa_p384_key()]);
    let pipe = start(&mut agent);

    let mut client = ClientOptions::new().open(&pipe).unwrap();
    client
        .write_all(&framed_sign_request(
            &test_ecdsa_p384_key_blob(),
            b"test data",
            0,
        ))
        .await
        .unwrap();
    let response = read_framed_response(&mut client).await;

    assert_eq!(response[0], 14, "expected SIGN_RESPONSE type byte");
    assert_eq!(
        parse_sign_response_algorithm(&response),
        "ecdsa-sha2-nistp384",
        "expected P-384 algorithm in response"
    );

    agent.stop();
}

#[serial]
#[tokio::test(flavor = "multi_thread")]
async fn test_sign_request_ecdsa_p521_produces_p521_signature() {
    setup();
    let mut agent = agent_with_keys(vec![test_ecdsa_p521_key()]);
    let pipe = start(&mut agent);

    let mut client = ClientOptions::new().open(&pipe).unwrap();
    client
        .write_all(&framed_sign_request(
            &test_ecdsa_p521_key_blob(),
            b"test data",
            0,
        ))
        .await
        .unwrap();
    let response = read_framed_response(&mut client).await;

    assert_eq!(response[0], 14, "expected SIGN_RESPONSE type byte");
    assert_eq!(
        parse_sign_response_algorithm(&response),
        "ecdsa-sha2-nistp521",
        "expected P-521 algorithm in response"
    );

    agent.stop();
}

#[serial]
#[tokio::test(flavor = "multi_thread")]
async fn test_sign_request_unsupported_key_type_returns_failure() {
    setup();
    // Agent has valid keys loaded; the sign request references a DSA key, which is
    // unsupported and can never be stored, so the agent must return FAILURE.
    let mut agent = agent_with_keys(vec![test_ed25519_key()]);
    let pipe = start(&mut agent);

    let mut client = ClientOptions::new().open(&pipe).unwrap();
    client
        .write_all(&framed_sign_request(
            &unsupported_dsa_key_blob(),
            b"test data",
            0,
        ))
        .await
        .unwrap();
    let response = read_framed_response(&mut client).await;

    assert_eq!(response[0], 5, "expected FAILURE for unsupported key type");

    agent.stop();
}

#[serial]
#[tokio::test(flavor = "multi_thread")]
async fn test_session_bind_valid_returns_success() {
    setup();
    let mut agent = always_approving_agent();
    let pipe = start(&mut agent);

    let mut client = ClientOptions::new().open(&pipe).unwrap();
    client
        .write_all(&framed_session_bind_extension(false))
        .await
        .unwrap();
    let response = read_framed_response(&mut client).await;

    assert_eq!(
        response[0], 6,
        "expected SSH_AGENT_SUCCESS for valid session-bind"
    );

    agent.stop();
}

#[serial]
#[tokio::test(flavor = "multi_thread")]
async fn test_session_bind_forwarding_returns_success() {
    setup();
    let mut agent = always_approving_agent();
    let pipe = start(&mut agent);

    let mut client = ClientOptions::new().open(&pipe).unwrap();
    client
        .write_all(&framed_session_bind_extension(true))
        .await
        .unwrap();
    let response = read_framed_response(&mut client).await;

    assert_eq!(
        response[0], 6,
        "expected SSH_AGENT_SUCCESS for forwarding session-bind"
    );

    agent.stop();
}

#[serial]
#[tokio::test(flavor = "multi_thread")]
async fn test_session_bind_invalid_signature_returns_failure() {
    setup();
    let mut agent = always_approving_agent();
    let pipe = start(&mut agent);

    let mut client = ClientOptions::new().open(&pipe).unwrap();
    client
        .write_all(&framed_invalid_session_bind_extension())
        .await
        .unwrap();
    let response = read_framed_response(&mut client).await;

    assert_eq!(
        response[0], 5,
        "expected FAILURE for invalid session-bind payload"
    );

    agent.stop();
}

#[serial]
#[tokio::test(flavor = "multi_thread")]
async fn test_session_bind_is_forwarding_reaches_approval_layer() {
    setup();

    let mut requester = MockApprovalRequester::new();
    requester
        .expect_request_sign_approval()
        .once()
        .withf(|req| {
            req.sign_request
                .connection
                .session_bind
                .as_ref()
                .is_some_and(|s| s.is_forwarding)
        })
        .returning(|_| Ok(true));

    let mut agent = BitwardenSSHAgent::new(InMemoryEncryptedKeyStore::new(), requester);
    agent.replace(vec![test_ed25519_key()]).unwrap();
    let pipe = start(&mut agent);

    let mut client = ClientOptions::new().open(&pipe).unwrap();

    client
        .write_all(&framed_session_bind_extension(true))
        .await
        .unwrap();
    let bind_response = read_framed_response(&mut client).await;
    assert_eq!(bind_response[0], 6, "session-bind should succeed");

    client
        .write_all(&framed_sign_request(
            &test_ed25519_key_blob(),
            b"test data",
            0,
        ))
        .await
        .unwrap();
    let sign_response = read_framed_response(&mut client).await;
    assert_eq!(sign_response[0], 14, "expected SIGN_RESPONSE");

    agent.stop();
}
