//! SSH agent client connection and connection handler

use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, trace, warn};

use super::{
    auth_policy::{AuthPolicy, AuthRequest, ConnectionContext, SessionBindContext, SignRequest},
    peer_info::PeerInfo,
    protocol::{
        build_identities_answer, build_sign_response, detect_namespace, failure, frame,
        parse_message, read_ssh_string, success, AgentMessage, SignFlags, EXTENSION,
    },
    session_bind::SessionBindState,
    KeyStore,
};
use crate::crypto::{PublicKey, SignablePrivateKey};

// Guards against oversized allocations from untrusted length prefixes on the socket.
const MAX_MESSAGE_LEN: usize = 256 * 1024;
const SESSION_BIND_EXTENSION: &[u8] = b"session-bind@openssh.com";

/// Lets a pending approval be traced back to the request it belongs to.
static NEXT_REQUEST_ID: AtomicU64 = AtomicU64::new(1);

/// An accepted connection from an SSH agent client, bundling the I/O stream
/// with information about the connecting peer.
pub(crate) struct Connection<S> {
    /// The I/O stream for this connection
    pub(crate) stream: S,
    /// Information about the connected peer process, if available
    pub(crate) peer_info: Option<PeerInfo>,
}

/// Handles an individual SSH agent client connection
pub(crate) struct ConnectionHandler<K, A, S> {
    keystore: Arc<K>,
    auth_policy: Arc<A>,
    connection: Connection<S>,
    token: CancellationToken,
}

impl<K, A, S> ConnectionHandler<K, A, S>
where
    K: KeyStore,
    A: AuthPolicy,
    S: AsyncRead + AsyncWrite + Unpin,
{
    /// Create a new connection handler
    pub fn new(
        keystore: Arc<K>,
        auth_policy: Arc<A>,
        connection: Connection<S>,
        token: CancellationToken,
    ) -> Self {
        Self {
            keystore,
            auth_policy,
            connection,
            token,
        }
    }

    /// Handle incoming SSH agent protocol messages from the client.
    ///
    /// Reads length-prefixed SSH agent protocol frames in a loop, dispatches each
    /// message to the appropriate handler, and writes the framed response back.
    /// Exits on cancellation, EOF, or unrecoverable I/O error.
    pub async fn handle(mut self) {
        debug!(peer_info = ?self.connection.peer_info, "handler starting");

        let mut session_bind_state = SessionBindState::default();
        // Read while a decision was pending; replayed by the framing loop.
        let mut buffered: Vec<u8> = Vec::new();

        loop {
            let mut len_buf = [0u8; 4];

            // Read the 4-byte length prefix, yielding to cancellation.
            debug!("handler reading length");
            if read_or_cancel(
                &mut self.connection.stream,
                &mut len_buf,
                &self.token,
                &mut buffered,
            )
            .await
            {
                break;
            }

            let msg_len = u32::from_be_bytes(len_buf) as usize;
            if msg_len > MAX_MESSAGE_LEN {
                warn!(
                    msg_len,
                    "Message length exceeds maximum, closing connection"
                );
                break;
            }
            let mut msg = vec![0u8; msg_len];

            // Read the message body, yielding to cancellation.
            debug!("handler reading message");
            if read_or_cancel(
                &mut self.connection.stream,
                &mut msg,
                &self.token,
                &mut buffered,
            )
            .await
            {
                break;
            }

            if msg.is_empty() {
                debug!("handler skipping empty message");
                continue;
            }

            // Pass Arc clones rather than &self to avoid requiring S: Sync
            let response = if msg.first() == Some(&EXTENSION) {
                handle_extension_message(&msg[1..], &mut session_bind_state)
            } else {
                let request_id = NEXT_REQUEST_ID.fetch_add(1, Ordering::Relaxed);

                // Race the decision against the client going away, so an abandoned request does not
                // keep its approval on screen.
                let decision = handle_message(
                    &msg,
                    self.connection.peer_info.as_ref(),
                    &session_bind_state,
                    &self.keystore,
                    &self.auth_policy,
                    request_id,
                );
                tokio::pin!(decision);

                let mut abandoned = false;
                let response = loop {
                    tokio::select! {
                        response = &mut decision => break response,
                        peer = watch_peer(&mut self.connection.stream, &mut buffered, &self.token) => {
                            match peer {
                                PeerState::Data => continue,
                                PeerState::Closed => {
                                    // The request already failed, so withdraw rather than leave the
                                    // prompt up. Not awaited: an approver that never answers must not
                                    // pin this task.
                                    self.auth_policy.cancel(request_id).await;
                                    abandoned = true;
                                    break Vec::new();
                                }
                            }
                        }
                    }
                };

                if abandoned {
                    info!("Client disconnected while a request was being authorized, closing");
                    break;
                }

                response
            };

            if let Err(error) = self.connection.stream.write_all(&frame(response)).await {
                error!(%error, "Failed to write response, closing connection");
                break;
            }
        }

        debug!("handler finished");
    }
}

/// What a watched socket did while a request was being authorized.
enum PeerState {
    /// More data arrived: a pipelined request, not a disconnect.
    Data,
    /// The client closed the connection, or the handler was cancelled.
    Closed,
}

/// Waits for the peer to close the connection, or for the handler to be cancelled.
///
/// Any byte read is buffered so the framing loop can replay a pipelined request.
async fn watch_peer<S: AsyncRead + Unpin>(
    stream: &mut S,
    buffered: &mut Vec<u8>,
    token: &CancellationToken,
) -> PeerState {
    let mut byte = [0u8; 1];

    tokio::select! {
        () = token.cancelled() => {
            debug!("handler received cancellation signal while awaiting a decision");
            PeerState::Closed
        }
        result = stream.read(&mut byte) => match result {
            Ok(0) => {
                trace!("Connection closed while awaiting a decision");
                PeerState::Closed
            }
            Ok(_) => {
                buffered.push(byte[0]);
                PeerState::Data
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => PeerState::Data,
            Err(error) => {
                debug!(%error, "I/O error while awaiting a decision");
                PeerState::Closed
            }
        },
    }
}

/// Fills `buf` from `stream`, serving buffered bytes first. Returns `true` when the caller should
/// break (cancelled or I/O error).
async fn read_or_cancel<S: AsyncRead + Unpin>(
    stream: &mut S,
    buf: &mut [u8],
    token: &CancellationToken,
    buffered: &mut Vec<u8>,
) -> bool {
    let mut filled = 0;
    while filled < buf.len() && !buffered.is_empty() {
        let take = (buf.len() - filled).min(buffered.len());
        buf[filled..filled + take].copy_from_slice(&buffered[..take]);
        buffered.drain(..take);
        filled += take;
    }
    if filled == buf.len() {
        return false;
    }

    tokio::select! {
        () = token.cancelled() => {
            debug!("handler received cancellation signal");
            true
        }
        result = stream.read_exact(&mut buf[filled..]) => match result {
            Ok(_) => false,
            Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => {
                trace!("Connection closed");
                true
            }
            Err(error) => {
                error!(%error, "I/O error on connection");
                true
            }
        },
    }
}

fn handle_extension_message(payload: &[u8], session_bind_state: &mut SessionBindState) -> Vec<u8> {
    let Some((name, rest)) = read_ssh_string(payload) else {
        return failure();
    };
    match name {
        SESSION_BIND_EXTENSION => handle_session_bind(rest, session_bind_state),
        _ => {
            warn!(
                name = std::str::from_utf8(name).unwrap_or("<non-utf8>"),
                "Received unsupported extension"
            );
            failure()
        }
    }
}

fn handle_session_bind(payload: &[u8], session_bind_state: &mut SessionBindState) -> Vec<u8> {
    if session_bind_state.parse_and_verify(payload) {
        success()
    } else {
        warn!("session-bind verification failed");
        failure()
    }
}

async fn handle_message<K: KeyStore, A: AuthPolicy>(
    msg: &[u8],
    peer_info: Option<&PeerInfo>,
    session_bind_state: &SessionBindState,
    keystore: &Arc<K>,
    auth_policy: &Arc<A>,
    request_id: u64,
) -> Vec<u8> {
    let Some(message) = parse_message(msg) else {
        error!("Received malformed message");
        return failure();
    };

    match message {
        AgentMessage::RequestIdentities => {
            handle_list_request(keystore, auth_policy, request_id).await
        }
        AgentMessage::SignRequest {
            public_key,
            data,
            flags,
        } => {
            handle_sign_request(
                public_key,
                data,
                flags,
                ConnectionContext {
                    process_name: peer_info.map(|p| p.process_name().to_string()),
                    session_bind: if session_bind_state.host_fingerprint.is_empty() {
                        None
                    } else {
                        Some(SessionBindContext {
                            is_forwarding: session_bind_state.is_forwarding,
                            host_fingerprint: session_bind_state.host_fingerprint.clone(),
                        })
                    },
                },
                keystore,
                auth_policy,
                request_id,
            )
            .await
        }
        AgentMessage::Unknown(msg_type) => {
            debug!(msg_type, "Received unhandled message type");
            failure()
        }
    }
}

async fn handle_list_request<K: KeyStore, A: AuthPolicy>(
    keystore: &Arc<K>,
    auth_policy: &Arc<A>,
    request_id: u64,
) -> Vec<u8> {
    debug!("handling list request");

    let Ok(authorized) = auth_policy
        .authorize(&AuthRequest::List { request_id })
        .await
        .inspect_err(|error| error!(%error, "Authorization error for list request"))
    else {
        return failure();
    };

    if !authorized {
        info!("List request denied.");
        return failure();
    }

    match keystore.get_all_public_keys_and_names() {
        Ok(keys) => build_identities_answer(keys),
        Err(error) => {
            error!(%error, "Failed to retrieve keys from keystore");
            failure()
        }
    }
}

async fn handle_sign_request<K: KeyStore, A: AuthPolicy>(
    public_key: PublicKey,
    data: Vec<u8>,
    flags: Option<SignFlags>,
    connection: ConnectionContext,
    keystore: &Arc<K>,
    auth_policy: &Arc<A>,
    request_id: u64,
) -> Vec<u8> {
    debug!("handling sign request");

    let sign_request = SignRequest {
        request_id,
        public_key: public_key.clone(),
        namespace: detect_namespace(&data),
        connection,
    };

    let Ok(authorized) = auth_policy
        .authorize(&AuthRequest::Sign(sign_request))
        .await
        .inspect_err(|error| error!(%error, "Sign request authorization error"))
    else {
        return failure();
    };

    if !authorized {
        debug!("Sign request denied by auth policy");
        return failure();
    }

    let Ok(maybe_key) = keystore
        .get_private_key(&public_key)
        .inspect_err(|error| error!(%error, "Failed to retrieve key from keystore"))
    else {
        return failure();
    };

    let Some(private_key) = maybe_key else {
        warn!("Key not found in keystore");
        return failure();
    };

    let Ok(signing_key) = SignablePrivateKey::try_from((private_key, flags)).inspect_err(
        |error| warn!(%error, ?flags, "Unable to create signable key with provided request input"),
    ) else {
        return failure();
    };

    build_sign_response(&signing_key.sign(&data))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use mockall::predicate::eq;

    use crate::{
        authorization::AuthError,
        crypto::{PrivateKey, PublicKey},
        server::{session_bind::SessionBindState, AuthPolicy, AuthRequest},
        storage::keystore::MockKeyStore,
    };
    const FAILURE: u8 = 5;
    const SUCCESS: u8 = 6;
    const REQUEST_IDENTITIES: u8 = 11;
    const IDENTITIES_ANSWER: u8 = 12;
    const SIGN_REQUEST: u8 = 13;
    const SIGN_RESPONSE: u8 = 14;

    use crate::server::test_common::{
        make_minimal_ed25519_blob, make_session_bind_payload_ed25519, make_sign_request_msg,
        write_ssh_string, AlwaysAllowPolicy,
    };

    fn make_minimal_rsa_blob() -> Vec<u8> {
        let alg = b"ssh-rsa";
        let mut blob = Vec::new();
        blob.extend_from_slice(&(alg.len() as u32).to_be_bytes());
        blob.extend_from_slice(alg);
        blob
    }

    // Builds the slice that handle_extension_message receives: [string name][raw payload]
    fn make_extension_payload(name: &[u8], data: &[u8]) -> Vec<u8> {
        let mut payload = Vec::new();
        write_ssh_string(&mut payload, name);
        payload.extend_from_slice(data);
        payload
    }

    struct ErrorAuthPolicy;

    #[async_trait::async_trait]
    impl AuthPolicy for ErrorAuthPolicy {
        async fn authorize(&self, _: &AuthRequest) -> Result<bool, AuthError> {
            Err(AuthError::KeyNotFound)
        }
    }

    struct AlwaysDenyPolicy;

    #[async_trait::async_trait]
    impl AuthPolicy for AlwaysDenyPolicy {
        async fn authorize(&self, _: &AuthRequest) -> Result<bool, AuthError> {
            Ok(false)
        }
    }

    struct CapturingAuthPolicy {
        captured: std::sync::Mutex<Option<AuthRequest>>,
    }

    #[async_trait::async_trait]
    impl AuthPolicy for CapturingAuthPolicy {
        async fn authorize(&self, req: &AuthRequest) -> Result<bool, AuthError> {
            *self.captured.lock().unwrap() = Some(req.clone());
            Ok(true)
        }
    }

    #[tokio::test]
    async fn unknown_message_type_returns_failure() {
        let keystore = Arc::new(MockKeyStore::new());
        let auth_policy = Arc::new(AlwaysAllowPolicy);

        let response = super::handle_message(
            &[99u8],
            None,
            &SessionBindState::default(),
            &keystore,
            &auth_policy,
            0,
        )
        .await;

        assert_eq!(response, vec![FAILURE]);
    }

    #[tokio::test]
    async fn list_request_when_authorized_returns_identities_answer() {
        let mut keystore = MockKeyStore::new();
        keystore
            .expect_get_all_public_keys_and_names()
            .once()
            .returning(|| {
                Ok(vec![(
                    PublicKey {
                        alg: "ssh-ed25519".to_string(),
                        blob: vec![1, 2, 3],
                    },
                    "Test Key".to_string(),
                )])
            });
        let auth_policy = Arc::new(AlwaysAllowPolicy);

        let response = super::handle_message(
            &[REQUEST_IDENTITIES],
            None,
            &SessionBindState::default(),
            &Arc::new(keystore),
            &auth_policy,
            0,
        )
        .await;

        assert_eq!(response[0], IDENTITIES_ANSWER);
        assert_eq!(u32::from_be_bytes(response[1..5].try_into().unwrap()), 1);
    }

    #[tokio::test]
    async fn list_request_when_denied_returns_failure() {
        let keystore = MockKeyStore::new();
        let auth_policy = Arc::new(AlwaysDenyPolicy);

        let response = super::handle_message(
            &[REQUEST_IDENTITIES],
            None,
            &SessionBindState::default(),
            &Arc::new(keystore),
            &auth_policy,
            0,
        )
        .await;

        assert_eq!(response, vec![FAILURE]);
    }

    #[tokio::test]
    async fn list_request_when_keystore_errors_returns_failure() {
        let mut keystore = MockKeyStore::new();
        keystore
            .expect_get_all_public_keys_and_names()
            .once()
            .returning(|| Err(anyhow::anyhow!("keystore error")));
        let auth_policy = Arc::new(AlwaysAllowPolicy);

        let response = super::handle_message(
            &[REQUEST_IDENTITIES],
            None,
            &SessionBindState::default(),
            &Arc::new(keystore),
            &auth_policy,
            0,
        )
        .await;

        assert_eq!(response, vec![FAILURE]);
    }

    #[tokio::test]
    async fn sign_request_when_authorized_key_found_returns_sign_response() {
        use ssh_key::{private::Ed25519Keypair, rand_core::OsRng};

        let keypair = Ed25519Keypair::random(&mut OsRng);
        let blob = make_minimal_ed25519_blob();
        let expected_public_key = PublicKey {
            alg: "ssh-ed25519".to_string(),
            blob: blob.clone(),
        };

        let private_key = PrivateKey::Ed25519(keypair);
        let mut keystore = MockKeyStore::new();
        keystore
            .expect_get_private_key()
            .with(eq(expected_public_key))
            .once()
            .return_once(move |_| Ok(Some(private_key)));

        let auth_policy = Arc::new(AlwaysAllowPolicy);
        let msg = make_sign_request_msg(&blob, b"test data", 0);

        let response = super::handle_message(
            &msg,
            None,
            &SessionBindState::default(),
            &Arc::new(keystore),
            &auth_policy,
            0,
        )
        .await;

        assert_eq!(response[0], SIGN_RESPONSE);
    }

    #[tokio::test]
    async fn sign_request_when_auth_denied_returns_failure() {
        let keystore = Arc::new(MockKeyStore::new());
        let auth_policy = Arc::new(AlwaysDenyPolicy);
        let blob = make_minimal_ed25519_blob();
        let msg = make_sign_request_msg(&blob, b"test data", 0);

        let response = super::handle_message(
            &msg,
            None,
            &SessionBindState::default(),
            &keystore,
            &auth_policy,
            0,
        )
        .await;

        assert_eq!(response, vec![FAILURE]);
    }

    #[tokio::test]
    async fn sign_request_when_auth_error_returns_failure() {
        let keystore = Arc::new(MockKeyStore::new());
        let auth_policy = Arc::new(ErrorAuthPolicy);
        let blob = make_minimal_ed25519_blob();
        let msg = make_sign_request_msg(&blob, b"test data", 0);

        let response = super::handle_message(
            &msg,
            None,
            &SessionBindState::default(),
            &keystore,
            &auth_policy,
            0,
        )
        .await;

        assert_eq!(response, vec![FAILURE]);
    }

    #[tokio::test]
    async fn sign_request_when_key_not_found_in_keystore_returns_failure() {
        let mut keystore = MockKeyStore::new();
        keystore
            .expect_get_private_key()
            .once()
            .returning(|_| Ok(None));

        let auth_policy = Arc::new(AlwaysAllowPolicy);
        let blob = make_minimal_ed25519_blob();
        let msg = make_sign_request_msg(&blob, b"test data", 0);

        let response = super::handle_message(
            &msg,
            None,
            &SessionBindState::default(),
            &Arc::new(keystore),
            &auth_policy,
            0,
        )
        .await;

        assert_eq!(response, vec![FAILURE]);
    }

    #[tokio::test]
    async fn sign_request_when_keystore_error_returns_failure() {
        let mut keystore = MockKeyStore::new();
        keystore
            .expect_get_private_key()
            .once()
            .returning(|_| Err(anyhow::anyhow!("keystore error")));

        let auth_policy = Arc::new(AlwaysAllowPolicy);
        let blob = make_minimal_ed25519_blob();
        let msg = make_sign_request_msg(&blob, b"test data", 0);

        let response = super::handle_message(
            &msg,
            None,
            &SessionBindState::default(),
            &Arc::new(keystore),
            &auth_policy,
            0,
        )
        .await;

        assert_eq!(response, vec![FAILURE]);
    }

    #[tokio::test]
    async fn sign_request_rsa_without_flags_returns_failure() {
        use ssh_key::{private::RsaKeypair, rand_core::OsRng};

        const MIN_RSA_BITS: usize = 2048;
        let keypair = RsaKeypair::random(&mut OsRng, MIN_RSA_BITS).unwrap();
        let blob = make_minimal_rsa_blob();
        let expected_public_key = PublicKey {
            alg: "ssh-rsa".to_string(),
            blob: blob.clone(),
        };

        let private_key = PrivateKey::Rsa(keypair);
        let mut keystore = MockKeyStore::new();
        keystore
            .expect_get_private_key()
            .with(eq(expected_public_key))
            .once()
            .return_once(move |_| Ok(Some(private_key)));

        let auth_policy = Arc::new(AlwaysAllowPolicy);
        let msg = make_sign_request_msg(&blob, b"test data", 0); // no flags 鈫?would imply SHA-1

        let response = super::handle_message(
            &msg,
            None,
            &SessionBindState::default(),
            &Arc::new(keystore),
            &auth_policy,
            0,
        )
        .await;

        assert_eq!(response, vec![FAILURE]);
    }

    #[tokio::test]
    async fn sign_request_rsa_sha256_flag_produces_sha256_signature() {
        use ssh_key::{private::RsaKeypair, rand_core::OsRng};

        // SSH_AGENT_RSA_SHA2_256 flag
        const RSA_SHA2_256: u32 = 2;

        const MIN_RSA_BITS: usize = 2048;

        let keypair = RsaKeypair::random(&mut OsRng, MIN_RSA_BITS).unwrap();
        let blob = make_minimal_rsa_blob();
        let expected_public_key = PublicKey {
            alg: "ssh-rsa".to_string(),
            blob: blob.clone(),
        };

        let private_key = PrivateKey::Rsa(keypair);
        let mut keystore = MockKeyStore::new();
        keystore
            .expect_get_private_key()
            .with(eq(expected_public_key))
            .once()
            .return_once(move |_| Ok(Some(private_key)));

        let auth_policy = Arc::new(AlwaysAllowPolicy);
        let msg = make_sign_request_msg(&blob, b"test data", RSA_SHA2_256);

        let response = super::handle_message(
            &msg,
            None,
            &SessionBindState::default(),
            &Arc::new(keystore),
            &auth_policy,
            0,
        )
        .await;

        assert_eq!(response[0], SIGN_RESPONSE);
        let alg_len = u32::from_be_bytes(response[5..9].try_into().unwrap()) as usize;
        let alg_str = std::str::from_utf8(&response[9..9 + alg_len]).unwrap();
        assert_eq!(alg_str, "rsa-sha2-256");
    }

    #[test]
    fn extension_truncated_name_returns_failure() {
        let mut state = SessionBindState::default();
        let response = super::handle_extension_message(&[0u8, 1u8, 2u8], &mut state);
        assert_eq!(response, vec![FAILURE]);
    }

    #[test]
    fn extension_unknown_name_returns_failure() {
        let payload = make_extension_payload(b"query", &[]);
        let mut state = SessionBindState::default();
        let response = super::handle_extension_message(&payload, &mut state);
        assert_eq!(response, vec![FAILURE]);
    }

    #[test]
    fn session_bind_invalid_payload_returns_failure() {
        let payload = make_extension_payload(b"session-bind@openssh.com", &[0xDE, 0xAD]);
        let mut state = SessionBindState::default();
        let response = super::handle_extension_message(&payload, &mut state);
        assert_eq!(response, vec![FAILURE]);
        assert!(!state.is_forwarding);
        assert!(state.host_fingerprint.is_empty());
    }

    #[test]
    fn session_bind_valid_not_forwarding_returns_success() {
        use ssh_key::{private::Ed25519Keypair, rand_core::OsRng};

        let keypair = Ed25519Keypair::random(&mut OsRng);
        let bind_payload = make_session_bind_payload_ed25519(&keypair, &[0x42u8; 32], false);
        let payload = make_extension_payload(b"session-bind@openssh.com", &bind_payload);

        let mut state = SessionBindState::default();
        let response = super::handle_extension_message(&payload, &mut state);
        assert_eq!(response, vec![SUCCESS]);
        assert!(!state.is_forwarding);
    }

    #[test]
    fn session_bind_valid_forwarding_returns_success_and_sets_flag() {
        use ssh_key::{private::Ed25519Keypair, rand_core::OsRng};

        let keypair = Ed25519Keypair::random(&mut OsRng);
        let bind_payload = make_session_bind_payload_ed25519(&keypair, &[0x42u8; 32], true);
        let payload = make_extension_payload(b"session-bind@openssh.com", &bind_payload);

        let mut state = SessionBindState::default();
        let response = super::handle_extension_message(&payload, &mut state);
        assert_eq!(response, vec![SUCCESS]);
        assert!(state.is_forwarding);
    }

    #[test]
    fn session_bind_is_forwarding_latched_on_rebind() {
        use ssh_key::{private::Ed25519Keypair, rand_core::OsRng};

        let keypair = Ed25519Keypair::random(&mut OsRng);
        let mut state = SessionBindState::default();

        let forwarding_payload = make_session_bind_payload_ed25519(&keypair, &[0x01u8; 32], true);
        let ext1 = make_extension_payload(b"session-bind@openssh.com", &forwarding_payload);
        let r1 = super::handle_extension_message(&ext1, &mut state);
        assert_eq!(r1, vec![SUCCESS]);
        assert!(
            state.is_forwarding,
            "first bind (forwarding=true) should set flag"
        );

        let not_forwarding_payload =
            make_session_bind_payload_ed25519(&keypair, &[0x02u8; 32], false);
        let ext2 = make_extension_payload(b"session-bind@openssh.com", &not_forwarding_payload);
        let r2 = super::handle_extension_message(&ext2, &mut state);
        assert_eq!(r2, vec![SUCCESS]);
        assert!(
            state.is_forwarding,
            "latch must not be cleared by a non-forwarding rebind"
        );
    }

    #[tokio::test]
    async fn session_bind_is_forwarding_propagates_to_sign_request_auth() {
        use ssh_key::{private::Ed25519Keypair, rand_core::OsRng};

        let keypair = Ed25519Keypair::random(&mut OsRng);
        let bind_payload = make_session_bind_payload_ed25519(&keypair, &[0x42u8; 32], true);
        let ext_payload = make_extension_payload(b"session-bind@openssh.com", &bind_payload);

        let mut state = SessionBindState::default();
        let bind_response = super::handle_extension_message(&ext_payload, &mut state);
        assert_eq!(bind_response, vec![SUCCESS]);
        assert!(state.is_forwarding);

        let blob = make_minimal_ed25519_blob();
        let msg = make_sign_request_msg(&blob, b"test data", 0);

        let mut keystore = MockKeyStore::new();
        keystore
            .expect_get_private_key()
            .once()
            .returning(|_| Ok(None));

        let capturing_policy = Arc::new(CapturingAuthPolicy {
            captured: std::sync::Mutex::new(None),
        });

        let _ = super::handle_message(
            &msg,
            None,
            &state,
            &Arc::new(keystore),
            &capturing_policy,
            0,
        )
        .await;

        let captured = capturing_policy.captured.lock().unwrap();
        if let Some(AuthRequest::Sign(sign_req)) = captured.as_ref() {
            assert!(
                sign_req
                    .connection
                    .session_bind
                    .as_ref()
                    .is_some_and(|s| s.is_forwarding),
                "is_forwarding must propagate to auth"
            );
        } else {
            panic!("expected Sign auth request to be captured");
        }
    }

    #[tokio::test]
    async fn host_fingerprint_propagates_to_sign_request_auth() {
        use ssh_key::{private::Ed25519Keypair, rand_core::OsRng};

        let keypair = Ed25519Keypair::random(&mut OsRng);
        let bind_payload = make_session_bind_payload_ed25519(&keypair, &[0x42u8; 32], true);
        let ext_payload = make_extension_payload(b"session-bind@openssh.com", &bind_payload);

        let mut state = SessionBindState::default();
        super::handle_extension_message(&ext_payload, &mut state);
        let expected_fingerprint = state.host_fingerprint.clone();
        assert!(!expected_fingerprint.is_empty());

        let blob = make_minimal_ed25519_blob();
        let msg = make_sign_request_msg(&blob, b"test data", 0);

        let mut keystore = MockKeyStore::new();
        keystore
            .expect_get_private_key()
            .once()
            .returning(|_| Ok(None));

        let capturing_policy = Arc::new(CapturingAuthPolicy {
            captured: std::sync::Mutex::new(None),
        });

        let _ = super::handle_message(
            &msg,
            None,
            &state,
            &Arc::new(keystore),
            &capturing_policy,
            0,
        )
        .await;

        let captured = capturing_policy.captured.lock().unwrap();
        if let Some(AuthRequest::Sign(sign_req)) = captured.as_ref() {
            assert_eq!(
                sign_req
                    .connection
                    .session_bind
                    .as_ref()
                    .map(|s| s.host_fingerprint.as_str()),
                Some(expected_fingerprint.as_str()),
                "host_fingerprint must propagate to auth request"
            );
        } else {
            panic!("expected Sign auth request to be captured");
        }
    }

    #[tokio::test]
    async fn sign_request_without_session_bind_has_no_host_fingerprint() {
        let blob = make_minimal_ed25519_blob();
        let msg = make_sign_request_msg(&blob, b"test data", 0);

        let mut keystore = MockKeyStore::new();
        keystore
            .expect_get_private_key()
            .once()
            .returning(|_| Ok(None));

        let capturing_policy = Arc::new(CapturingAuthPolicy {
            captured: std::sync::Mutex::new(None),
        });

        let _ = super::handle_message(
            &msg,
            None,
            &SessionBindState::default(),
            &Arc::new(keystore),
            &capturing_policy,
            0,
        )
        .await;

        let captured = capturing_policy.captured.lock().unwrap();
        if let Some(AuthRequest::Sign(sign_req)) = captured.as_ref() {
            assert!(
                sign_req.connection.session_bind.is_none(),
                "session_bind must be None when no session-bind was received"
            );
        } else {
            panic!("expected Sign auth request to be captured");
        }
    }

    #[tokio::test]
    async fn oversized_message_length_closes_connection_without_panic() {
        use tokio::io::{duplex, AsyncWriteExt};
        use tokio_util::sync::CancellationToken;

        let (mut client, server) = duplex(1024);
        let keystore = Arc::new(MockKeyStore::new());
        let auth_policy = Arc::new(AlwaysAllowPolicy);
        let token = CancellationToken::new();

        let handler = super::ConnectionHandler::new(
            keystore,
            auth_policy,
            super::Connection {
                stream: server,
                peer_info: None,
            },
            token,
        );

        // Send a length one byte over the 256 KiB cap
        let oversized_len = (256 * 1024 + 1) as u32;
        client
            .write_all(&oversized_len.to_be_bytes())
            .await
            .unwrap();

        tokio::time::timeout(std::time::Duration::from_secs(1), handler.handle())
            .await
            .expect("handler should exit, denying oversized message length");
    }

    #[tokio::test]
    async fn client_disconnect_while_awaiting_a_decision_closes_the_handler() {
        use tokio::io::{duplex, AsyncWriteExt};
        use tokio_util::sync::CancellationToken;

        /// Stands in for a prompt the user never answers.
        struct PendingApprovalPolicy {
            cancelled: std::sync::Mutex<Vec<u64>>,
        }

        #[async_trait::async_trait]
        impl AuthPolicy for PendingApprovalPolicy {
            async fn authorize(&self, _: &AuthRequest) -> Result<bool, AuthError> {
                std::future::pending::<()>().await;
                unreachable!("authorize never resolves")
            }

            async fn cancel(&self, request_id: u64) {
                self.cancelled.lock().unwrap().push(request_id);
            }
        }

        let (mut client, server) = duplex(1024);
        let keystore = Arc::new(MockKeyStore::new());
        let auth_policy = Arc::new(PendingApprovalPolicy {
            cancelled: std::sync::Mutex::new(Vec::new()),
        });

        let handler = super::ConnectionHandler::new(
            keystore,
            auth_policy.clone(),
            super::Connection {
                stream: server,
                peer_info: None,
            },
            CancellationToken::new(),
        );

        // The handler reads a 4-byte length prefix before the message body.
        let body = make_sign_request_msg(&make_minimal_ed25519_blob(), b"test data", 0);
        let mut framed = (body.len() as u32).to_be_bytes().to_vec();
        framed.extend_from_slice(&body);

        client.write_all(&framed).await.unwrap();

        // Give the handler time to reach the authorization that never resolves.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // The client gives up waiting for the signature.
        drop(client);

        // Without the peer watch this would stay parked until the approval timeout.
        tokio::time::timeout(std::time::Duration::from_secs(1), handler.handle())
            .await
            .expect("handler should exit once the client disconnects");

        // The pending approval must be withdrawn, not left for the user to answer.
        assert_eq!(
            auth_policy.cancelled.lock().unwrap().len(),
            1,
            "expected the abandoned request to be cancelled exactly once"
        );
    }
}
