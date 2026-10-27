//! SSH Agent napi:
//! - Wraps the agent to provide access from Electron.
//! - Sets up the callback handlers for the agent to request approval for ssh agent server
//!   operations to Electron.

#[napi]
pub mod sshagent {
    use std::{sync::Arc, time::Duration};

    use async_trait::async_trait;
    use napi::{
        bindgen_prelude::{JsValuesTupleIntoVec, Promise},
        threadsafe_function::ThreadsafeFunction,
    };
    use ssh_agent::{
        ApprovalError, ApprovalRequester, BitwardenSSHAgent, InMemoryEncryptedKeyStore,
        SIGNamespace as SSHSIGNamespace, SignApprovalRequest as SSHSignApprovalRequest,
        UnparsedSSHKeyData,
    };
    use tokio::time::timeout;
    use tracing::{debug, error};

    /// Timeout for Electron approval callbacks
    const APPROVAL_CALLBACK_TIMEOUT: Duration = Duration::from_secs(60);

    /// SSH key data, sent from Electron.
    // NOTE: the public key is derived from the private key.
    #[napi(object)]
    pub struct SSHKeyData {
        pub private_key: String,
        pub name: String,
        pub cipher_id: String,
    }

    /// SSH public key data
    #[napi(object)]
    #[derive(Debug, Clone)]
    pub struct PublicKey {
        pub alg: String,
        pub blob: Vec<u8>,
    }

    /// A sign request's SIG namespace
    #[napi(string_enum = "camelCase")]
    #[derive(Debug)]
    pub enum SIGNamespace {
        Git,
        File,
        Unsupported,
    }

    impl From<SSHSIGNamespace> for SIGNamespace {
        fn from(ns: SSHSIGNamespace) -> Self {
            match ns {
                SSHSIGNamespace::Git => Self::Git,
                SSHSIGNamespace::File => Self::File,
                SSHSIGNamespace::Unsupported => Self::Unsupported,
            }
        }
    }

    /// SSH sign request fields.
    #[napi(object)]
    #[derive(Debug)]
    pub struct SignRequest {
        pub public_key: PublicKey,
        pub process_name: Option<String>,
        pub is_forwarding: bool,
        pub namespace: Option<SIGNamespace>,
        pub host_fingerprint: Option<String>,
    }

    impl From<ssh_agent::SignRequest> for SignRequest {
        fn from(r: ssh_agent::SignRequest) -> Self {
            Self {
                public_key: PublicKey {
                    alg: r.public_key.alg,
                    blob: r.public_key.blob,
                },
                process_name: r.connection.process_name,
                is_forwarding: r
                    .connection
                    .session_bind
                    .as_ref()
                    .is_some_and(|s| s.is_forwarding),
                namespace: r.namespace.map(Into::into),
                host_fingerprint: r.connection.session_bind.map(|s| s.host_fingerprint),
            }
        }
    }

    /// Data for a sign request, including vault cipher context.
    #[napi(object)]
    #[derive(Debug)]
    pub struct SignRequestData {
        /// Identifies this request so it can be withdrawn if the client goes away.
        pub request_id: u32,
        pub sign_request: SignRequest,
        pub cipher_id: Option<String>,
    }

    impl From<SSHSignApprovalRequest> for SignRequestData {
        fn from(request: SSHSignApprovalRequest) -> Self {
            Self {
                // Unique only while a prompt is open, so it fits in a JS number without loss.
                request_id: request.sign_request.request_id as u32,
                sign_request: request.sign_request.into(),
                cipher_id: request.cipher_id,
            }
        }
    }

    /// Wrapper for Electron to be able to interface with the agent directly.
    #[napi]
    pub struct SSHAgentState {
        agent: BitwardenSSHAgent<InMemoryEncryptedKeyStore, ElectronApprovalRequester>,
    }

    /// Interface for the agent to request approval for ssh operations from Electron.
    struct ElectronApprovalRequester {
        sign_callback: Arc<ThreadsafeFunction<SignRequestData, Promise<bool>>>,
        list_callback: Arc<ThreadsafeFunction<u32, Promise<bool>>>,
        /// Tells Electron that a pending approval is no longer needed, so its prompt can close.
        cancel_callback: Arc<ThreadsafeFunction<u32, Promise<()>>>,
    }

    async fn invoke_callback<T: 'static + JsValuesTupleIntoVec>(
        callback: &ThreadsafeFunction<T, Promise<bool>>,
        arg: T,
    ) -> Result<bool, ApprovalError> {
        timeout(APPROVAL_CALLBACK_TIMEOUT, async {
            let promise = callback
                .call_async(Ok(arg))
                .await
                .map_err(|e| ApprovalError::HandlerFailed(e.into()))?;
            promise
                .await
                .map_err(|e| ApprovalError::HandlerFailed(e.into()))
        })
        .await
        .map_err(|_| ApprovalError::Timeout)
        .flatten()
    }

    #[async_trait]
    impl ApprovalRequester for ElectronApprovalRequester {
        async fn request_sign_approval(
            &self,
            request: SSHSignApprovalRequest,
        ) -> Result<bool, ApprovalError> {
            debug!("Sending sign approval request to Electron.");

            let is_approved =
                invoke_callback(&self.sign_callback, SignRequestData::from(request)).await?;

            debug!(%is_approved, "Sign approval response from Electron.");

            Ok(is_approved)
        }

        async fn request_list_approval(&self, request_id: u64) -> Result<bool, ApprovalError> {
            debug!(request_id, "Sending list approval request to Electron.");

            let is_approved = invoke_callback(&self.list_callback, request_id as u32).await?;

            debug!(%is_approved, "List approval response from Electron.");

            Ok(is_approved)
        }

        async fn cancel_approval(&self, request_id: u64) {
            debug!(
                request_id,
                "Telling Electron to abandon a pending approval."
            );

            // Best effort: the client is already gone, so a failed delivery loses nothing.
            if let Err(error) = self.cancel_callback.call_async(Ok(request_id as u32)).await {
                debug!(%error, request_id, "Failed to deliver approval cancellation");
            }
        }
    }

    #[napi]
    impl SSHAgentState {
        /// Creates a new [`BitwardenSSHAgent`] and starts the server.
        ///
        /// # Arguments
        ///
        /// * `sign_callback` - Approval for sign requests
        /// * `list_callback` - Approval for list-keys requests
        /// * `cancel_callback` - Withdraws a pending approval whose client disconnected
        #[napi(factory)]
        #[allow(clippy::unused_async)]
        pub async fn serve(
            sign_callback: ThreadsafeFunction<SignRequestData, Promise<bool>>,
            list_callback: ThreadsafeFunction<u32, Promise<bool>>,
            cancel_callback: ThreadsafeFunction<u32, Promise<()>>,
        ) -> napi::Result<Self> {
            debug!("Creating agent and starting server.");

            let approval_handler = ElectronApprovalRequester {
                sign_callback: Arc::new(sign_callback),
                list_callback: Arc::new(list_callback),
                cancel_callback: Arc::new(cancel_callback),
            };

            let keystore = InMemoryEncryptedKeyStore::default();

            let mut agent = ssh_agent::BitwardenSSHAgent::new(keystore, approval_handler);

            // TODO after PM-31827 is merged, can use simplified error conversion
            agent.start().map_err(|error| {
                error!(%error, "Failed to start the server.");
                napi::Error::from_reason(error.to_string())
            })?;

            debug!("Server started, returning agent state object.");

            Ok(Self { agent })
        }

        #[napi]
        pub fn stop(&mut self) {
            self.agent.stop();
        }

        #[napi]
        pub fn is_running(&self) -> bool {
            self.agent.is_running()
        }

        #[napi]
        pub fn replace(&mut self, new_keys: Vec<SSHKeyData>) -> napi::Result<()> {
            let keys = new_keys
                .into_iter()
                .map(|k| UnparsedSSHKeyData {
                    private_key_pem: k.private_key,
                    name: k.name,
                    cipher_id: k.cipher_id,
                })
                .collect();

            self.agent
                .replace(ssh_agent::SSHKeyData::from_private_key_pems(keys))
                .map_err(|e| napi::Error::from_reason(e.to_string()))
        }
    }
}
