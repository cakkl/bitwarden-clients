/**
 * A sign request that needs approval. Sent by the renderer, the only process holding the decrypted
 * vault, and drawn by a dedicated main-process window.
 */
export interface SshApprovalPrompt {
  /** Name of the vault item that holds the key being used. */
  cipherName: string;
  /** Process that asked for the signature, or a localized stand-in when it is unknown. */
  applicationName: string;
  /** Whether the request arrived over agent forwarding. */
  isAgentForwarding: boolean;
  /** i18n key describing the operation, e.g. `sshActionGitSign`. */
  actionI18nKey: string;
  /** OpenSSH-style fingerprint, so it can be matched against `ssh-keygen -lf`. */
  keyFingerprint: string | null;
  /** Epoch ms at which the agent asked for approval; the agent's own 60s budget starts here. */
  receivedAt: number;
}

/** A prompt with every string already resolved, as handed to the approval window. */
export interface SshApprovalView {
  requestId: number;
  /** Resolved user theme, so the prompt matches the app it belongs to. */
  theme: SshApprovalTheme;
  question: string;
  applicationName: string;
  cipherName: string;
  /** Empty when the agent could not report it; the window then hides the meta line. */
  keyFingerprint: string;
  action: string;
  isAgentForwarding: boolean;
  forwardedLabel: string;
  authorizeLabel: string;
  denyLabel: string;
  /** Total time the prompt is shown for; drawn as a countdown bar. */
  timeoutMs: number;
  /** Epoch milliseconds at which the request is denied automatically. */
  expiresAt: number;
}

export type SshApprovalTheme = "light" | "dark";
