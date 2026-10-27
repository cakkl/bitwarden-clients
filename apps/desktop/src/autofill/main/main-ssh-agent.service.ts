// FIXME: Update this file to be type safe and remove this and next line
// @ts-strict-ignore
import { createHash } from "node:crypto";

import { ipcMain } from "electron";

import { LogService } from "@bitwarden/common/platform/abstractions/log.service";
import { MessagingService } from "@bitwarden/common/platform/abstractions/messaging.service";
import { sshagent } from "@bitwarden/desktop-napi";

import { SSH_AGENT_IPC_CHANNELS } from "../models/ipc-channels";

/**
 * How long a bridged request is kept before it is abandoned. Slightly longer than the native agent's
 * own 60s approval timeout, so it only fires when a native promise was dropped.
 */
const PENDING_REQUEST_TTL_MS = 65_000;

interface PendingRequest {
  resolve: (accepted: boolean) => void;
  /** Abandons the request if nothing answers it; unref'd so it never keeps the process alive. */
  timer: NodeJS.Timeout;
}

/**
 * Formats a public key fingerprint the way OpenSSH does, so the user can compare it with
 * `ssh-keygen -lf`.
 */
function sshFingerprint(blob: number[]): string | null {
  if (blob == null || blob.length === 0) {
    return null;
  }

  const digest = createHash("sha256").update(Buffer.from(blob)).digest("base64");
  return `SHA256:${digest.replace(/=+$/, "")}`;
}

export class MainSshAgentService {
  // The Rust agent awaits each callback, and answering needs a round trip through the renderer, so
  // this map correlates each reply back to its waiting Promise.
  private pendingRequests = new Map<number, PendingRequest>();
  /** Maps the agent's request id to the id used for the renderer round trip. */
  private agentRequestIds = new Map<number, number>();
  private requestId = 0;
  private agentState: sshagent.SshAgentState;
  /** Closes the approval prompt for a request the agent has given up on. */
  private withdrawApproval: ((requestId: number) => void) | null = null;

  constructor(
    private logService: LogService,
    private messagingService: MessagingService,
  ) {
    this.registerIpcHandlers();
  }

  /** Registers how to close an approval prompt whose SSH client disconnected. */
  setApprovalWithdrawal(withdraw: (requestId: number) => void): void {
    this.withdrawApproval = withdraw;
  }

  private registerIpcHandlers() {
    ipcMain.handle(SSH_AGENT_IPC_CHANNELS.INIT, async () => {
      await this.init();
    });

    ipcMain.handle(SSH_AGENT_IPC_CHANNELS.IS_LOADED, async () => {
      return this.agentState?.isRunning() ?? false;
    });

    ipcMain.handle(
      SSH_AGENT_IPC_CHANNELS.REPLACE,
      async (_, keys: { name: string; privateKey: string; cipherId: string }[]) => {
        if (this.agentState != null && this.agentState.isRunning()) {
          this.agentState.replace(keys);
        }
      },
    );

    ipcMain.handle(
      SSH_AGENT_IPC_CHANNELS.SIGN_REQUEST_RESPONSE,
      async (_, { requestId, accepted }: { requestId: number; accepted: boolean }) => {
        this.settlePending(requestId, accepted);
      },
    );

    ipcMain.handle(SSH_AGENT_IPC_CHANNELS.STOP, async () => {
      if (this.agentState != null) {
        this.agentState.stop();
        this.agentState = null;
      }
      this.settleAllPending("the SSH agent was stopped");
    });

    ipcMain.handle(
      SSH_AGENT_IPC_CHANNELS.LIST_KEYS_RESPONSE,
      async (_, { requestId, accepted }: { requestId: number; accepted: boolean }) => {
        this.settlePending(requestId, accepted);
      },
    );
  }

  // Starts the Agent.
  // @pre: The agent must not be running. The caller may utilize `is_running()` and `stop()`.
  private async init() {
    const signCb = (_err: Error | null, data: sshagent.SignRequestData) => this.requestSign(data);
    const listCb = (_err: Error | null, agentRequestId: number) =>
      this.requestListKeys(agentRequestId);
    // Fired when the SSH client goes away while the user is still deciding.
    const cancelCb = async (_err: Error | null, agentRequestId: number): Promise<undefined> => {
      this.withdrawApprovalFor(agentRequestId);
      // The native side only awaits completion, so the value itself carries no meaning.
      return undefined;
    };
    try {
      this.agentState = await sshagent.SshAgentState.serve(signCb, listCb, cancelCb);
      this.logService.info("SSH agent started");
    } catch (e: unknown) {
      this.logService.error("SSH agent encountered an error: ", e);
      this.settleAllPending("the SSH agent failed to start");
    }
  }

  /**
   * Withdraws the prompt for a request the agent abandoned. The agent's id is translated through
   * {@link agentRequestIds}, since sign and list requests draw their ids from different sources.
   */
  private withdrawApprovalFor(agentRequestId: number): void {
    const requestId = this.agentRequestIds.get(agentRequestId);
    if (requestId == null) {
      return;
    }

    this.logService.info(`SSH client disconnected; withdrawing approval for request ${requestId}.`);
    this.withdrawApproval?.(requestId);

    // The agent dropped the callback, so no answer will ever arrive; settle now rather than at the TTL.
    this.settlePending(requestId, false);
  }

  private requestListKeys(agentRequestId: number): Promise<boolean> {
    const id = ++this.requestId;
    // Lets a disconnect settle this request instead of leaving it parked.
    this.agentRequestIds.set(agentRequestId, id);
    return this.createPendingRequest(id, () => {
      this.messagingService.send(SSH_AGENT_IPC_CHANNELS.LIST_KEYS_REQUEST, { requestId: id });
    });
  }

  private requestSign(data: sshagent.SignRequestData): Promise<boolean> {
    const id = ++this.requestId;
    this.agentRequestIds.set(data.requestId, id);
    return this.createPendingRequest(id, () => {
      this.messagingService.send(SSH_AGENT_IPC_CHANNELS.SIGN_REQUEST, {
        cipherId: data.cipherId,
        requestId: id,
        // Stamped on arrival: the agent's timeout is already running while the vault is unlocked.
        receivedAt: Date.now(),
        processName: data.signRequest.processName,
        isAgentForwarding: data.signRequest.isForwarding,
        namespace: data.signRequest.namespace,
        hostFingerprint: data.signRequest.hostFingerprint,
        keyFingerprint: sshFingerprint(data.signRequest.publicKey?.blob),
      });
    });
  }

  /** Parks a request until the renderer answers it, resolving exactly once. */
  private createPendingRequest(id: number, sendToRenderer: () => void): Promise<boolean> {
    return new Promise<boolean>((resolve) => {
      const timer = setTimeout(() => {
        this.logService.warning(
          `SSH agent request ${id} was never answered; abandoning it after ${PENDING_REQUEST_TTL_MS}ms.`,
        );
        this.settlePending(id, false);
      }, PENDING_REQUEST_TTL_MS);
      timer.unref?.();

      this.pendingRequests.set(id, { resolve, timer });
      sendToRenderer();
    });
  }

  /** Resolves a parked request and forgets it. Safe to call for an unknown id. */
  private settlePending(requestId: number, accepted: boolean): void {
    const pending = this.pendingRequests.get(requestId);
    if (pending == null) {
      // Already answered, abandoned, or never ours.
      return;
    }

    this.pendingRequests.delete(requestId);
    clearTimeout(pending.timer);
    pending.resolve(accepted);

    // Drop the translation entry so an abandoned request cannot be matched twice.
    for (const [agentRequestId, jsRequestId] of this.agentRequestIds) {
      if (jsRequestId === requestId) {
        this.agentRequestIds.delete(agentRequestId);
        break;
      }
    }
  }

  /** Abandons every parked request, e.g. when the agent stops. */
  private settleAllPending(reason: string): void {
    if (this.pendingRequests.size === 0) {
      return;
    }

    this.logService.info(
      `Abandoning ${this.pendingRequests.size} pending SSH agent request(s): ${reason}`,
    );

    for (const requestId of [...this.pendingRequests.keys()]) {
      this.settlePending(requestId, false);
    }
  }
}
