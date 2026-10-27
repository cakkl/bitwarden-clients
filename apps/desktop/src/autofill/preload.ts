import { ipcRenderer } from "electron";

import { DesktopAutofillPreload } from "./desktop-autofill.preload";
import { AutotypeConfig } from "./models/autotype-config";
import { AutotypeMatchError } from "./models/autotype-errors";
import { AutotypeVaultData } from "./models/autotype-vault-data";
import { AUTOTYPE_MVP_IPC_CHANNELS, SSH_AGENT_IPC_CHANNELS } from "./models/ipc-channels";
import { SshApprovalPrompt, SshApprovalView } from "./models/ssh-agent-approval";

const sshAgent = {
  init: async () => {
    await ipcRenderer.invoke(SSH_AGENT_IPC_CHANNELS.INIT);
  },
  replace: (keys: { name: string; privateKey: string; cipherId: string }[]): Promise<void> =>
    ipcRenderer.invoke(SSH_AGENT_IPC_CHANNELS.REPLACE, keys),
  signRequestResponse: async (requestId: number, accepted: boolean) => {
    await ipcRenderer.invoke(SSH_AGENT_IPC_CHANNELS.SIGN_REQUEST_RESPONSE, { requestId, accepted });
  },
  listRequestResponse: async (requestId: number, accepted: boolean) => {
    await ipcRenderer.invoke(SSH_AGENT_IPC_CHANNELS.LIST_KEYS_RESPONSE, { requestId, accepted });
  },
  isLoaded(): Promise<boolean> {
    return ipcRenderer.invoke(SSH_AGENT_IPC_CHANNELS.IS_LOADED);
  },
  stop: async () => ipcRenderer.invoke(SSH_AGENT_IPC_CHANNELS.STOP),
  /** Shows the approval window and resolves with the decision (`false` on timeout or dismissal). */
  requestApproval: (prompt: SshApprovalPrompt): Promise<boolean> =>
    ipcRenderer.invoke(SSH_AGENT_IPC_CHANNELS.APPROVAL_REQUEST, prompt),
  /** Approval window only: the request currently on screen, if any. */
  getApproval: (): Promise<SshApprovalView | null> =>
    ipcRenderer.invoke(SSH_AGENT_IPC_CHANNELS.APPROVAL_GET),
  /** Approval window only: fires when a queued request replaces the current one. */
  onApprovalChanged: (callback: (view: SshApprovalView) => void): void => {
    ipcRenderer.on(SSH_AGENT_IPC_CHANNELS.APPROVAL_CHANGED, (_event, view: SshApprovalView) =>
      callback(view),
    );
  },
  /** Approval window only: answers the request currently on screen. */
  respondApproval: async (requestId: number, accepted: boolean) => {
    await ipcRenderer.invoke(SSH_AGENT_IPC_CHANNELS.APPROVAL_RESPONSE, { requestId, accepted });
  },
  /** Denies anything on screen, e.g. because the vault locked while the prompt was open. */
  cancelApprovals: async () => {
    await ipcRenderer.invoke(SSH_AGENT_IPC_CHANNELS.APPROVAL_CANCEL);
  },
  /** Approval window only: reports the height its content needs, so the window fits the prompt. */
  resizeApproval: async (contentHeight: number) => {
    await ipcRenderer.invoke(SSH_AGENT_IPC_CHANNELS.APPROVAL_RESIZE, contentHeight);
  },
};

// MVP, delete with PM-41067
const autotypeMvp = {
  configure: (config: AutotypeConfig) => {
    ipcRenderer.send(AUTOTYPE_MVP_IPC_CHANNELS.CONFIGURE, config);
  },
  toggle: (enable: boolean) => {
    ipcRenderer.send(AUTOTYPE_MVP_IPC_CHANNELS.TOGGLE, enable);
  },
  listenRequest: (
    fn: (
      windowTitle: string,
      completeCallback: (error: Error | null, response: AutotypeVaultData | null) => void,
    ) => void,
  ) => {
    ipcRenderer.on(
      AUTOTYPE_MVP_IPC_CHANNELS.LISTEN,
      (
        _event,
        data: {
          windowTitle: string;
        },
      ) => {
        const { windowTitle } = data;

        fn(windowTitle, (error, vaultData) => {
          if (error) {
            const matchError: AutotypeMatchError = {
              windowTitle,
              errorMessage: error.message,
            };
            ipcRenderer.send(AUTOTYPE_MVP_IPC_CHANNELS.EXECUTION_ERROR, matchError);
            return;
          }

          if (vaultData !== null) {
            ipcRenderer.send(AUTOTYPE_MVP_IPC_CHANNELS.EXECUTE, vaultData);
          }
        });
      },
    );
  },
};

export default {
  desktopAutofill: DesktopAutofillPreload,

  sshAgent,

  autotypeMvp,
};
