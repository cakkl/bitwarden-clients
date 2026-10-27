/* eslint-disable @typescript-eslint/no-unsafe-function-type */

import { createHash } from "node:crypto";

import { ipcMain } from "electron";

import { MessagingService } from "@bitwarden/common/platform/abstractions/messaging.service";
import { sshagent } from "@bitwarden/desktop-napi";
import { LogService } from "@bitwarden/logging";

import { MainSshAgentService } from "./main-ssh-agent.service";

jest.mock("electron", () => ({
  ipcMain: {
    handle: jest.fn(),
  },
}));

jest.mock("@bitwarden/desktop-napi", () => ({
  sshagent: {
    SshAgentState: {
      serve: jest.fn(),
    },
  },
}));

describe("MainSshAgentService", () => {
  let mockLogService: jest.Mocked<LogService>;
  let mockMessagingService: jest.Mocked<MessagingService>;

  let ipcHandlers: Map<string, Function>;
  let mockAgentState: {
    isRunning: jest.Mock;
    replace: jest.Mock;
    stop: jest.Mock;
  };

  let capturedSignCb: (err: Error | null, data: sshagent.SignRequestData) => Promise<boolean>;
  let capturedListCb: (err: Error | null, agentRequestId: number) => Promise<boolean>;
  let capturedCancelCb: (err: Error | null, agentRequestId: number) => Promise<void>;

  beforeEach(async () => {
    ipcHandlers = new Map();

    mockLogService = {
      info: jest.fn(),
      error: jest.fn(),
      debug: jest.fn(),
      warning: jest.fn(),
    } as any;

    mockMessagingService = {
      send: jest.fn(),
    } as any;

    mockAgentState = {
      isRunning: jest.fn().mockReturnValue(true),
      replace: jest.fn(),
      stop: jest.fn(),
    };

    (ipcMain.handle as jest.Mock).mockImplementation((channel: string, handler: Function) => {
      ipcHandlers.set(channel, handler);
    });

    (sshagent.SshAgentState.serve as jest.Mock).mockImplementation(
      (sign: Function, list: Function, cancel: Function) => {
        capturedSignCb = sign as any;
        capturedListCb = list as any;
        capturedCancelCb = cancel as any;
        return Promise.resolve(mockAgentState);
      },
    );

    new MainSshAgentService(mockLogService, mockMessagingService);
    await ipcHandlers.get("sshagent.init")!({});
    await Promise.resolve(); // let agentState settle
  });

  describe("constructor", () => {
    // Handlers are registered up front rather than on INIT, so a call that arrives before the
    // agent is started is a no-op instead of an Electron "No handler registered" throw.
    it.each([
      "sshagent.init",
      "sshagent.isloaded",
      "sshagent.replace",
      "sshagent.signrequestresponse",
      "sshagent.stop",
      "sshagent.listkeysresponse",
    ])("should register the %s IPC handler", (channel) => {
      expect(ipcHandlers.has(channel)).toBe(true);
    });
  });

  describe("sshagent.isloaded IPC handler", () => {
    it("should return false before sshagent.init IPC is called", async () => {
      // Create a fresh service that has not received the INIT IPC call
      new MainSshAgentService(mockLogService, mockMessagingService);
      const handler = ipcHandlers.get("sshagent.isloaded")!;
      expect(await handler({})).toBe(false);
    });

    it("should return agentState.isRunning() after sshagent.init IPC resolves", async () => {
      const handler = ipcHandlers.get("sshagent.isloaded")!;
      expect(await handler({})).toBe(true);
    });

    it("should return false after sshagent.stop is called", async () => {
      await ipcHandlers.get("sshagent.stop")!({});
      const handler = ipcHandlers.get("sshagent.isloaded")!;
      expect(await handler({})).toBe(false);
    });
  });

  describe("sshagent.init IPC handler", () => {
    it("should pass sign, list and cancellation callbacks to serve", () => {
      expect(sshagent.SshAgentState.serve).toHaveBeenCalledWith(
        expect.any(Function),
        expect.any(Function),
        expect.any(Function),
      );
    });

    it("should log success after serve resolves", async () => {
      expect(mockLogService.info).toHaveBeenCalledWith("SSH agent started");
    });

    it("should log error if serve rejects", async () => {
      const error = new Error("napi bind failed");
      (sshagent.SshAgentState.serve as jest.Mock).mockRejectedValueOnce(error);

      // Re-create service and invoke INIT again with the rejecting mock
      new MainSshAgentService(mockLogService, mockMessagingService);
      await ipcHandlers.get("sshagent.init")!({});
      await Promise.resolve(); // propagates rejection through .then()
      await Promise.resolve(); // .catch() handler runs

      expect(mockLogService.error).toHaveBeenCalledWith("SSH agent encountered an error: ", error);
    });
  });

  describe("requestSign (via sign callback)", () => {
    const mockSignData = {
      requestId: 7,
      cipherId: "cipher-abc",
      signRequest: {
        publicKey: { keyType: "Ed25519", keypair: "keypair-data" },
        processName: "ssh",
        isForwarding: false,
        namespace: "ssh",
      },
    } as unknown as sshagent.SignRequestData;

    it("should send sshagent.signrequest with the correct fields", () => {
      void capturedSignCb(null, mockSignData);

      expect(mockMessagingService.send).toHaveBeenCalledWith("sshagent.signrequest", {
        cipherId: "cipher-abc",
        requestId: 1,
        // Stamped on arrival so the approval window can honour the agent's own 60s budget.
        receivedAt: expect.any(Number),
        processName: "ssh",
        isAgentForwarding: false,
        namespace: "ssh",
        hostFingerprint: undefined,
        keyFingerprint: null,
      });
    });

    it("should forward the key fingerprint in OpenSSH format", () => {
      const blob = [0x0a, 0x0b, 0x0c];

      void capturedSignCb(null, {
        cipherId: "cipher-abc",
        signRequest: {
          publicKey: { alg: "ssh-ed25519", blob },
          processName: "ssh",
          isForwarding: true,
          namespace: "git",
          hostFingerprint: "SHA256:hostkey",
        },
      } as unknown as sshagent.SignRequestData);

      // Same digest OpenSSH prints from `ssh-keygen -lf`: base64 of the SHA-256 of the key blob,
      // without the trailing `=` padding.
      const digest = createHash("sha256").update(Buffer.from(blob)).digest("base64");

      expect(mockMessagingService.send).toHaveBeenCalledWith(
        "sshagent.signrequest",
        expect.objectContaining({
          isAgentForwarding: true,
          namespace: "git",
          hostFingerprint: "SHA256:hostkey",
          keyFingerprint: `SHA256:${digest.replace(/=+$/, "")}`,
        }),
      );
    });

    it("should resolve with true when the renderer accepts", async () => {
      const signPromise = capturedSignCb(null, mockSignData);

      const responseHandler = ipcHandlers.get("sshagent.signrequestresponse")!;
      await responseHandler({}, { requestId: 1, accepted: true });

      expect(await signPromise).toBe(true);
    });

    it("should resolve with false when the renderer rejects", async () => {
      const signPromise = capturedSignCb(null, mockSignData);

      const responseHandler = ipcHandlers.get("sshagent.signrequestresponse")!;
      await responseHandler({}, { requestId: 1, accepted: false });

      expect(await signPromise).toBe(false);
    });
  });

  describe("requestListKeys (via list callback)", () => {
    it("should send sshagent.listkeysrequest with a requestId", () => {
      void capturedListCb(null, 11);

      expect(mockMessagingService.send).toHaveBeenCalledWith("sshagent.listkeysrequest", {
        requestId: expect.any(Number),
      });
    });

    it("should resolve with true when the renderer accepts", async () => {
      const listPromise = capturedListCb(null, 11);

      const responseHandler = ipcHandlers.get("sshagent.listkeysresponse")!;
      await responseHandler({}, { requestId: 1, accepted: true });

      expect(await listPromise).toBe(true);
    });

    it("should resolve with false when the renderer rejects", async () => {
      const listPromise = capturedListCb(null, 11);

      const responseHandler = ipcHandlers.get("sshagent.listkeysresponse")!;
      await responseHandler({}, { requestId: 1, accepted: false });

      expect(await listPromise).toBe(false);
    });
  });

  describe("abandoning parked requests", () => {
    // The native agent stops waiting for an approval after 60s, so anything still parked here past
    // that point can never be answered. These tests cover the two ways an entry stops leaking.

    const parkedSignData = {
      requestId: 7,
      cipherId: "cipher-abc",
      signRequest: {
        publicKey: { alg: "ssh-ed25519", blob: [1, 2, 3] },
        processName: "ssh",
        isForwarding: false,
        namespace: "ssh",
      },
    } as unknown as sshagent.SignRequestData;

    it("resolves a request that nobody answers instead of leaving it parked", async () => {
      jest.useFakeTimers();
      try {
        const signPromise = capturedSignCb(null, parkedSignData);
        await Promise.resolve();

        jest.advanceTimersByTime(65_000);

        await expect(signPromise).resolves.toBe(false);
      } finally {
        jest.useRealTimers();
      }
    });

    it("denies everything parked when the agent stops", async () => {
      const first = capturedSignCb(null, parkedSignData);
      const second = capturedSignCb(null, parkedSignData);
      await Promise.resolve();

      await ipcHandlers.get("sshagent.stop")!({});

      await expect(first).resolves.toBe(false);
      await expect(second).resolves.toBe(false);
    });

    it("settles a request only once when both an answer and a stop arrive", async () => {
      const signPromise = capturedSignCb(null, parkedSignData);
      await Promise.resolve();

      await ipcHandlers.get("sshagent.signrequestresponse")!({}, { requestId: 1, accepted: true });
      await ipcHandlers.get("sshagent.stop")!({});

      await expect(signPromise).resolves.toBe(true);
    });

    // Without this the prompt stays on screen after the SSH client has gone away.
    it("withdraws the approval when the agent reports the client disconnected", async () => {
      const withdraw = jest.fn();
      const service = new MainSshAgentService(mockLogService, mockMessagingService);
      service.setApprovalWithdrawal(withdraw);
      await ipcHandlers.get("sshagent.init")!({});
      await Promise.resolve();

      void capturedSignCb(null, parkedSignData);
      await Promise.resolve();

      await capturedCancelCb(null, parkedSignData.requestId);

      // The agent's id is translated to the id used for the renderer round trip.
      expect(withdraw).toHaveBeenCalledWith(1);
    });

    it("ignores a withdrawal for a request that is already settled", async () => {
      const withdraw = jest.fn();
      const service = new MainSshAgentService(mockLogService, mockMessagingService);
      service.setApprovalWithdrawal(withdraw);
      await ipcHandlers.get("sshagent.init")!({});
      await Promise.resolve();

      const signPromise = capturedSignCb(null, parkedSignData);
      await Promise.resolve();
      await ipcHandlers.get("sshagent.signrequestresponse")!({}, { requestId: 1, accepted: true });
      await signPromise;

      await capturedCancelCb(null, parkedSignData.requestId);

      expect(withdraw).not.toHaveBeenCalled();
    });

    // A client can give up while the vault is still locked, before any prompt exists. Its key list
    // will never be read, so waiting out the timeout would only leak the entry.
    it("settles a parked list request when the client disconnects", async () => {
      const listPromise = capturedListCb(null, 42);
      await Promise.resolve();

      await capturedCancelCb(null, 42);

      await expect(listPromise).resolves.toBe(false);
    });
  });

  describe("sshagent.replace IPC handler", () => {
    const keys = [{ name: "My Key", privateKey: "key-data", cipherId: "cipher-1" }];

    it("should call replace with the provided keys", async () => {
      const handler = ipcHandlers.get("sshagent.replace")!;
      await handler({}, keys);

      expect(mockAgentState.replace).toHaveBeenCalledWith(keys);
    });

    it("should not call replace when agent is not running", async () => {
      mockAgentState.isRunning.mockReturnValue(false);

      const handler = ipcHandlers.get("sshagent.replace")!;
      await handler({}, keys);

      expect(mockAgentState.replace).not.toHaveBeenCalled();
    });
  });

  describe("sshagent.stop IPC handler", () => {
    it("should call stop on the agent state", async () => {
      const handler = ipcHandlers.get("sshagent.stop")!;
      await handler({});

      expect(mockAgentState.stop).toHaveBeenCalled();
    });

    it("should be a no-op when called a second time after the agent is cleared", async () => {
      const handler = ipcHandlers.get("sshagent.stop")!;
      await handler({});
      mockAgentState.stop.mockClear();

      // agentState is now null; second call should not throw or call stop again
      await expect(handler({})).resolves.not.toThrow();
      expect(mockAgentState.stop).not.toHaveBeenCalled();
    });

    it("should allow the server to restart via INIT after a stop", async () => {
      (sshagent.SshAgentState.serve as jest.Mock).mockClear();

      const stopHandler = ipcHandlers.get("sshagent.stop")!;
      await stopHandler({});

      await ipcHandlers.get("sshagent.init")!({});
      await Promise.resolve();

      expect(sshagent.SshAgentState.serve).toHaveBeenCalledTimes(1);
    });
  });
});
