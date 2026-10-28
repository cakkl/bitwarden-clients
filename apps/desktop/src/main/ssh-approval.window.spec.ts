import { BrowserWindow, ipcMain } from "electron";
import { mock } from "jest-mock-extended";
import { BehaviorSubject } from "rxjs";

import { I18nService } from "@bitwarden/common/platform/abstractions/i18n.service";
import { LogService } from "@bitwarden/common/platform/abstractions/log.service";
import { Theme, ThemeTypes } from "@bitwarden/common/platform/enums";
import { ThemeStateService } from "@bitwarden/common/platform/theming/theme-state.service";

// The service under test builds a real BrowserWindow; only the Electron surface it touches needs
// to exist for the module to load in Jest.
jest.mock("electron", () => ({
  BrowserWindow: jest.fn(),
  ipcMain: { handle: jest.fn(), removeHandler: jest.fn() },
  nativeTheme: { shouldUseDarkColors: false },
  screen: {
    getDisplayMatching: jest.fn().mockReturnValue({ workAreaSize: { width: 1920, height: 1040 } }),
  },
}));

import { SSH_AGENT_IPC_CHANNELS } from "../autofill/models/ipc-channels";
import { SshApprovalPrompt } from "../autofill/models/ssh-agent-approval";

import { SshApprovalWindow } from "./ssh-approval.window";

const BASE_PROMPT: Omit<SshApprovalPrompt, "receivedAt"> = {
  cipherName: "Git key",
  applicationName: "git",
  isAgentForwarding: false,
  actionI18nKey: "sshActionGitSign",
  keyFingerprint: "SHA256:9xK2",
};

/** A prompt whose time budget starts now, which is what a fresh agent request looks like. */
const prompt = (overrides: Partial<SshApprovalPrompt> = {}): SshApprovalPrompt => ({
  ...BASE_PROMPT,
  receivedAt: Date.now(),
  ...overrides,
});

const TIMEOUT_MS = 60_000;

type Handler = (event: unknown, arg?: unknown) => Promise<unknown>;

function createBrowserWindowStub() {
  const webContents = {
    setWindowOpenHandler: jest.fn(),
    on: jest.fn(),
    send: jest.fn(),
    getURL: jest.fn().mockReturnValue(""),
  };

  const win = {
    webContents,
    setAlwaysOnTop: jest.fn(),
    setMenuBarVisibility: jest.fn(),
    setBackgroundColor: jest.fn(),
    setContentSize: jest.fn(),
    isResizable: jest.fn().mockReturnValue(false),
    setResizable: jest.fn(),
    getBounds: jest.fn().mockReturnValue({ x: 0, y: 0, width: 520, height: 320 }),
    on: jest.fn(),
    loadFile: jest.fn().mockResolvedValue(undefined),
    isMinimized: jest.fn().mockReturnValue(false),
    restore: jest.fn(),
    center: jest.fn(),
    isVisible: jest.fn().mockReturnValue(false),
    show: jest.fn(),
    showInactive: jest.fn(),
    moveTop: jest.fn(),
    focus: jest.fn(),
    flashFrame: jest.fn(),
    hide: jest.fn(),
    isDestroyed: jest.fn().mockReturnValue(false),
    destroy: jest.fn(),
  };

  (BrowserWindow as unknown as jest.Mock).mockImplementation(() => win);
  return win;
}

describe("SshApprovalWindow", () => {
  let sut: SshApprovalWindow;
  let win: ReturnType<typeof createBrowserWindowStub>;
  let selectedTheme: BehaviorSubject<Theme>;

  const handlerFor = (channel: string): Handler => {
    const call = (ipcMain.handle as jest.Mock).mock.calls.find(([name]) => name === channel);
    if (call == null) {
      throw new Error(`No IPC handler registered for ${channel}`);
    }
    return call[1] as Handler;
  };

  // `requestApproval` reaches the window through a couple of awaited promises, so the assertions
  // have to let those microtasks run.
  const flushMicrotasks = async () => {
    for (let i = 0; i < 5; i++) {
      await Promise.resolve();
    }
  };

  // The window only shows once the renderer has reported how tall its content is, so tests have to
  // stand in for that message before asserting on the visibility calls.
  const reportContentHeight = async (height = 300) => {
    await handlerFor(SSH_AGENT_IPC_CHANNELS.APPROVAL_RESIZE)({ sender: win.webContents }, height);
    await flushMicrotasks();
  };

  beforeEach(() => {
    // `isDev()` reads this global, which only webpack defines in real builds.
    (globalThis as unknown as Record<string, unknown>).BIT_ENVIRONMENT = "test";

    jest.clearAllMocks();
    win = createBrowserWindowStub();

    selectedTheme = new BehaviorSubject<Theme>(ThemeTypes.Dark);

    sut = new SshApprovalWindow(mock<LogService>(), mock<I18nService>(), {
      selectedTheme$: selectedTheme.asObservable(),
    } as unknown as ThemeStateService);
  });

  afterEach(() => {
    sut.dispose();
  });

  it("registers a handler for every approval channel", () => {
    const channels = (ipcMain.handle as jest.Mock).mock.calls.map(([channel]) => channel);

    expect(channels).toEqual(
      expect.arrayContaining([
        SSH_AGENT_IPC_CHANNELS.APPROVAL_REQUEST,
        SSH_AGENT_IPC_CHANNELS.APPROVAL_GET,
        SSH_AGENT_IPC_CHANNELS.APPROVAL_RESPONSE,
        SSH_AGENT_IPC_CHANNELS.APPROVAL_CANCEL,
      ]),
    );
  });

  it("shows the prompt and resolves true when the user authorizes", async () => {
    const decided = sut.requestApproval(prompt());
    await flushMicrotasks();

    const view = (await handlerFor(SSH_AGENT_IPC_CHANNELS.APPROVAL_GET)({})) as {
      requestId: number;
    };

    expect(view.requestId).toBe(1);
    await reportContentHeight();
    expect(win.showInactive).toHaveBeenCalled();
    expect(win.show).not.toHaveBeenCalled();
    expect(win.focus).not.toHaveBeenCalled();

    await handlerFor(SSH_AGENT_IPC_CHANNELS.APPROVAL_RESPONSE)(
      {},
      {
        requestId: view.requestId,
        accepted: true,
      },
    );

    await expect(decided).resolves.toBe(true);
  });

  it("passes the resolved theme and key details to the window", async () => {
    void sut.requestApproval(prompt({ cipherName: "Deploy key" }));
    await flushMicrotasks();

    const view = (await handlerFor(SSH_AGENT_IPC_CHANNELS.APPROVAL_GET)({})) as Record<
      string,
      unknown
    >;

    expect(view.theme).toBe("dark");
    expect(view.keyFingerprint).toBe("SHA256:9xK2");
  });

  it("counts down from when the request arrived, not from when it is shown", async () => {
    const receivedAt = Date.now();
    void sut.requestApproval(prompt({ receivedAt }));
    await flushMicrotasks();

    const view = (await handlerFor(SSH_AGENT_IPC_CHANNELS.APPROVAL_GET)({})) as {
      expiresAt: number;
      timeoutMs: number;
    };

    // The agent's own 60s budget started when it asked, so the deadline is anchored there.
    expect(view.timeoutMs).toBe(60_000);
    expect(view.expiresAt).toBe(receivedAt + 60_000);
  });

  it("denies a request that expired while it was waiting to be shown", async () => {
    const decided = sut.requestApproval(prompt({ receivedAt: Date.now() - 61_000 }));
    await flushMicrotasks();

    await expect(decided).resolves.toBe(false);
    // Nothing left to ask: the SSH client has already been told the signature failed.
    expect(win.showInactive).not.toHaveBeenCalled();
    expect(await handlerFor(SSH_AGENT_IPC_CHANNELS.APPROVAL_GET)({})).toBeNull();
  });

  it("does not present a prompt that was cancelled while the window was still loading", async () => {
    let finishLoad: () => void = () => {};
    win.loadFile.mockReturnValue(
      new Promise<void>((resolve) => {
        finishLoad = resolve;
      }),
    );

    const decided = sut.requestApproval(prompt());
    await flushMicrotasks();

    // The vault locked while the page was loading.
    await handlerFor(SSH_AGENT_IPC_CHANNELS.APPROVAL_CANCEL)({});
    await flushMicrotasks();

    finishLoad();
    await flushMicrotasks();

    await expect(decided).resolves.toBe(false);
    expect(win.showInactive).not.toHaveBeenCalled();
  });

  it("falls back to the OS appearance when the user follows the system theme", async () => {
    selectedTheme.next(ThemeTypes.System);

    void sut.requestApproval(prompt());
    await flushMicrotasks();

    const view = (await handlerFor(SSH_AGENT_IPC_CHANNELS.APPROVAL_GET)({})) as Record<
      string,
      unknown
    >;

    // The Electron mock reports a light OS appearance.
    expect(view.theme).toBe("light");
  });

  it("sizes itself to the height the renderer reports", async () => {
    void sut.requestApproval(prompt());
    await flushMicrotasks();

    await reportContentHeight(268);

    expect(win.setContentSize).toHaveBeenCalledWith(520, 268);
    // The window must end up non-resizable again, whatever the platform needed to apply the size.
    expect(win.setResizable).toHaveBeenLastCalledWith(false);
  });

  it("ignores a height reported by any other window", async () => {
    void sut.requestApproval(prompt());
    await flushMicrotasks();

    await handlerFor(SSH_AGENT_IPC_CHANNELS.APPROVAL_RESIZE)({ sender: { id: 99 } }, 900);

    expect(win.setContentSize).not.toHaveBeenCalled();
  });

  it("refuses to grow past the display work area", async () => {
    void sut.requestApproval(prompt());
    await flushMicrotasks();

    await reportContentHeight(99_999);

    // The display mock reports a 1040px work area, leaving room for the taskbar and a margin.
    expect(win.setContentSize).toHaveBeenCalledWith(520, 960);
  });

  it("resolves false when the user denies", async () => {
    const decided = sut.requestApproval(prompt());
    await flushMicrotasks();

    await handlerFor(SSH_AGENT_IPC_CHANNELS.APPROVAL_RESPONSE)(
      {},
      {
        requestId: 1,
        accepted: false,
      },
    );

    await expect(decided).resolves.toBe(false);
  });

  it("keeps one prompt on screen at a time and serves the queue in order", async () => {
    const first = sut.requestApproval(prompt());
    const second = sut.requestApproval(prompt({ cipherName: "Deploy key" }));
    await flushMicrotasks();

    // Only the first request has been pushed to the window.
    const pushed = win.webContents.send.mock.calls.filter(
      ([channel]) => channel === SSH_AGENT_IPC_CHANNELS.APPROVAL_CHANGED,
    );
    expect(pushed).toHaveLength(1);

    const getCurrent = handlerFor(SSH_AGENT_IPC_CHANNELS.APPROVAL_GET);
    expect(((await getCurrent({})) as { cipherName: string }).cipherName).toBe("Git key");

    await handlerFor(SSH_AGENT_IPC_CHANNELS.APPROVAL_RESPONSE)(
      {},
      {
        requestId: 1,
        accepted: true,
      },
    );
    await flushMicrotasks();

    await expect(first).resolves.toBe(true);
    expect(((await getCurrent({})) as { cipherName: string }).cipherName).toBe("Deploy key");

    await handlerFor(SSH_AGENT_IPC_CHANNELS.APPROVAL_RESPONSE)(
      {},
      {
        requestId: 2,
        accepted: false,
      },
    );

    await expect(second).resolves.toBe(false);
  });

  it("denies a prompt that nobody answers before the native agent gives up", async () => {
    jest.useFakeTimers();

    try {
      const decided = sut.requestApproval(prompt());
      await flushMicrotasks();

      jest.advanceTimersByTime(TIMEOUT_MS);
      await flushMicrotasks();

      await expect(decided).resolves.toBe(false);
      expect(win.hide).toHaveBeenCalled();
    } finally {
      jest.useRealTimers();
    }
  });

  it("denies everything pending when the vault locks", async () => {
    const first = sut.requestApproval(prompt());
    const second = sut.requestApproval(prompt());
    await flushMicrotasks();

    await handlerFor(SSH_AGENT_IPC_CHANNELS.APPROVAL_CANCEL)({});
    await flushMicrotasks();

    await expect(first).resolves.toBe(false);
    await expect(second).resolves.toBe(false);
  });

  // The SSH client can disconnect while the prompt is up; only that request must be withdrawn.
  it("withdraws a single prompt without touching the rest of the queue", async () => {
    const first = sut.requestApproval(prompt());
    const second = sut.requestApproval(prompt({ cipherName: "Deploy key" }));
    await flushMicrotasks();

    sut.cancelRequest(1, "the SSH client disconnected");
    await flushMicrotasks();

    await expect(first).resolves.toBe(false);
    // The second request is still waiting for an answer.
    await expect(handlerFor(SSH_AGENT_IPC_CHANNELS.APPROVAL_GET)({})).resolves.toMatchObject({
      requestId: 2,
    });

    sut.cancelRequest(2, "the SSH client disconnected");
    await expect(second).resolves.toBe(false);
  });

  it("withdraws a request that is still queued", async () => {
    const first = sut.requestApproval(prompt());
    const second = sut.requestApproval(prompt({ cipherName: "Deploy key" }));
    await flushMicrotasks();

    sut.cancelRequest(2, "the SSH client disconnected");
    await flushMicrotasks();

    await expect(second).resolves.toBe(false);
    // The visible prompt is untouched.
    await expect(handlerFor(SSH_AGENT_IPC_CHANNELS.APPROVAL_GET)({})).resolves.toMatchObject({
      requestId: 1,
    });

    sut.cancelRequest(1, "the SSH client disconnected");
    await expect(first).resolves.toBe(false);
  });

  it("answers a late response exactly once", async () => {
    const decided = sut.requestApproval(prompt());
    await flushMicrotasks();

    const respond = handlerFor(SSH_AGENT_IPC_CHANNELS.APPROVAL_RESPONSE);
    await respond({}, { requestId: 1, accepted: false });
    await respond({}, { requestId: 1, accepted: true });

    await expect(decided).resolves.toBe(false);
  });

  it("refuses to let the OS close the prompt without an answer", async () => {
    const decided = sut.requestApproval(prompt());
    await flushMicrotasks();

    const closeListener = win.on.mock.calls.find(([event]) => event === "close")?.[1] as (event: {
      preventDefault: () => void;
    }) => void;
    const preventDefault = jest.fn();
    closeListener({ preventDefault });

    expect(preventDefault).toHaveBeenCalled();
    await expect(decided).resolves.toBe(false);
  });

  it("unregisters its handlers on dispose", () => {
    sut.dispose();

    expect(ipcMain.removeHandler).toHaveBeenCalledWith(SSH_AGENT_IPC_CHANNELS.APPROVAL_REQUEST);
    expect(ipcMain.removeHandler).toHaveBeenCalledWith(SSH_AGENT_IPC_CHANNELS.APPROVAL_GET);
    expect(ipcMain.removeHandler).toHaveBeenCalledWith(SSH_AGENT_IPC_CHANNELS.APPROVAL_RESPONSE);
    expect(ipcMain.removeHandler).toHaveBeenCalledWith(SSH_AGENT_IPC_CHANNELS.APPROVAL_CANCEL);
    expect(ipcMain.removeHandler).toHaveBeenCalledWith(SSH_AGENT_IPC_CHANNELS.APPROVAL_RESIZE);
  });

  it("stacks the prompt on top without taking focus from the user's window", async () => {
    void sut.requestApproval(prompt());
    await flushMicrotasks();
    await reportContentHeight();

    expect(win.setAlwaysOnTop).toHaveBeenCalledWith(true, "screen-saver");
    expect(win.moveTop).toHaveBeenCalled();

    // The user is usually mid-sentence elsewhere; activating this window would eat their keystrokes.
    expect(win.showInactive).toHaveBeenCalled();
    expect(win.show).not.toHaveBeenCalled();
    expect(win.focus).not.toHaveBeenCalled();
  });
});
