// FIXME: Update this file to be type safe and remove this and next line
// @ts-strict-ignore
import * as path from "path";

import { app, BrowserWindow, ipcMain, nativeTheme, screen } from "electron";
import { firstValueFrom } from "rxjs";

import { I18nService } from "@bitwarden/common/platform/abstractions/i18n.service";
import { LogService } from "@bitwarden/common/platform/abstractions/log.service";
import { ThemeTypes } from "@bitwarden/common/platform/enums";
import { ThemeStateService } from "@bitwarden/common/platform/theming/theme-state.service";

import { SSH_AGENT_IPC_CHANNELS } from "../autofill/models/ipc-channels";
import {
  SshApprovalPrompt,
  SshApprovalTheme,
  SshApprovalView,
} from "../autofill/models/ssh-agent-approval";
import { DEV_ICON_FILE, isDev } from "../utils";

import { isLinux, isWindows } from "./platform-utils.main";

/** Denies the request after this long. Matches the native agent's own approval timeout. */
const APPROVAL_TIMEOUT_MS = 60_000;

/** Width is fixed; height comes from the rendered content. */
const WINDOW_WIDTH = 520;
const MIN_WINDOW_HEIGHT = 220;
/** Only used before the content height is known. */
const INITIAL_WINDOW_HEIGHT = 320;
/** How long to wait for the content height before showing anyway. */
const LAYOUT_TIMEOUT_MS = 400;

/** Must match the page background tokens in ssh-approval/index.html to avoid a white flash. */
function backgroundColor(theme: SshApprovalTheme): string {
  return theme === "dark" ? "#020618" : "#ffffff";
}

interface PendingApproval {
  requestId: number;
  /** Epoch ms at which the agent asked for approval; the authoritative start of the time budget. */
  receivedAt: number;
  view: SshApprovalView;
  resolve: (accepted: boolean) => void;
}

/** Shows SSH agent sign requests in a dedicated always-on-top window, one at a time. */
export class SshApprovalWindow {
  private win: BrowserWindow | null = null;
  private queue: PendingApproval[] = [];
  private current: PendingApproval | null = null;
  private timeout: NodeJS.Timeout | null = null;
  private onLayoutReady: (() => void) | null = null;
  private nextRequestId = 0;
  private allowClose = false;

  constructor(
    private logService: LogService,
    private i18nService: I18nService,
    private themeStateService: ThemeStateService,
  ) {
    this.registerIpcHandlers();
  }

  /** Queues a prompt and resolves with the decision. Never rejects; an unshowable request is denied. */
  private requestApproval(prompt: SshApprovalPrompt): Promise<boolean> {
    const requestId = ++this.nextRequestId;
    return new Promise<boolean>((resolve) => {
      const pending: PendingApproval = {
        requestId,
        view: this.buildView(requestId, prompt),
        receivedAt: prompt.receivedAt,
        resolve,
      };
      this.queue.push(pending);
      this.logService.info(
        `SSH sign request ${requestId} received for "${prompt.applicationName}"; ${this.queue.length} queued.`,
      );
      void this.showNext();
    });
  }

  /** Denies every prompt on screen or queued, e.g. when the vault locks. */
  cancelAll(reason: string): void {
    const pending = this.current == null ? [...this.queue] : [this.current, ...this.queue];
    this.queue = [];
    this.current = null;
    this.clearTimeout();
    this.hideWindow();

    if (pending.length > 0) {
      const ids = pending.map((request) => request.requestId).join(", ");
      this.logService.info(`Denying pending SSH sign request(s) ${ids}: ${reason}`);
    }

    for (const request of pending) {
      request.resolve(false);
    }
  }

  /** Denies one prompt, leaving the rest alone. Used when its SSH client disconnects. */
  cancelRequest(requestId: number, reason: string): void {
    if (this.current?.requestId === requestId) {
      this.settle(requestId, false, reason);
      return;
    }

    const index = this.queue.findIndex((request) => request.requestId === requestId);
    if (index === -1) {
      // Already answered, withdrawn, or timed out.
      return;
    }

    const [pending] = this.queue.splice(index, 1);
    this.logService.info(`Withdrawing queued SSH sign request ${requestId}: ${reason}`);
    pending.resolve(false);
  }

  dispose(): void {
    this.allowClose = true;
    this.cancelAll("the application is shutting down");

    ipcMain.removeHandler(SSH_AGENT_IPC_CHANNELS.APPROVAL_REQUEST);
    ipcMain.removeHandler(SSH_AGENT_IPC_CHANNELS.APPROVAL_GET);
    ipcMain.removeHandler(SSH_AGENT_IPC_CHANNELS.APPROVAL_RESPONSE);
    ipcMain.removeHandler(SSH_AGENT_IPC_CHANNELS.APPROVAL_CANCEL);
    ipcMain.removeHandler(SSH_AGENT_IPC_CHANNELS.APPROVAL_RESIZE);

    if (this.win != null && !this.win.isDestroyed()) {
      this.win.destroy();
    }
    this.win = null;
  }

  private registerIpcHandlers() {
    ipcMain.handle(SSH_AGENT_IPC_CHANNELS.APPROVAL_REQUEST, async (_, prompt: SshApprovalPrompt) =>
      this.requestApproval(prompt),
    );

    ipcMain.handle(SSH_AGENT_IPC_CHANNELS.APPROVAL_GET, async () => this.current?.view ?? null);

    ipcMain.handle(
      SSH_AGENT_IPC_CHANNELS.APPROVAL_RESPONSE,
      async (_, { requestId, accepted }: { requestId: number; accepted: boolean }) => {
        this.settle(requestId, accepted);
      },
    );

    ipcMain.handle(SSH_AGENT_IPC_CHANNELS.APPROVAL_CANCEL, async () =>
      this.cancelAll("the vault is no longer unlocked"),
    );

    // Only the approval window itself may resize it.
    ipcMain.handle(SSH_AGENT_IPC_CHANNELS.APPROVAL_RESIZE, async (event, contentHeight: number) => {
      if (this.win == null || this.win.isDestroyed() || event.sender !== this.win.webContents) {
        return;
      }

      this.applyContentHeight(this.clampHeight(contentHeight));
      this.notifyLayoutReady();
    });
  }

  private applyContentHeight(height: number): void {
    // Some platforms ignore a resize while the window is non-resizable.
    const wasResizable = this.win.isResizable();
    this.win.setResizable(true);
    this.win.setContentSize(WINDOW_WIDTH, height);
    this.win.setResizable(wasResizable);
  }

  /** Keeps the prompt inside its display when the content is unusually tall. */
  private clampHeight(contentHeight: number): number {
    const display = screen.getDisplayMatching(this.win.getBounds());
    const maxHeight = Math.max(MIN_WINDOW_HEIGHT, display.workAreaSize.height - 80);
    return Math.min(Math.max(Math.ceil(contentHeight), MIN_WINDOW_HEIGHT), maxHeight);
  }

  private buildView(requestId: number, prompt: SshApprovalPrompt): SshApprovalView {
    return {
      requestId,
      // Stamped when the prompt is shown, so a queued request gets the state current at that moment.
      theme: "light",
      timeoutMs: APPROVAL_TIMEOUT_MS,
      expiresAt: 0,
      // These keys already exist for this flow, so the prompt is translated in every locale.
      question: this.i18nService.t("sshkeyApprovalTitle"),
      applicationName: prompt.applicationName,
      cipherName: prompt.cipherName,
      keyFingerprint: prompt.keyFingerprint ?? "",
      action: this.i18nService.t(prompt.actionI18nKey),
      isAgentForwarding: prompt.isAgentForwarding,
      forwardedLabel: this.i18nService.t("agentForwardingWarningText"),
      authorizeLabel: this.i18nService.t("authorize"),
      denyLabel: this.i18nService.t("deny"),
    };
  }

  /** The theme picked in the app, or the OS theme when the user follows the system. */
  private async resolveTheme(): Promise<SshApprovalTheme> {
    const theme = await firstValueFrom(this.themeStateService.selectedTheme$);

    switch (theme) {
      case ThemeTypes.Light:
        return "light";
      case ThemeTypes.Dark:
        return "dark";
      default:
        return nativeTheme.shouldUseDarkColors ? "dark" : "light";
    }
  }

  private async showNext(): Promise<void> {
    if (this.current != null || this.queue.length === 0) {
      return;
    }

    const next = this.queue.shift();
    this.current = next;

    // The deadline belongs to the request, not to the moment the prompt reaches the screen.
    const expiresAt = next.receivedAt + APPROVAL_TIMEOUT_MS;
    const remaining = expiresAt - Date.now();
    if (remaining <= 0) {
      // The agent has already given up, so an answer could never reach the SSH client.
      this.current = null;
      this.logService.info(
        `SSH sign request ${next.requestId} expired before it could be shown; denying.`,
      );
      next.resolve(false);
      void this.showNext();
      return;
    }

    next.view.expiresAt = expiresAt;
    next.view.theme = await this.resolveTheme();
    if (!this.isStillCurrent(next)) {
      return;
    }

    this.timeout = setTimeout(() => this.settle(next.requestId, false, "timed out"), remaining);

    try {
      const win = this.ensureWindow();
      win.setBackgroundColor(backgroundColor(next.view.theme));
      await this.loadWindow(win);
      if (!this.isStillCurrent(next)) {
        return;
      }

      // Wait for the measured height so the window does not appear then jump.
      const layoutReady = this.waitForLayoutReady();
      win.webContents.send(SSH_AGENT_IPC_CHANNELS.APPROVAL_CHANGED, next.view);
      await layoutReady;
      if (!this.isStillCurrent(next)) {
        return;
      }

      this.logService.info(
        `Showing SSH sign request ${next.requestId} with ${Math.max(
          0,
          expiresAt - Date.now(),
        )}ms left.`,
      );
      this.present(win);
    } catch (e: unknown) {
      this.logService.error("Failed to show the SSH sign approval window", e);
      this.settle(next.requestId, false, "the approval window could not be shown");
      void this.showNext();
    }
  }

  /** Showing spans several awaits, and a cancellation can land in between. */
  private isStillCurrent(pending: PendingApproval): boolean {
    return this.current === pending;
  }

  /** Resolves when the renderer reports its height, or after a short timeout. */
  private waitForLayoutReady(): Promise<void> {
    return new Promise<void>((resolve) => {
      const finish = () => {
        if (this.onLayoutReady === finish) {
          this.onLayoutReady = null;
        }
        clearTimeout(timeout);
        resolve();
      };

      const timeout = setTimeout(finish, LAYOUT_TIMEOUT_MS);
      this.onLayoutReady = finish;
    });
  }

  private notifyLayoutReady(): void {
    this.onLayoutReady?.();
  }

  private ensureWindow(): BrowserWindow {
    if (this.win != null && !this.win.isDestroyed()) {
      return this.win;
    }

    const win = new BrowserWindow({
      width: WINDOW_WIDTH,
      height: INITIAL_WINDOW_HEIGHT,
      useContentSize: true,
      resizable: false,
      minimizable: false,
      maximizable: false,
      fullscreenable: false,
      // No frame means no close button, so the only way out is an explicit answer. Still
      // intercepted below for the cases the OS closes the window anyway.
      frame: false,
      closable: false,
      alwaysOnTop: true,
      show: false,
      title: this.i18nService.t("sshkeyApprovalTitle"),
      icon: this.windowIcon(),
      backgroundColor: backgroundColor(nativeTheme.shouldUseDarkColors ? "dark" : "light"),
      webPreferences: {
        preload: path.join(__dirname, "preload.js"),
        contextIsolation: true,
        nodeIntegration: false,
        sandbox: true,
        spellcheck: false,
        devTools: isDev(),
      },
    });

    win.setAlwaysOnTop(true, "screen-saver");
    win.setMenuBarVisibility?.(false);

    // The window only ever shows our local bundle; block navigation and popups.
    win.webContents.setWindowOpenHandler(() => ({ action: "deny" }));
    win.webContents.on("will-navigate", (event) => event.preventDefault());

    win.on("close", (event) => {
      if (this.allowClose) {
        return;
      }
      event.preventDefault();
      this.cancelAll("the approval window was closed");
    });

    win.on("closed", () => {
      this.win = null;
    });

    this.win = win;
    return win;
  }

  private async loadWindow(win: BrowserWindow): Promise<void> {
    if (win.webContents.getURL() !== "") {
      // Reused window: the prompt is pushed by the caller once it is on screen.
      return;
    }

    await win.loadFile(path.join(__dirname, "ssh-approval.html"));
  }

  /** Brings the prompt to the front. Windows and Linux only focus once the OS activates the app. */
  private present(win: BrowserWindow): void {
    if (win.isMinimized()) {
      win.restore();
    }

    win.setAlwaysOnTop(true, "screen-saver");
    win.center();

    if (!win.isVisible()) {
      win.show();
    }

    win.moveTop();

    if (isWindows() || isLinux()) {
      app.focus({ steal: true });
    }

    win.focus();

    if (isWindows() || isLinux()) {
      win.flashFrame(true);
    }
  }

  private settle(requestId: number, accepted: boolean, reason?: string): void {
    const pending = this.current;
    if (pending == null || pending.requestId !== requestId) {
      // Already answered, cancelled or timed out.
      return;
    }

    this.clearTimeout();
    this.current = null;
    this.hideWindow();

    // SSH_AGENT_FAILURE cannot distinguish denial from timeout, so the log keeps the real cause.
    const outcome = accepted ? "approved" : `denied (${reason ?? "by the user"})`;
    this.logService.info(
      `SSH sign request ${requestId} ${outcome} ${Date.now() - pending.receivedAt}ms after it arrived.`,
    );

    pending.resolve(accepted);
    void this.showNext();
  }

  private hideWindow(): void {
    if (this.win == null || this.win.isDestroyed()) {
      return;
    }

    this.win.flashFrame(false);
    this.win.hide();
  }

  private clearTimeout(): void {
    if (this.timeout != null) {
      clearTimeout(this.timeout);
      this.timeout = null;
    }
  }

  private windowIcon(): string | undefined {
    if (isDev()) {
      return path.join(__dirname, "images", DEV_ICON_FILE);
    }

    return isLinux() ? path.join(__dirname, "/images/icon.png") : undefined;
  }
}
