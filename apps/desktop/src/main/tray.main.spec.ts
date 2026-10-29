import { EventEmitter } from "node:events";

import { app, BrowserWindow, Menu } from "electron";
import { mock } from "jest-mock-extended";
import { BehaviorSubject } from "rxjs";

import { I18nService } from "@bitwarden/common/platform/abstractions/i18n.service";
import { MessagingService } from "@bitwarden/common/platform/abstractions/messaging.service";
import { BiometricsService } from "@bitwarden/key-management";

import { DesktopSettingsService } from "../platform/services/desktop-settings.service";

jest.mock("electron", () => ({
  app: { quit: jest.fn(), dock: { hide: jest.fn(), show: jest.fn() } },
  Menu: { buildFromTemplate: jest.fn((template: unknown) => ({ template })) },
  nativeImage: {
    createFromPath: jest.fn(() => ({ setTemplateImage: jest.fn() })),
  },
  Tray: jest.fn(() => ({
    on: jest.fn(),
    setToolTip: jest.fn(),
    setPressedImage: jest.fn(),
    setContextMenu: jest.fn(),
    destroy: jest.fn(),
  })),
}));

jest.mock("./window.main", () => ({ WindowMain: jest.fn() }));

import { TrayMain } from "./tray.main";
import { WindowMain } from "./window.main";

describe("TrayMain", () => {
  describe("window close", () => {
    let runInBackground$: BehaviorSubject<boolean>;
    let windowMain: WindowMain;
    let win: EventEmitter & { hide: jest.Mock };

    const emitClose = () => {
      const event = { preventDefault: jest.fn() };
      win.emit("close", event);
      return event;
    };

    beforeEach(async () => {
      globalThis.BIT_ENVIRONMENT = "production";
      runInBackground$ = new BehaviorSubject(false);
      win = Object.assign(new EventEmitter(), { hide: jest.fn() });
      windowMain = { isQuitting: false, win } as unknown as WindowMain;

      const desktopSettingsService = mock<DesktopSettingsService>();
      desktopSettingsService.runInBackground$ = runInBackground$;

      const sut = new TrayMain(
        windowMain,
        mock<I18nService>(),
        desktopSettingsService,
        mock<MessagingService>(),
        mock<BiometricsService>(),
      );
      await sut.init("Bitwarden");
      sut.setupWindowListeners(win as unknown as BrowserWindow);
    });

    it("prevents the close synchronously and hides the window when running in the background", () => {
      runInBackground$.next(true);

      const event = emitClose();

      expect(event.preventDefault).toHaveBeenCalled();
      expect(win.hide).toHaveBeenCalled();
      expect(windowMain.isQuitting).toBe(false);
    });

    it("hides the window being closed when another window is the main window", () => {
      runInBackground$.next(true);
      const other = { hide: jest.fn() };
      windowMain.win = other as unknown as BrowserWindow;

      emitClose();

      expect(win.hide).toHaveBeenCalled();
      expect(other.hide).not.toHaveBeenCalled();
    });

    it("lets the close proceed and marks the app as quitting when not running in the background", () => {
      const event = emitClose();

      expect(event.preventDefault).not.toHaveBeenCalled();
      expect(windowMain.isQuitting).toBe(true);
    });

    it("lets the close proceed while the app is quitting", () => {
      runInBackground$.next(true);
      windowMain.isQuitting = true;

      const event = emitClose();

      expect(event.preventDefault).not.toHaveBeenCalled();
      expect(win.hide).not.toHaveBeenCalled();
    });
  });

  // The SSH approval window is kept warm and is not closable, so `window-all-closed` never fires.
  // Quitting therefore has to be asked for explicitly, whether from the tray menu or by closing
  // the main window with "run in background" off.
  describe("quitting explicitly", () => {
    const makeSut = async () => {
      globalThis.BIT_ENVIRONMENT = "production";

      const windowMain = { isQuitting: false, win: null } as unknown as WindowMain;
      const desktopSettingsService = mock<DesktopSettingsService>();
      desktopSettingsService.runInBackground$ = new BehaviorSubject(false);

      // `init()` builds the tray menu, and I18nService is mocked, so map keys back to themselves
      // to find the "exit" entry by name.
      const i18nService = mock<I18nService>();
      i18nService.t.mockImplementation((key: string) => key);

      const sut = new TrayMain(
        windowMain,
        i18nService,
        desktopSettingsService,
        mock<MessagingService>(),
        mock<BiometricsService>(),
      );
      await sut.init("Bitwarden");

      const template = (Menu.buildFromTemplate as jest.Mock).mock.calls.at(-1)[0] as {
        label?: string;
      }[];
      return { sut, windowMain, template };
    };

    beforeEach(() => {
      jest.clearAllMocks();
    });

    it("asks the app to quit from the tray menu", async () => {
      const { windowMain, template } = await makeSut();

      const exitItem = template.find((item) => item.label === "exit") as {
        click?: () => void;
      };
      expect(exitItem?.click).toBeDefined();
      exitItem.click();

      expect(windowMain.isQuitting).toBe(true);
      expect(app.quit).toHaveBeenCalled();
    });
  });
});
