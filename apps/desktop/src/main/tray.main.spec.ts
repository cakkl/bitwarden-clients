import { app, Menu } from "electron";
import { BehaviorSubject } from "rxjs";

import type { I18nService } from "@bitwarden/common/platform/abstractions/i18n.service";
import type { MessagingService } from "@bitwarden/common/platform/abstractions/messaging.service";
import type { BiometricsService } from "@bitwarden/key-management";

import type { DesktopSettingsService } from "../platform/services/desktop-settings.service";

jest.mock("electron", () => ({
  app: { quit: jest.fn(), dock: { hide: jest.fn(), show: jest.fn() } },
  BrowserWindow: jest.fn(),
  Menu: { buildFromTemplate: jest.fn((template: unknown) => ({ template })) },
  Tray: jest.fn().mockImplementation(() => ({
    setToolTip: jest.fn(),
    on: jest.fn(),
    setPressedImage: jest.fn(),
    setContextMenu: jest.fn(),
    popUpContextMenu: jest.fn(),
    destroy: jest.fn(),
  })),
  nativeImage: { createFromPath: jest.fn(() => ({ setTemplateImage: jest.fn() })) },
}));

jest.mock("../utils", () => ({ isDev: () => false }));

import { TrayMain } from "./tray.main";
import type { WindowMain } from "./window.main";

describe("TrayMain", () => {
  const windowMain = { isQuitting: false, win: null } as unknown as WindowMain;

  function makeSut(runInBackground: boolean): TrayMain {
    return new TrayMain(
      windowMain,
      { t: (key: string) => key } as unknown as I18nService,
      {
        runInBackground$: new BehaviorSubject(runInBackground),
      } as unknown as DesktopSettingsService,
      {} as unknown as MessagingService,
      {} as unknown as BiometricsService,
    );
  }

  function makeWindow() {
    const handlers: Record<string, (event: unknown) => Promise<void> | void> = {};
    const win = {
      on: (name: string, handler: (event: unknown) => Promise<void> | void) => {
        handlers[name] = handler;
      },
      hide: jest.fn(),
    };
    return { win, handlers };
  }

  function clickMenuItem(sut: TrayMain, label: string) {
    const template = (Menu.buildFromTemplate as jest.Mock).mock.calls.at(-1)[0] as {
      label?: string;
      click?: () => void;
    }[];
    const item = template.find((entry) => entry.label === label);
    if (item?.click == null) {
      throw new Error(`menu item "${label}" not found`);
    }
    item.click();
  }

  beforeEach(() => {
    jest.clearAllMocks();
    windowMain.isQuitting = false;
  });

  // The tray window is created once and kept alive, and it is not closable. Relying on
  // `window-all-closed` therefore never quits: the process survives with only a tray icon.
  describe("exit menu item", () => {
    it("asks the app to quit", async () => {
      const sut = makeSut(false);
      await sut.init("Bitwarden");

      clickMenuItem(sut, "exit");

      expect(app.quit).toHaveBeenCalledTimes(1);
    });

    it("marks the quit before asking, so closing the window does not hide it to the tray", async () => {
      const sut = makeSut(false);
      await sut.init("Bitwarden");

      clickMenuItem(sut, "exit");

      expect(windowMain.isQuitting).toBe(true);
    });
  });

  describe("main window close", () => {
    it("quits explicitly when running in the background is disabled", async () => {
      const sut = makeSut(false);
      await sut.init("Bitwarden");
      const { win, handlers } = makeWindow();
      sut.setupWindowListeners(win as never);
      const preventDefault = jest.fn();

      await handlers["close"]({ preventDefault });

      expect(preventDefault).not.toHaveBeenCalled();
      expect(windowMain.isQuitting).toBe(true);
      expect(app.quit).toHaveBeenCalledTimes(1);
    });

    it("hides to the tray instead of quitting when running in the background is enabled", async () => {
      const sut = makeSut(true);
      await sut.init("Bitwarden");
      const { win, handlers } = makeWindow();
      sut.setupWindowListeners(win as never);
      const preventDefault = jest.fn();

      await handlers["close"]({ preventDefault });

      expect(preventDefault).toHaveBeenCalledTimes(1);
      expect(windowMain.isQuitting).toBe(false);
      expect(app.quit).not.toHaveBeenCalled();
    });
  });
});
