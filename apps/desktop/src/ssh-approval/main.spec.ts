import { readFileSync } from "fs";
import { join } from "path";

import { SshApprovalView } from "../autofill/models/ssh-agent-approval";

/**
 * Tests the approval window's renderer.
 *
 * The page is a separate webpack entry that runs on import, so each test installs the real markup
 * from `index.html` and then loads the module fresh. Using the actual markup keeps the test honest
 * about the element ids the renderer requires.
 */

const INDEX_HTML = readFileSync(join(__dirname, "index.html"), "utf8");
const BODY_MARKUP = INDEX_HTML.slice(
  INDEX_HTML.indexOf("<body>") + "<body>".length,
  INDEX_HTML.indexOf("</body>"),
);

const makeView = (overrides: Partial<SshApprovalView> = {}): SshApprovalView => ({
  requestId: 1,
  theme: "light",
  question: "Confirm SSH key usage",
  applicationName: "git",
  cipherName: "Git key",
  keyFingerprint: "SHA256:abc123",
  action: "sign a git commit",
  isAgentForwarding: false,
  forwardedLabel: "This request comes from a remote device",
  authorizeLabel: "Authorize",
  denyLabel: "Deny",
  timeoutMs: 60_000,
  expiresAt: Date.now() + 60_000,
  ...overrides,
});

describe("SSH approval window renderer", () => {
  let respondApproval: jest.Mock;
  let resizeApproval: jest.Mock;
  let getApproval: jest.Mock;
  let approvalChanged: (view: SshApprovalView) => void;

  /** Loads the renderer against the real markup, with `ipc` stubbed out. */
  const load = async () => {
    document.body.innerHTML = BODY_MARKUP;

    jest.resetModules();
    await import("./main");
    // The module fetches the pending request from main once at startup.
    await Promise.resolve();
    await Promise.resolve();
  };

  const element = (id: string) => document.getElementById(id) as HTMLElement;

  beforeEach(() => {
    // The countdown is driven by timers, so it has to be controllable (and cleaned up).
    jest.useFakeTimers();

    respondApproval = jest.fn().mockResolvedValue(undefined);
    resizeApproval = jest.fn().mockResolvedValue(undefined);
    getApproval = jest.fn().mockResolvedValue(null);

    (global as unknown as Record<string, unknown>).ipc = {
      autofill: {
        sshAgent: {
          respondApproval,
          resizeApproval,
          getApproval,
          onApprovalChanged: (callback: (view: SshApprovalView) => void) => {
            approvalChanged = callback;
          },
        },
      },
    };
  });

  afterEach(() => {
    jest.useRealTimers();
    delete (global as unknown as Record<string, unknown>).ipc;
    document.body.innerHTML = "";
  });

  it("renders every field of the request", async () => {
    getApproval.mockResolvedValue(makeView());
    await load();

    expect(element("question").textContent).toBe("Confirm SSH key usage");
    expect(element("application-name").textContent).toBe("git");
    expect(element("purpose").textContent).toBe("sign a git commit");
    expect(element("cipher-name").textContent).toBe("Git key");
    expect(element("key-meta").textContent).toBe("SHA256:abc123");
    expect(element("deny").textContent).toBe("Deny");
    expect(element("authorize").textContent).toBe("Authorize");
  });

  it("applies the theme resolved by the main process", async () => {
    getApproval.mockResolvedValue(makeView({ theme: "dark" }));
    await load();

    expect(document.documentElement.dataset.theme).toBe("dark");
  });

  it("hides the fingerprint line when the agent could not report a key", async () => {
    getApproval.mockResolvedValue(makeView({ keyFingerprint: "" }));
    await load();

    expect(element("key-meta").hidden).toBe(true);
  });

  it("only warns about forwarding for forwarded requests", async () => {
    getApproval.mockResolvedValue(makeView());
    await load();
    expect(element("forwarding-warning").hidden).toBe(true);

    approvalChanged(makeView({ requestId: 2, isAgentForwarding: true }));
    expect(element("forwarding-warning").hidden).toBe(false);
    expect(element("forwarding-warning-text").textContent).toBe(
      "This request comes from a remote device",
    );
  });

  // The main process both answers the initial fetch and pushes changes, so the same request can
  // arrive twice; re-rendering would restart the countdown and re-enable the buttons.
  it("ignores a repeat of the request already on screen", async () => {
    getApproval.mockResolvedValue(makeView());
    await load();

    const countdownBefore = element("countdown-bar").style.transform;
    jest.advanceTimersByTime(2_000);
    const countdownAfterTwoSeconds = element("countdown-bar").style.transform;

    approvalChanged(makeView());

    expect(element("countdown-bar").style.transform).toBe(countdownAfterTwoSeconds);
    expect(countdownAfterTwoSeconds).not.toBe(countdownBefore);
  });

  it("shrinks the countdown bar as time passes and stops at zero", async () => {
    const expiresAt = Date.now() + 10_000;
    getApproval.mockResolvedValue(makeView({ timeoutMs: 10_000, expiresAt }));
    await load();

    expect(element("countdown-bar").style.transform).toBe("scaleX(1)");

    jest.advanceTimersByTime(5_000);
    expect(element("countdown-bar").style.transform).toBe("scaleX(0.5)");

    jest.advanceTimersByTime(5_000);
    expect(element("countdown-bar").style.transform).toBe("scaleX(0)");
  });

  it("answers with the id of the request on screen", async () => {
    getApproval.mockResolvedValue(makeView({ requestId: 7 }));
    await load();

    element("deny").click();
    await Promise.resolve();

    expect(respondApproval).toHaveBeenCalledWith(7, false);
  });

  it("answers an approval", async () => {
    getApproval.mockResolvedValue(makeView({ requestId: 7 }));
    await load();

    element("authorize").click();
    await Promise.resolve();

    expect(respondApproval).toHaveBeenCalledWith(7, true);
  });

  it("disables both buttons once an answer is on its way", async () => {
    getApproval.mockResolvedValue(makeView());
    await load();

    element("authorize").click();
    await Promise.resolve();

    expect((element("deny") as HTMLButtonElement).disabled).toBe(true);
    expect((element("authorize") as HTMLButtonElement).disabled).toBe(true);
  });

  // Escape is not an answer; the user has to pick one explicitly.
  it("swallows Escape so the prompt cannot be dismissed without an answer", async () => {
    getApproval.mockResolvedValue(makeView());
    await load();

    const escape = new KeyboardEvent("keydown", { key: "Escape", cancelable: true });
    document.dispatchEvent(escape);

    expect(escape.defaultPrevented).toBe(true);
  });

  // A stray Enter or Space then refuses instead of authorizing.
  it("focuses the deny button", async () => {
    getApproval.mockResolvedValue(makeView());
    await load();

    expect(document.activeElement).toBe(element("deny"));
  });

  it("reports the height its content needs so the window can match it", async () => {
    getApproval.mockResolvedValue(makeView());
    await load();

    expect(resizeApproval).toHaveBeenCalled();
  });

  it("renders nothing until a request exists", async () => {
    await load();

    expect(element("question").textContent).toBe("");
    expect(respondApproval).not.toHaveBeenCalled();
  });
});
