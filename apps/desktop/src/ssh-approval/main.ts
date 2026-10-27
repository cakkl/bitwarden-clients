import { SshApprovalView } from "../autofill/models/ssh-agent-approval";

/**
 * Renderer for the SSH sign-approval window. Angular-free so it renders in milliseconds.
 * Strings arrive translated and are written with `textContent`, so request data is never markup.
 */

/** The CSS transition smooths the steps between ticks. */
const COUNTDOWN_TICK_MS = 250;

function requireElement<T extends HTMLElement>(id: string): T {
  const element = document.getElementById(id);
  if (element == null) {
    throw new Error(`The SSH approval window is missing the #${id} element`);
  }
  return element as T;
}

const elements = {
  window: requireElement<HTMLDivElement>("window"),
  question: requireElement<HTMLHeadingElement>("question"),
  applicationName: requireElement<HTMLElement>("application-name"),
  purpose: requireElement<HTMLElement>("purpose"),
  cipherName: requireElement<HTMLElement>("cipher-name"),
  keyMeta: requireElement<HTMLElement>("key-meta"),
  forwardingWarning: requireElement<HTMLParagraphElement>("forwarding-warning"),
  forwardingWarningText: requireElement<HTMLElement>("forwarding-warning-text"),
  deny: requireElement<HTMLButtonElement>("deny"),
  authorize: requireElement<HTMLButtonElement>("authorize"),
  countdownBar: requireElement<HTMLDivElement>("countdown-bar"),
};

let renderedRequestId: number | null = null;
let countdownTimer: ReturnType<typeof setInterval> | null = null;

function stopCountdown(): void {
  if (countdownTimer != null) {
    clearInterval(countdownTimer);
    countdownTimer = null;
  }
}

function setBusy(busy: boolean): void {
  elements.deny.disabled = busy;
  elements.authorize.disabled = busy;
}

/**
 * Reports the height the content needs. Measured synchronously on purpose: `requestAnimationFrame`
 * is throttled while the window is still hidden.
 */
function requestResize(): void {
  const height = Math.ceil(elements.window.getBoundingClientRect().height);
  void ipc.autofill.sshAgent.resizeApproval(height);
}

function startCountdown(view: SshApprovalView): void {
  const total = Math.max(1, view.timeoutMs);

  const tick = () => {
    const remaining = Math.max(0, view.expiresAt - Date.now());
    elements.countdownBar.style.transform = `scaleX(${remaining / total})`;

    if (remaining === 0) {
      stopCountdown();
    }
  };

  stopCountdown();
  tick();
  countdownTimer = setInterval(tick, COUNTDOWN_TICK_MS);
}

function render(view: SshApprovalView): void {
  // Main both answers the initial fetch and pushes changes, so the same request can arrive twice.
  if (view.requestId === renderedRequestId) {
    return;
  }
  renderedRequestId = view.requestId;

  document.documentElement.dataset.theme = view.theme;

  elements.question.textContent = view.question;
  elements.applicationName.textContent = view.applicationName;
  elements.purpose.textContent = view.action;
  elements.cipherName.textContent = view.cipherName;

  elements.keyMeta.hidden = view.keyFingerprint === "";
  elements.keyMeta.textContent = view.keyFingerprint;
  elements.keyMeta.title = view.keyFingerprint;

  elements.forwardingWarning.hidden = !view.isAgentForwarding;
  elements.forwardingWarningText.textContent = view.forwardedLabel;

  elements.deny.textContent = view.denyLabel;
  elements.authorize.textContent = view.authorizeLabel;

  setBusy(false);
  startCountdown(view);
  requestResize();

  // Focus the safe answer, so a stray Enter or Space refuses instead of authorizing.
  elements.deny.focus();
}

async function respond(accepted: boolean): Promise<void> {
  const requestId = renderedRequestId;
  if (requestId == null) {
    return;
  }

  setBusy(true);
  stopCountdown();

  try {
    await ipc.autofill.sshAgent.respondApproval(requestId, accepted);
  } catch {
    // Main hides the window on an answer; if it never arrived, keep the prompt usable.
    setBusy(false);
  }
}

elements.deny.addEventListener("click", () => void respond(false));
elements.authorize.addEventListener("click", () => void respond(true));

// Escape must not dismiss the prompt: the user has to pick an answer explicitly.
document.addEventListener("keydown", (event) => {
  if (event.key === "Escape") {
    event.preventDefault();
  }
});

void (async () => {
  ipc.autofill.sshAgent.onApprovalChanged((view) => render(view));

  const pending = await ipc.autofill.sshAgent.getApproval();
  if (pending != null) {
    render(pending);
  }
})();
