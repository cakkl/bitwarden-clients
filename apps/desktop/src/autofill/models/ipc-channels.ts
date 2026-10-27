// MVP, delete with PM-41067
export const AUTOTYPE_MVP_IPC_CHANNELS = {
  TOGGLE: "autofill.toggleAutotypeMvp",
  CONFIGURE: "autofill.configureAutotypeMvp",
  LISTEN: "autofill.listenAutotypeRequestMvp",
  EXECUTION_ERROR: "autofill.autotypeExecutionErrorMvp",
  EXECUTE: "autofill.executeAutotypeMvp",
} as const;

export const SSH_AGENT_IPC_CHANNELS = {
  INIT: "sshagent.init",
  IS_LOADED: "sshagent.isloaded",
  STOP: "sshagent.stop",
  REPLACE: "sshagent.replace",
  SIGN_REQUEST: "sshagent.signrequest",
  SIGN_REQUEST_RESPONSE: "sshagent.signrequestresponse",
  LIST_KEYS_REQUEST: "sshagent.listkeysrequest",
  LIST_KEYS_RESPONSE: "sshagent.listkeysresponse",
  // Approval window. The renderer asks main to show a prompt and awaits the decision, so the
  // prompt is a window of its own rather than a dialog drawn inside the main window.
  APPROVAL_REQUEST: "sshagent.approvalrequest",
  APPROVAL_GET: "sshagent.getapprovalrequest",
  APPROVAL_CHANGED: "sshagent.approvalrequestchanged",
  APPROVAL_RESPONSE: "sshagent.approvalrequestresponse",
  APPROVAL_CANCEL: "sshagent.cancelapprovals",
  APPROVAL_RESIZE: "sshagent.approvalresize",
} as const;
