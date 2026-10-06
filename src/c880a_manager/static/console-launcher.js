"use strict";

// These are viewer-launch context flags, not BMC credentials. The BMC GUI
// session remains in the gateway process; virtual media and power UI stay off.
window.CONSTANTS = Object.freeze({
  CD_SERVER_APP_FLAG: false,
  KVM_SESS_RECON_FLG: window.CONSOLE_FLAGS.kvmReconnect,
  VMEDIA_MAX_COUNT_FLAG: false,
  HOST_CURSOR_ENABLED_FLAG: false,
});
window.kvm_access = 1;
window.vmedia_access = 0;
window.privilege_id = 0;
window.$ = () => ({removeAttr() {}});
