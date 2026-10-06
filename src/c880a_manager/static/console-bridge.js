"use strict";

// The vendor viewer expects an opener window. In the gateway it runs in a
// same-origin iframe, so its launcher page is the parent window instead.
if (window.parent !== window) {
  try {
    window.opener = window.parent;
    window.kvm_access = window.parent.kvm_access;
    window.vmedia_access = window.parent.vmedia_access;
  } catch (_error) {
    // A browser may make opener read-only; the live integration test detects it.
  }
}
