// Capability seam — Solo-safe defaults; Group tier injects real impls.
// Core modules import these accessors rather than group/ modules directly.

function soloDefaults() {
  return {
    recordAudit: () => {},
    currentProvider: () => null,
    currentUser: () => null,
  };
}

let _caps = soloDefaults();

export function installCapabilities(impl) {
  _caps = { ...soloDefaults(), ...(impl || {}) };
}

export function resetCapabilities() {
  _caps = soloDefaults();
}

export const recordAudit    = (...args) => _caps.recordAudit(...args);
export const currentProvider = ()       => _caps.currentProvider();
export const currentUser    = ()        => _caps.currentUser();
