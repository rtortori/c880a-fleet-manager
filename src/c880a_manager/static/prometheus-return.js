"use strict";

// Only native read-only pages can be resumed after signing in. Query text stays
// data in the URL; it cannot select another origin or an administrative API.
function safePrometheusReturn(value, origin) {
  if (typeof value !== "string" || value.length > 65536 ||
      !value.startsWith("/prometheus/") || /(?:^|\/)(?:\.|\.\.)(?:\/|$)/.test(value.split(/[?#]/)[0]) || /[\\\u0000-\u001f\u007f]/.test(value)) return null;
  try {
    const target = new URL(value, origin);
    if (target.origin !== origin || target.username || target.password ||
        !/^\/prometheus\/(?:query|graph|targets|service-discovery|status|rules|alerts|tsdb-status)?$/.test(target.pathname)) return null;
    return target.pathname + target.search + target.hash;
  } catch { return null; }
}
if (typeof module !== "undefined") module.exports = {safePrometheusReturn};
