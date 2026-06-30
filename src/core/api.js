// Authenticated HTTP client for the Tahlk cloud API.
// Adds Bearer token to every request. On 401 it attempts one silent token
// refresh; if that fails the caller receives the 401 so the UI can prompt
// the user to log in again.

import { getAccessToken, refreshAccessToken, serverUrl } from './auth.js';

export async function apiFetch(path, opts = {}) {
  const token = getAccessToken();

  const doFetch = (t) =>
    fetch(`${serverUrl()}${path}`, {
      ...opts,
      credentials: 'include',
      headers: {
        'Content-Type': 'application/json',
        ...(opts.headers ?? {}),
        ...(t ? { Authorization: `Bearer ${t}` } : {}),
      },
    });

  let res = await doFetch(token);

  if (res.status === 401) {
    const newToken = await refreshAccessToken();
    if (!newToken) return res; // still 401 — caller must handle
    res = await doFetch(newToken);
  }

  return res;
}
