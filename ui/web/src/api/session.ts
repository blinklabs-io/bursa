const SESSION_FRAGMENT_PREFIX = "#session=";

let controlSessionToken = "";

export function controlSessionHeaders(): Record<string, string> {
  return controlSessionToken ? { "X-Bursa-Session": controlSessionToken } : {};
}

export async function establishControlSession(): Promise<void> {
  if (!window.location.hash.startsWith(SESSION_FRAGMENT_PREFIX)) return;

  const token = decodeURIComponent(window.location.hash.slice(SESSION_FRAGMENT_PREFIX.length));
  if (!token) return;

  controlSessionToken = "";
  // Remove the launch credential even if validation fails or the network drops.
  window.history.replaceState(null, "", `${window.location.pathname}${window.location.search}#/`);
  const response = await fetch("/session", {
    method: "POST",
    headers: { "X-Bursa-Session": token },
  });
  if (!response.ok) {
    controlSessionToken = "";
    throw new Error("wallet session authorization failed");
  }

  controlSessionToken = token;
}

export function hasControlSession(): boolean {
  return controlSessionToken !== "";
}
