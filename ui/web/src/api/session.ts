const SESSION_FRAGMENT_PREFIX = "#session=";

let controlSessionToken = "";

export function controlSessionHeaders(): Record<string, string> {
  return controlSessionToken ? { "X-Bursa-Session": controlSessionToken } : {};
}

export async function establishControlSession(): Promise<void> {
  if (!window.location.hash.startsWith(SESSION_FRAGMENT_PREFIX)) return;

  const token = decodeURIComponent(window.location.hash.slice(SESSION_FRAGMENT_PREFIX.length));
  if (!token) return;

  controlSessionToken = token;

  const response = await fetch("/session", {
    method: "POST",
    headers: { "X-Bursa-Session": token },
  });
  if (!response.ok) {
    controlSessionToken = "";
    throw new Error("wallet session authorization failed");
  }

  // Keep the capability only in this page's memory and remove it from browser
  // history. Hash routes resume at the normal default screen.
  window.history.replaceState(null, "", `${window.location.pathname}${window.location.search}#/`);
}
