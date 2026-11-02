const SESSION_FRAGMENT_PREFIX = "#session=";

export async function establishControlSession(): Promise<void> {
  if (!window.location.hash.startsWith(SESSION_FRAGMENT_PREFIX)) return;

  const token = decodeURIComponent(window.location.hash.slice(SESSION_FRAGMENT_PREFIX.length));
  if (!token) return;

  const response = await fetch("/session", {
    method: "POST",
    headers: { "X-Bursa-Session": token },
  });
  if (!response.ok) throw new Error("wallet session authorization failed");

  // Remove the capability from browser history as soon as the HttpOnly cookie
  // is established. Hash routes resume at the normal default screen.
  window.history.replaceState(null, "", `${window.location.pathname}${window.location.search}#/`);
}
