// Node-local wallet-activity notifications.
//
// The backend's GET /wallet/activity returns the incoming-funds / stake-reward
// events that appeared since the previous poll (dedup is server-side). This
// module turns one such event into a user-facing notification:
//   - On the desktop webview build, `window.bursaNotify` raises a real OS-native
//     notification (bound in ui/cmd/bursa-wallet/ui_webview.go).
//   - In the plain browser build there is no bridge, so it falls back to the
//     browser Notification API (which requires the per-origin permission the
//     user granted when enabling notifications).
// Everything here is client-only; the detection itself is node-local.

import { formatAda } from "./format";
import type { ActivityEvent } from "./api/types";

// notificationsSupported reports whether this environment can raise a
// notification at all — either the desktop bridge or the browser Notification
// API is present.
export function notificationsSupported(): boolean {
  return (
    typeof window !== "undefined" &&
    (typeof window.bursaNotify === "function" ||
      typeof window.Notification !== "undefined")
  );
}

// notificationPermission reports the browser Notification permission, or
// "unsupported" when the Notification API is absent. The desktop bridge does not
// use this — it has its own OS-level permission model — so a webview build can
// still notify via the bridge even when this returns "unsupported".
export function notificationPermission(): NotificationPermission | "unsupported" {
  if (typeof window === "undefined" || typeof window.Notification === "undefined") {
    return "unsupported";
  }
  return window.Notification.permission;
}

// requestNotificationPermission asks the browser for the Notification
// permission, returning the resulting state. It is a no-op (returns "granted")
// when the desktop bridge is present, and "unsupported" when neither the bridge
// nor the Notification API exists. Only call this in response to the user opting
// in — browsers reject or penalize unsolicited permission prompts.
export async function requestNotificationPermission(): Promise<
  NotificationPermission | "unsupported"
> {
  if (typeof window !== "undefined" && typeof window.bursaNotify === "function") {
    return "granted";
  }
  if (typeof window === "undefined" || typeof window.Notification === "undefined") {
    return "unsupported";
  }
  if (window.Notification.permission !== "default") {
    return window.Notification.permission;
  }
  try {
    return await window.Notification.requestPermission();
  } catch {
    // Some browsers throw on the legacy callback form; treat as denied.
    return "denied";
  }
}

// notificationText builds the title/body copy for an activity event.
export function notificationText(event: ActivityEvent): { title: string; body: string } {
  const ada = formatAda(event.lovelace);
  if (event.kind === "reward") {
    return { title: "Staking reward", body: `Staking reward: ${ada} ADA` };
  }
  return { title: "Funds received", body: `Received ${ada} ADA` };
}

// raiseActivityNotification shows a notification for one activity event, using
// the desktop bridge when present and otherwise the browser Notification API.
// It returns true when a notification was raised. It never throws — a failure to
// notify must not break the polling loop.
export function raiseActivityNotification(event: ActivityEvent): boolean {
  const { title, body } = notificationText(event);
  if (typeof window !== "undefined" && typeof window.bursaNotify === "function") {
    try {
      window.bursaNotify(title, body);
      return true;
    } catch {
      return false;
    }
  }
  if (
    typeof window === "undefined" ||
    typeof window.Notification === "undefined" ||
    window.Notification.permission !== "granted"
  ) {
    return false;
  }
  try {
    // The tag dedups OS-side too: a re-shown event with the same id replaces
    // rather than stacks.
    new window.Notification(title, { body, tag: event.id });
    return true;
  } catch {
    return false;
  }
}
