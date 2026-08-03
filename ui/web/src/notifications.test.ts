// Copyright 2026 Blink Labs Software
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import {
  notificationText,
  raiseActivityNotification,
  requestNotificationPermission,
  notificationPermission,
} from "./notifications";
import type { ActivityEvent } from "./api/types";

// ---------------------------------------------------------------------------
// Mock Notification API
// ---------------------------------------------------------------------------

class MockNotification {
  static instances: MockNotification[] = [];
  static permission: NotificationPermission = "default";
  static requestPermission = vi.fn(async () => {
    MockNotification.permission = "granted";
    return MockNotification.permission;
  });

  title: string;
  options: NotificationOptions | undefined;

  constructor(title: string, options?: NotificationOptions) {
    this.title = title;
    this.options = options;
    MockNotification.instances.push(this);
  }
}

function installMockNotification(permission: NotificationPermission = "granted") {
  MockNotification.instances = [];
  MockNotification.permission = permission;
  MockNotification.requestPermission = vi.fn(async () => {
    MockNotification.permission = "granted";
    return MockNotification.permission;
  });
  globalThis.Notification = MockNotification as unknown as typeof Notification;
}

const realNotification = globalThis.Notification;

function restoreNotification() {
  if (realNotification === undefined) {
    Reflect.deleteProperty(globalThis, "Notification");
    return;
  }
  globalThis.Notification = realNotification;
}

const received: ActivityEvent = {
  id: "tx:abc",
  kind: "received",
  lovelace: "2500000",
  tx_hash: "abc",
};
const reward: ActivityEvent = {
  id: "reward:101",
  kind: "reward",
  lovelace: "7000000",
  epoch: 101,
};

afterEach(() => {
  vi.restoreAllMocks();
  restoreNotification();
  Reflect.deleteProperty(window, "bursaNotify");
});

// ---------------------------------------------------------------------------
// notificationText
// ---------------------------------------------------------------------------

test("notificationText formats a received event as ADA", () => {
  expect(notificationText(received).body).toBe("Received 2.5 ADA");
});

test("notificationText formats a reward event as ADA", () => {
  expect(notificationText(reward).body).toBe("Staking reward: 7 ADA");
});

// ---------------------------------------------------------------------------
// raiseActivityNotification — browser Notification path
// ---------------------------------------------------------------------------

test("raises a browser Notification when permission is granted", () => {
  installMockNotification("granted");
  const ok = raiseActivityNotification(received);
  expect(ok).toBe(true);
  expect(MockNotification.instances).toHaveLength(1);
  expect(MockNotification.instances[0].title).toBe("Funds received");
  expect(MockNotification.instances[0].options?.body).toBe("Received 2.5 ADA");
  // The event id is used as the OS-side dedup tag.
  expect(MockNotification.instances[0].options?.tag).toBe("tx:abc");
});

test("does nothing when notification permission is denied", () => {
  installMockNotification("denied");
  const ok = raiseActivityNotification(received);
  expect(ok).toBe(false);
  expect(MockNotification.instances).toHaveLength(0);
});

test("does nothing when the Notification API is unsupported", () => {
  restoreNotification();
  Reflect.deleteProperty(globalThis, "Notification");
  const ok = raiseActivityNotification(received);
  expect(ok).toBe(false);
});

test("returns false rather than throwing when the Notification constructor throws", () => {
  class ThrowingNotification {
    static permission: NotificationPermission = "granted";
    static requestPermission = vi.fn();
    constructor() {
      throw new Error("blocked by OS");
    }
  }
  globalThis.Notification = ThrowingNotification as unknown as typeof Notification;
  expect(() => raiseActivityNotification(received)).not.toThrow();
  expect(raiseActivityNotification(received)).toBe(false);
});

// ---------------------------------------------------------------------------
// raiseActivityNotification — desktop bridge path
// ---------------------------------------------------------------------------

test("prefers the desktop bursaNotify bridge over the browser Notification", () => {
  installMockNotification("granted");
  const bridge = vi.fn();
  window.bursaNotify = bridge;
  const ok = raiseActivityNotification(reward);
  expect(ok).toBe(true);
  expect(bridge).toHaveBeenCalledWith("Staking reward", "Staking reward: 7 ADA");
  // The browser Notification must NOT also fire when the bridge handled it.
  expect(MockNotification.instances).toHaveLength(0);
});

test("returns false rather than throwing when the desktop bridge throws", () => {
  installMockNotification("granted");
  window.bursaNotify = vi.fn(() => {
    throw new Error("bridge failed");
  });
  expect(() => raiseActivityNotification(reward)).not.toThrow();
  expect(raiseActivityNotification(reward)).toBe(false);
  // The bridge owns the call once present; its failure must not fall through
  // to the browser Notification API.
  expect(MockNotification.instances).toHaveLength(0);
});

// ---------------------------------------------------------------------------
// permission helpers
// ---------------------------------------------------------------------------

test("notificationPermission reflects the browser permission", () => {
  installMockNotification("granted");
  expect(notificationPermission()).toBe("granted");
  restoreNotification();
  Reflect.deleteProperty(globalThis, "Notification");
  expect(notificationPermission()).toBe("unsupported");
});

test("requestNotificationPermission returns granted for the desktop bridge", async () => {
  Reflect.deleteProperty(globalThis, "Notification");
  window.bursaNotify = vi.fn();
  await expect(requestNotificationPermission()).resolves.toBe("granted");
});

test("requestNotificationPermission asks the browser when permission is default", async () => {
  installMockNotification("default");
  await expect(requestNotificationPermission()).resolves.toBe("granted");
  expect(MockNotification.requestPermission).toHaveBeenCalledTimes(1);
});

test("requestNotificationPermission does not re-ask when already decided", async () => {
  installMockNotification("denied");
  await expect(requestNotificationPermission()).resolves.toBe("denied");
  expect(MockNotification.requestPermission).not.toHaveBeenCalled();
});

test("requestNotificationPermission falls back to denied when requestPermission throws", async () => {
  installMockNotification("default");
  // Some browsers throw synchronously on the legacy callback form instead of
  // rejecting the promise.
  MockNotification.requestPermission = vi.fn((): Promise<NotificationPermission> => {
    throw new Error("legacy callback form unsupported");
  });
  await expect(requestNotificationPermission()).resolves.toBe("denied");
});
