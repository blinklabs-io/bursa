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

import type { ConnectorRequest } from "./api/types";

// notifyPending is imported dynamically (after vi.resetModules) inside each test
// so connectorNotify's module-level `permissionRequested` flag is fresh per test.
// A static import would share that flag across tests, causing requestPermission()
// to early-return on every test after the first.
async function freshNotifyPending() {
  vi.resetModules();
  const mod = await import("./connectorNotify");
  return mod.notifyPending;
}

const makeReq = (id = "r1"): ConnectorRequest => ({
  id,
  origin: "https://app.minswap.org",
  method: "signTx",
  created: "2026-06-27T00:00:00Z",
});

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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

afterEach(() => {
  vi.restoreAllMocks();
  // The module-level `permissionRequested` flag is reset by freshNotifyPending()
  // re-importing the module (via vi.resetModules) at the start of each test, so
  // requestPermission() actually runs again instead of early-returning.
});

test("constructs a Notification when permission is granted", async () => {
  const notifyPending = await freshNotifyPending();
  installMockNotification("granted");
  await notifyPending(makeReq("n1"));
  expect(MockNotification.instances).toHaveLength(1);
  expect(MockNotification.instances[0].title).toBe("Bursa — dApp request");
  expect(MockNotification.instances[0].options?.body).toMatch(/app\.minswap\.org/);
});

test("does not throw when permission is denied", async () => {
  const notifyPending = await freshNotifyPending();
  installMockNotification("denied");
  await expect(notifyPending(makeReq("n2"))).resolves.not.toThrow();
  expect(MockNotification.instances).toHaveLength(0);
});

test("does not throw when Notification API is absent", async () => {
  const notifyPending = await freshNotifyPending();
  // Simulate an environment without the Notification API.
  const saved = globalThis.Notification;
  // @ts-expect-error — intentionally removing Notification for the test
  delete globalThis.Notification;
  await expect(notifyPending(makeReq("n3"))).resolves.not.toThrow();
  globalThis.Notification = saved;
});

test("uses the request id as a tag to collapse duplicate notifications", async () => {
  const notifyPending = await freshNotifyPending();
  installMockNotification("granted");
  await notifyPending(makeReq("dedup-1"));
  expect(MockNotification.instances[0].options?.tag).toBe("connector-dedup-1");
});
