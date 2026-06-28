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

import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { ConnectorApproval } from "./ConnectorApproval";
import * as connectorApi from "../api/connector";
import * as notify from "../connectorNotify";
import type { ConnectorRequest } from "../api/types";

// ---------------------------------------------------------------------------
// Fake EventSource
// ---------------------------------------------------------------------------

class FakeEventSource {
  static instances: FakeEventSource[] = [];
  url: string;
  onmessage: ((evt: { data: string }) => void) | null = null;
  closed = false;

  constructor(url: string) {
    this.url = url;
    FakeEventSource.instances.push(this);
  }

  emit(data: string) {
    this.onmessage?.({ data });
  }

  close() {
    this.closed = true;
  }
}

// ---------------------------------------------------------------------------
// Setup / teardown
// ---------------------------------------------------------------------------

const makeReq = (overrides: Partial<ConnectorRequest> = {}): ConnectorRequest => ({
  id: "req-1",
  origin: "https://app.minswap.org",
  method: "enable",
  created: "2026-06-27T00:00:00Z",
  ...overrides,
});

beforeEach(() => {
  FakeEventSource.instances = [];
  globalThis.EventSource = FakeEventSource as unknown as typeof EventSource;
  vi.spyOn(notify, "notifyPending").mockResolvedValue(undefined);
});

afterEach(() => {
  vi.restoreAllMocks();
});

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test("renders nothing when there are no pending requests", () => {
  render(<ConnectorApproval />);
  expect(screen.queryByRole("dialog")).toBeNull();
});

test("shows the approval dialog when a pending request arrives", async () => {
  render(<ConnectorApproval />);
  FakeEventSource.instances[0].emit(JSON.stringify(makeReq()));
  await waitFor(() => expect(screen.getByRole("dialog")).toBeInTheDocument());
  expect(screen.getByText("https://app.minswap.org")).toBeInTheDocument();
  expect(screen.getByText(/grant wallet access/i)).toBeInTheDocument();
});

test("Approve calls decide(id, true, password) for a signing method", async () => {
  const decideSpy = vi.spyOn(connectorApi, "decide").mockResolvedValue(undefined);
  const req = makeReq({ id: "sign-1", method: "signTx" });

  render(<ConnectorApproval />);
  FakeEventSource.instances[0].emit(JSON.stringify(req));

  await waitFor(() => screen.getByLabelText(/spending password/i));
  fireEvent.change(screen.getByLabelText(/spending password/i), {
    target: { value: "mypassword" },
  });
  fireEvent.click(screen.getByRole("button", { name: /approve/i }));

  await waitFor(() => expect(decideSpy).toHaveBeenCalledWith("sign-1", true, "mypassword"));
});

test("Reject calls decide(id, false) without a password", async () => {
  const decideSpy = vi.spyOn(connectorApi, "decide").mockResolvedValue(undefined);
  const req = makeReq({ id: "enable-1", method: "enable" });

  render(<ConnectorApproval />);
  FakeEventSource.instances[0].emit(JSON.stringify(req));

  await waitFor(() => screen.getByRole("button", { name: /reject/i }));
  fireEvent.click(screen.getByRole("button", { name: /reject/i }));

  await waitFor(() => expect(decideSpy).toHaveBeenCalledWith("enable-1", false, undefined));
});

test("dialog disappears after a request is decided", async () => {
  vi.spyOn(connectorApi, "decide").mockResolvedValue(undefined);
  const req = makeReq({ id: "vanish-1", method: "enable" });

  render(<ConnectorApproval />);
  FakeEventSource.instances[0].emit(JSON.stringify(req));

  await waitFor(() => screen.getByRole("dialog"));
  fireEvent.click(screen.getByRole("button", { name: /reject/i }));

  await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
});

test("notifyPending is called once per new request", async () => {
  const notifySpy = vi.spyOn(notify, "notifyPending").mockResolvedValue(undefined);
  const req = makeReq({ id: "notify-1" });

  render(<ConnectorApproval />);
  FakeEventSource.instances[0].emit(JSON.stringify(req));

  await waitFor(() => expect(notifySpy).toHaveBeenCalledWith(expect.objectContaining({ id: "notify-1" })));
  expect(notifySpy).toHaveBeenCalledTimes(1);
});

test("Approve is disabled when password is required but empty", async () => {
  const req = makeReq({ id: "signTx-pw", method: "signTx" });

  render(<ConnectorApproval />);
  FakeEventSource.instances[0].emit(JSON.stringify(req));

  await waitFor(() => screen.getByRole("button", { name: /approve/i }));
  expect(screen.getByRole("button", { name: /approve/i })).toBeDisabled();
});
