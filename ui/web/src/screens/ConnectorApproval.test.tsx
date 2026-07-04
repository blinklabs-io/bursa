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

import { act, render, screen, fireEvent, waitFor } from "@testing-library/react";
import { ConnectorApproval } from "./ConnectorApproval";
import * as connectorApi from "../api/connector";
import { ApiError } from "../api/client";
import * as notify from "../connectorNotify";
import type { ConnectorRequest } from "../api/types";
import { FakeEventSource, installFakeEventSource } from "../test-utils/FakeEventSource";

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

let restoreEventSource: (() => void) | undefined;

function emitRequest(req: ConnectorRequest) {
  act(() => {
    FakeEventSource.instances[0].emit(JSON.stringify(req));
  });
}

beforeEach(() => {
  restoreEventSource = installFakeEventSource();
  vi.spyOn(notify, "notifyPending").mockResolvedValue(undefined);
});

afterEach(() => {
  vi.restoreAllMocks();
  restoreEventSource?.();
  restoreEventSource = undefined;
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
  emitRequest(makeReq());
  await waitFor(() => expect(screen.getByRole("dialog")).toBeInTheDocument());
  expect(screen.getByText("https://app.minswap.org")).toBeInTheDocument();
  expect(screen.getByText(/grant wallet access/i)).toBeInTheDocument();
});

test("Approve calls decide(id, true, password) for a signing method", async () => {
  const decideSpy = vi.spyOn(connectorApi, "decide").mockResolvedValue(undefined);
  const req = makeReq({ id: "sign-1", method: "signTx" });

  render(<ConnectorApproval />);
  emitRequest(req);

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
  emitRequest(req);

  await waitFor(() => screen.getByRole("button", { name: /reject/i }));
  fireEvent.click(screen.getByRole("button", { name: /reject/i }));

  await waitFor(() => expect(decideSpy).toHaveBeenCalledWith("enable-1", false, undefined));
});

test("dialog disappears after a request is decided", async () => {
  vi.spyOn(connectorApi, "decide").mockResolvedValue(undefined);
  const req = makeReq({ id: "vanish-1", method: "enable" });

  render(<ConnectorApproval />);
  emitRequest(req);

  await waitFor(() => screen.getByRole("dialog"));
  fireEvent.click(screen.getByRole("button", { name: /reject/i }));

  await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
});

test("notifyPending is called once per new request", async () => {
  const notifySpy = vi.spyOn(notify, "notifyPending").mockResolvedValue(undefined);
  const req = makeReq({ id: "notify-1" });

  render(<ConnectorApproval />);
  emitRequest(req);

  await waitFor(() => expect(notifySpy).toHaveBeenCalledWith(expect.objectContaining({ id: "notify-1" })));
  expect(notifySpy).toHaveBeenCalledTimes(1);
});

test("Approve is disabled when password is required but empty", async () => {
  const req = makeReq({ id: "signTx-pw", method: "signTx" });

  render(<ConnectorApproval />);
  emitRequest(req);

  await waitFor(() => screen.getByRole("button", { name: /approve/i }));
  expect(screen.getByRole("button", { name: /approve/i })).toBeDisabled();
});

test("submitTx approval does not require a spending password", async () => {
  const decideSpy = vi.spyOn(connectorApi, "decide").mockResolvedValue(undefined);
  const req = makeReq({ id: "submit-1", method: "submitTx", params: { tx: "deadbeef" } });

  render(<ConnectorApproval />);
  emitRequest(req);

  await waitFor(() => screen.getByRole("button", { name: /approve/i }));
  expect(screen.queryByLabelText(/spending password/i)).toBeNull();
  expect(screen.getByRole("button", { name: /approve/i })).not.toBeDisabled();

  fireEvent.click(screen.getByRole("button", { name: /approve/i }));

  await waitFor(() => expect(decideSpy).toHaveBeenCalledWith("submit-1", true, undefined));
});

test("drops stale pending requests when decide returns 404", async () => {
  vi.spyOn(connectorApi, "decide").mockRejectedValue(new ApiError(404, "unknown request id"));

  render(<ConnectorApproval />);
  emitRequest(makeReq({ id: "stale-1", origin: "https://stale.example" }));
  emitRequest(makeReq({ id: "next-1", origin: "https://next.example" }));

  await waitFor(() => expect(screen.getByText("https://stale.example")).toBeInTheDocument());
  fireEvent.click(screen.getByRole("button", { name: /reject/i }));

  await waitFor(() => expect(screen.getByText("https://next.example")).toBeInTheDocument());
  expect(screen.queryByText("https://stale.example")).toBeNull();
});

test("shows request params before approval", async () => {
  const req = makeReq({
    id: "params-1",
    method: "signData",
    params: { addr: "addr_test1qpz...", payload: "4275727361" },
  });

  render(<ConnectorApproval />);
  emitRequest(req);

  await waitFor(() => expect(screen.getByText(/"payload": "4275727361"/)).toBeInTheDocument());
  expect(screen.getByText(/"addr": "addr_test1qpz\.\.\."/)).toBeInTheDocument();
});
