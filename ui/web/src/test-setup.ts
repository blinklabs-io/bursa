import "@testing-library/jest-dom/vitest";

// Provide a minimal EventSource stub for tests. The real EventSource is only
// available in browser environments; jsdom does not implement it, so any
// component that calls new EventSource() (e.g. ConnectorApproval via
// subscribePending) would throw "EventSource is not defined" without this.
//
// Tests that need to simulate incoming SSE messages should replace this stub
// with a FakeEventSource that exposes an emit() method.
class StubEventSource {
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  constructor(_url: string) {}
  onmessage: null = null;
  close() {}
}

if (typeof globalThis.EventSource === "undefined") {
  globalThis.EventSource = StubEventSource as unknown as typeof EventSource;
}
