export class FakeEventSource {
  static readonly CONNECTING = 0;
  static readonly OPEN = 1;
  static readonly CLOSED = 2;
  static instances: FakeEventSource[] = [];

  url: string;
  onmessage: ((evt: { data: string }) => void) | null = null;
  closed = false;
  readyState = FakeEventSource.OPEN;

  constructor(url: string) {
    this.url = url;
    FakeEventSource.instances.push(this);
  }

  emit(data: string) {
    this.onmessage?.({ data });
  }

  close() {
    this.closed = true;
    this.readyState = FakeEventSource.CLOSED;
    FakeEventSource.instances = FakeEventSource.instances.filter(
      (instance) => instance !== this,
    );
  }
}

export function installFakeEventSource(): () => void {
  const realEventSource = globalThis.EventSource;
  FakeEventSource.instances = [];
  globalThis.EventSource = FakeEventSource as unknown as typeof EventSource;

  return () => {
    FakeEventSource.instances = [];
    if (realEventSource === undefined) {
      Reflect.deleteProperty(globalThis, "EventSource");
      return;
    }
    globalThis.EventSource = realEventSource;
  };
}
