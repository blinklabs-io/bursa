export class FakeEventSource {
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
