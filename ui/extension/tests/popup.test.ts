// @vitest-environment jsdom
import { beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

// Chrome mock — set up BEFORE any module import so side effects see the mock
const storageMock: Record<string, unknown> = {};
const chromeMock = {
  storage: {
    local: {
      get: vi.fn(async (keys: string[]) => {
        const result: Record<string, unknown> = {};
        for (const k of keys) if (k in storageMock) result[k] = storageMock[k];
        return result;
      }),
      set: vi.fn(async (data: Record<string, unknown>) => Object.assign(storageMock, data)),
    },
  },
  runtime: { id: 'test-extension-id' },
};
(globalThis as Record<string, unknown>).chrome = chromeMock;

// Set up the full DOM before importing popup.ts so that getElementById calls succeed
// during module-level event listener registration and init().
document.body.innerHTML = `
  <div id="status-bar" class="status disconnected">Not paired</div>
  <div id="pair-section">
    <input id="port-input" type="number" value="8090">
    <button id="pair-btn">Pair with Bursa</button>
    <div id="pair-error" hidden></div>
    <div id="code-section" hidden>
      <input id="code-input" type="text">
      <button id="confirm-btn">Confirm Pairing</button>
      <div id="code-error" hidden></div>
    </div>
  </div>
`;

// Dynamic import after DOM and chrome mock are ready
await import('../src/popup');

describe('popup UI', () => {
  beforeAll(() => {
    // Re-install mock implementations after any vi.clearAllMocks() calls
  });

  beforeEach(() => {
    // Clear storage mock data
    for (const key of Object.keys(storageMock)) {
      delete storageMock[key];
    }
    vi.clearAllMocks();

    // Re-install mock implementations (clearAllMocks clears implementations too)
    chromeMock.storage.local.get.mockImplementation(async (keys: string[]) => {
      const result: Record<string, unknown> = {};
      for (const k of keys) if (k in storageMock) result[k] = storageMock[k];
      return result;
    });
    chromeMock.storage.local.set.mockImplementation(async (data: Record<string, unknown>) => {
      Object.assign(storageMock, data);
      return storageMock;
    });

    // Reset DOM state to unpaired
    const codeSection = document.getElementById('code-section')!;
    const pairError = document.getElementById('pair-error')!;
    const codeError = document.getElementById('code-error')!;
    const statusBar = document.getElementById('status-bar')!;
    const pairSection = document.getElementById('pair-section')!;
    const portInput = document.getElementById('port-input') as HTMLInputElement;
    const codeInput = document.getElementById('code-input') as HTMLInputElement;

    codeSection.hidden = true;
    pairError.hidden = true;
    codeError.hidden = true;
    statusBar.textContent = 'Not paired';
    statusBar.className = 'status disconnected';
    pairSection.hidden = false;
    portInput.value = '8090';
    codeInput.value = '';
    pairError.textContent = '';
    codeError.textContent = '';
  });

  it('pair button click → step 1 POST with correct URL and body, then shows code section', async () => {
    const fetchMock = vi.fn(async () => ({
      status: 202,
      ok: true,
    }));
    vi.stubGlobal('fetch', fetchMock);

    const pairBtn = document.getElementById('pair-btn')!;
    pairBtn.click();

    // Wait for promises to settle
    await new Promise((r) => setTimeout(r, 0));

    expect(fetchMock).toHaveBeenCalledOnce();
    const [url, opts] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe('http://127.0.0.1:8090/connector/pair');
    expect(opts.method).toBe('POST');
    const body = JSON.parse(opts.body as string);
    expect(body).toEqual({ extension_id: 'test-extension-id' });

    const codeSection = document.getElementById('code-section')!;
    expect(codeSection.hidden).toBe(false);
  });

  it('confirm button click → step 2 POST with code, stores token', async () => {
    // No port stored: confirm handler falls back to the default port 8090.
    const fetchMock = vi.fn(async () => ({
      ok: true,
      status: 200,
      json: async () => ({ token: 'abc123' }),
    }));
    vi.stubGlobal('fetch', fetchMock);

    const codeInput = document.getElementById('code-input') as HTMLInputElement;
    codeInput.value = '1234';

    const confirmBtn = document.getElementById('confirm-btn')!;
    confirmBtn.click();

    await new Promise((r) => setTimeout(r, 0));

    expect(fetchMock).toHaveBeenCalledOnce();
    const [url, opts] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe('http://127.0.0.1:8090/connector/pair');
    expect(opts.method).toBe('POST');
    const body = JSON.parse(opts.body as string);
    expect(body).toEqual({ extension_id: 'test-extension-id', code: '1234' });

    expect(chromeMock.storage.local.set).toHaveBeenCalledWith({ token: 'abc123' });

    // The confirm handler calls await init() after storing the token. The mock
    // get() re-reads storageMock (now containing the token), so init() takes the
    // connected branch and updates the UI.
    const statusBar = document.getElementById('status-bar')!;
    const pairSection = document.getElementById('pair-section')!;
    expect(statusBar.textContent).toBe('Connected');
    expect(statusBar.className).toContain('connected');
    expect(pairSection.hidden).toBe(true);
    expect(document.getElementById('sites-section')).toBeNull();
  });

  it('pair step 1 failure shows pair-error element', async () => {
    const fetchMock = vi.fn(async () => {
      throw new Error('Network error');
    });
    vi.stubGlobal('fetch', fetchMock);

    const pairBtn = document.getElementById('pair-btn')!;
    pairBtn.click();

    await new Promise((r) => setTimeout(r, 0));

    const pairError = document.getElementById('pair-error')!;
    expect(pairError.hidden).toBe(false);
    expect(pairError.textContent).toContain('Pair failed');
  });
});
