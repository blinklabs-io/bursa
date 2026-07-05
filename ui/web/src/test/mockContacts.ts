import * as hooks from "../api/hooks";
import type { Contact } from "../api/types";

export function mockContacts(
  data: Contact[] | null,
  opts?: { loading?: boolean; error?: Error | null }
) {
  const refresh = vi.fn();
  vi.spyOn(hooks, "useContacts").mockReturnValue({
    data,
    error: opts?.error ?? null,
    loading: opts?.loading ?? false,
    refresh,
    setData: vi.fn(),
  } as never);
  return refresh;
}
