# Feature 1 — SPA Network Resilience — Implementation Report

**Date:** 2026-06-29  
**Branch:** feat/mobile-net-resilience  
**Spec:** docs/superpowers/specs/2026-06-29-mobile-resilience-design.md § Feature 1  
**Approach:** TDD (RED→GREEN per piece, no production code before a failing test)

---

## Summary

Three files changed in the SPA (`ui/web/src/`). All strictly TDD. 106 tests pass (16 files). Type-check clean. Build clean. Go embed unaffected.

---

## Changes

### `ui/web/src/api/client.ts`

Added bounded retry + capped exponential backoff inside the `request()` function:

- **Retries only on `TypeError`** (network-level rejections — "Failed to fetch"). These are the only unrecoverable transport failures worth retrying.
- **Does NOT retry on HTTP responses** (4xx, 5xx). A response, even an error one, means the server received and handled the request — retrying would be wrong.
- **Does NOT retry on `AbortError`** (explicit timeout/abort signal). These are intentional cancellations.
- **3 total attempts** (1 initial + 2 retries).
- **Backoff:** 250ms after attempt 1, capped at 1000ms (250ms → 500ms).
- Public API surface unchanged: `apiGet`, `apiPost`, `apiPut`, `apiDelete` return/throw the same types as before.

### `ui/web/src/api/hooks.ts`

Modified `useAsync()` to be online-aware:

- **Poll suspension:** the `setInterval` callback skips the fetch if `navigator.onLine === false` OR `document.hidden === true`. The initial fetch (on mount / on `tick` change via `refresh()`) is always allowed regardless.
- **Online recovery:** a `window 'online'` event listener triggers an immediate `run(false)` call so the UI recovers without waiting for the next poll cycle.
- **Cleanup:** the `'online'` listener is removed in the effect's cleanup function (unmount or re-effect).
- Existing `pollMs` behavior unchanged when online and visible.

### `ui/web/src/app.tsx`

Added a small dismissible `OfflineBanner` component:

- Tracks `navigator.onLine` at mount; reacts to `window 'offline'` and `'online'` events via `useEffect`.
- Going offline shows the banner; coming back online hides it automatically.
- The user can dismiss it manually (sets a local `dismissed` flag that resets on the next offline/online cycle).
- Banner uses `role="alert" aria-label="offline"` for screen reader accessibility.
- Rendered at the top of every render path in `App` (including `FullScreen`, the syncing boot view, and the main unlocked layout), so it appears regardless of vault/unlock state.

---

## Tests

| File | New tests | All tests |
|------|-----------|-----------|
| `src/api/client.test.ts` | 3 | 5 |
| `src/api/hooks.test.tsx` | 3 | 4 |
| `src/app.test.tsx` | 3 | 16 |

Total suite: **106 tests, 16 files, all pass**.

---

## Verification

```
npm run type-check   → clean (exit 0)
npm run test         → 106 passed, 0 failed
npm run build        → built in ~1.7s, no warnings
go build ./...       → exit 0 (embed unaffected)
```

dist/ artifacts restored with `git checkout -- ui/internal/webui/dist/` before commit.

---

## Concerns / Follow-ons

- The retry backoff uses real `setTimeout` in tests — the `persistent network error` test takes ~754ms because it waits out two real backoff delays (250ms + 500ms). This is acceptable for correctness but could be replaced with `vi.useFakeTimers()` if test speed becomes an issue. Opted for real timers to keep tests closer to production behavior.
- The banner state is local to each `App` mount; if in future the `OfflineBanner` needs to be shared across multiple sub-trees, extracting it to a context would be cleaner.
- The `document.hidden` check in `useAsync` guards against polling in a background tab but does NOT add a `visibilitychange` listener to resume polling when the tab becomes visible again — that is explicitly Feature 3's scope (`feat/mobile-resume`).
