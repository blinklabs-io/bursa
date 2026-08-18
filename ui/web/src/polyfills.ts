// Node globals that browser-targeted dependencies still expect.
//
// @ledgerhq/hw-transport-webhid (and the ledgerjs Cardano app beneath it)
// reference the Node `Buffer` global directly. Browsers have no such global,
// so without this the module throws `ReferenceError: Buffer is not defined`
// while it is being evaluated — which, for a statically reachable import,
// aborts the whole bundle before React ever mounts and leaves a blank page.
//
// This module exists so the assignment happens in a module BODY that is
// evaluated before anything that needs it: `import "./polyfills"` as the first
// import of main.tsx runs this to completion before ./app (and the hardware
// modules it reaches) are evaluated. Setting the global inside main.tsx's own
// body would be too late — every one of its imports is evaluated first.
import { Buffer } from "buffer";

declare global {
  var Buffer: typeof import("buffer").Buffer;
}

globalThis.Buffer ??= Buffer;

export {};
