import { ApiError } from "./api/client";

// errorMessage normalizes a thrown value into a display string, matching the
// pattern used across the spending screens.
export function errorMessage(err: unknown): string {
  if (err instanceof ApiError) return err.message;
  if (err instanceof Error) return err.message;
  return String(err);
}
