import { ReactNode } from "react";

export type Tone = "ok" | "warn" | "error" | "muted";

interface StatusPillProps {
  tone: Tone;
  children?: ReactNode;
}

export function StatusPill({ tone, children }: StatusPillProps) {
  return <span className={`pill pill-${tone}`}>{children}</span>;
}
