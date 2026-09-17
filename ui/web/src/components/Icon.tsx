import type { CSSProperties } from "react";

const paths: Record<string, string> = {
  portfolio: "M3 3h7v7H3z M14 3h7v7h-7z M3 14h7v7H3z M14 14h7v7h-7z",
  activity: "M3 12h4l3-8 4 16 3-8h4",
  stake: "M12 21V9 M12 15C5 15 3 11 3 5c6 0 9 3 9 8 M12 11c0-6 4-9 9-9 0 6-3 10-9 10",
  swap: "M4 7h16m-4-4 4 4-4 4 M20 17H4m4-4-4 4 4 4",
  settings: "M4 6h16 M4 12h16 M4 18h16 M8 3v6 M16 9v6 M9 15v6",
  send: "M5 19 19 5 M5 5h14v14",
  receive: "M19 5 5 19 M5 5v14h14",
  shield: "M12 3 4 6v6c0 5 8 9 8 9s8-4 8-9V6z M8 12l3 3 5-6",
  arrow: "M5 12h14 M14 7l5 5-5 5",
  search: "M21 21l-5-5 M18 10a8 8 0 1 1-16 0 8 8 0 0 1 16 0",
  menu: "M4 6h16 M4 12h16 M4 18h16",
  close: "m6 6 12 12 M6 18 18 6",
  operate: "M5 4h14v6H5z M5 14h14v6H5z M8 7h.01 M8 17h.01",
  wallet: "M3 6h17v14H3z M3 6V4h14v2 M16 11h5v5h-5z",
  image: "M3 3h18v18H3z M3 17l6-6 4 4 3-3 5 5 M15 7h.01",
};

export function Icon({ name, size = 20, style }: { name: string; size?: number; style?: CSSProperties }) {
  return <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" style={style}><path d={paths[name] ?? paths.wallet} /></svg>;
}

export function BursaMark() {
  return <img className="bursa-symbol" src="/brand/bursa-pouch.png" width="32" height="36" alt="" aria-hidden="true" />;
}

export function BursaLogo() {
  return <img className="bursa-logo" src="/brand/bursa-logo.png" width="151" height="79" alt="Bursa" />;
}
