import { useState, useEffect } from "react";

function getRoute(): string {
  return location.hash.replace(/^#\//, "") || "portfolio";
}

export function useHashRoute(): string {
  const [route, setRoute] = useState<string>(getRoute);

  useEffect(() => {
    const handler = () => setRoute(getRoute());
    window.addEventListener("hashchange", handler);
    return () => window.removeEventListener("hashchange", handler);
  }, []);

  return route;
}

export function navigate(route: string): void {
  location.hash = "#/" + route;
}
