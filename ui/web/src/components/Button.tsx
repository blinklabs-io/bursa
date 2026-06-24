import { ButtonHTMLAttributes } from "react";

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: "primary" | "ghost";
}

export function Button({ variant = "primary", className, type, ...props }: ButtonProps) {
  return (
    <button
      // Default to "button" so a Button inside a <form> doesn't implicitly
      // submit it; callers that want submit pass type="submit" explicitly.
      type={type ?? "button"}
      className={["btn", variant, className].filter(Boolean).join(" ")}
      {...props}
    />
  );
}
