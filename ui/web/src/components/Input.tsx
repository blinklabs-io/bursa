import { InputHTMLAttributes } from "react";

type InputProps = InputHTMLAttributes<HTMLInputElement>;

export function Input({ className, ...props }: InputProps) {
  return (
    <input
      className={["field", className].filter(Boolean).join(" ")}
      {...props}
    />
  );
}
